"""
File tail input: globs, rotation, truncation, multiline, container logs, exactly-once.

Each file's checkpoint is the byte offset just past the last record that was
journaled, stored together with that record's journal sequence. Checkpoints
become durable only after the journal is flushed (``Checkpoints.flush``). On
restart, records of this file already journaled after the durable checkpoint
are skipped (byte-for-byte comparison) while re-reading, so a crash at any
point neither loses nor duplicates a line.

Rotation is detected by file identity (device + inode, or a hash of the first
bytes where inodes are unavailable): the rest of the old file is read from
its new name before the new file is started at offset 0. A file that shrinks
below the checkpoint was truncated in place and is re-read from the start.

Container modes (``container:``) keep the original bytes in the journal and
let the workers unwrap them:
* ``docker``     — json-file driver lines; 16 KB partial lines are joined;
                   container name/image/labels come from ``config.v2.json``;
* ``kubernetes`` / ``containerd`` — CRI lines ``<time> <stream> <P|F> <msg>``;
                   P(artial) lines are joined; pod/namespace/container come
                   from the ``/var/log/containers`` file name.
"""
from __future__ import annotations

import glob
import hashlib
import json
import logging
import os
import re
import threading
import time

from ulpf.runtime.inputs.base import Input

logger = logging.getLogger(__name__)

_READ_CHUNK = 4 * 2**20
_MAX_RECORDS_PER_INGEST = 2000


def file_identity(path: str, st: os.stat_result | None = None) -> str:
    st = st or os.stat(path)
    if st.st_ino:
        return f"{st.st_dev}:{st.st_ino}"
    with open(path, "rb") as f:
        head = f.read(256)
    return "h:" + hashlib.sha256(head).hexdigest()[:24]


class _Tracked:
    __slots__ = ("path", "ident", "read_pos", "buf", "pending", "pending_since", "skip", "eof_since")

    def __init__(self, path: str, ident: str, offset: int):
        self.path = path
        self.ident = ident
        self.read_pos = offset           # bytes consumed into buf / pending
        self.buf = b""                   # incomplete trailing line
        self.pending: list[bytes] = []   # multiline / partial-line event being assembled
        self.pending_since = 0.0
        self.skip: list[bytes] = []      # journaled before a crash, not yet checkpointed
        self.eof_since = 0.0

    def committed_offset(self) -> int:
        pend = sum(len(l) + 1 for l in self.pending)
        return self.read_pos - len(self.buf) - pend


class FileInput(Input):
    def __init__(self, name, options, ctx):
        super().__init__(name, options, ctx)
        ml = options.get("multiline") or None
        self.start_re = re.compile(ml["start_pattern"].encode()) if ml else None
        self.ml_max = int(ml.get("max_lines", 500)) if ml else 0
        self.ml_timeout = (ml.get("timeout_ms", 1000) / 1000.0) if ml else 0.0
        self.container = options.get("container", "none")
        self.files: dict[str, _Tracked] = {}
        self.poll = options.get("poll_interval_ms", 250) / 1000.0

    # ---- discovery / checkpoints -------------------------------------
    def _ckpt_key(self, path: str) -> str:
        return f"file:{self.name}:{path}"

    def _discover(self) -> list[str]:
        found: set[str] = set()
        for pattern in self.opts["paths"]:
            for p in glob.glob(os.path.expanduser(pattern)):
                if os.path.isfile(p):
                    found.add(os.path.abspath(p))
        for pattern in self.opts.get("exclude") or []:
            for p in glob.glob(os.path.expanduser(pattern)):
                found.discard(os.path.abspath(p))
        return sorted(found)

    def _track(self, path: str, first_run: bool) -> _Tracked | None:
        try:
            st = os.stat(path)
            ident = file_identity(path, st)
        except OSError:
            return None
        ck = self.ctx.checkpoints.durable(self._ckpt_key(path))
        if ck and ck["value"].get("ident") == ident and ck["value"]["offset"] <= st.st_size:
            t = _Tracked(path, ident, ck["value"]["offset"])
            t.skip = [r.raw for r in self.ctx.journaled_after(self.name, path, ck["seq"])]
            if t.skip:
                logger.info(f"{self.name}: {path}: {len(t.skip)} record(s) were journaled after the last "
                            "durable checkpoint; they will not be ingested twice")
        elif first_run and self.opts.get("start_from") == "end" and ck is None:
            t = _Tracked(path, ident, st.st_size)
        else:
            t = _Tracked(path, ident, 0)
        if self.container == "docker":
            self._write_docker_labels(path)
        return t

    # ---- reading -----------------------------------------------------
    def _emit(self, t: _Tracked, records: list[bytes]) -> None:
        if t.skip:
            kept = []
            for r in records:
                if t.skip and r == t.skip[0]:
                    t.skip.pop(0)
                    continue
                t.skip = []            # diverged (file changed): stop skipping
                kept.append(r)
            records = kept
        for i in range(0, len(records), _MAX_RECORDS_PER_INGEST):
            chunk = records[i:i + _MAX_RECORDS_PER_INGEST]
            if chunk:
                self.accept(t.path, chunk, block=True)
        seq = self.last_seq if self.last_seq is not None else self.ctx.journal.next_seq - 1
        self.ctx.checkpoints.set(self._ckpt_key(t.path), {"ident": t.ident, "offset": t.committed_offset()}, seq)

    def _lines_to_records(self, t: _Tracked, lines: list[bytes], now: float) -> list[bytes]:
        out: list[bytes] = []
        for line in lines:
            if self.container == "docker":
                t.pending.append(line)
                try:
                    complete = json.loads(line).get("log", "\n").endswith("\n")
                except ValueError:
                    complete = True
                if complete:
                    out.append(b"\n".join(t.pending))
                    t.pending = []
                continue
            if self.container in ("kubernetes", "containerd"):
                parts = line.split(b" ", 3)
                t.pending.append(line)
                if len(parts) < 3 or parts[2] != b"P":
                    out.append(b"\n".join(t.pending))
                    t.pending = []
                continue
            if self.start_re is None:
                if line.strip():
                    out.append(line)
                continue
            if self.start_re.match(line):
                if t.pending:
                    out.append(b"\n".join(t.pending))
                t.pending = [line]
                t.pending_since = now
            elif line.strip() or t.pending:
                if not t.pending:
                    t.pending_since = now
                t.pending.append(line)
            if self.ml_max and len(t.pending) >= self.ml_max:
                out.append(b"\n".join(t.pending))
                t.pending = []
        return out

    def _read_new(self, t: _Tracked, path: str, now: float) -> None:
        with open(path, "rb") as f:
            f.seek(t.read_pos)
            while True:
                chunk = f.read(_READ_CHUNK)
                if not chunk:
                    break
                t.read_pos += len(chunk)
                data = t.buf + chunk
                lines = data.split(b"\n")
                t.buf = lines.pop()
                lines = [l[:-1] if l.endswith(b"\r") else l for l in lines]
                records = self._lines_to_records(t, lines, now)
                if records or t.pending or t.buf:
                    self._emit(t, records)

    def _poll_file(self, t: _Tracked, now: float) -> None:
        try:
            st = os.stat(t.path)
            ident = file_identity(t.path, st)
        except OSError:
            st, ident = None, None
        if st is None or ident != t.ident:
            # Rotated (or deleted): finish the old file under its new name, if it still exists
            old = self._find_by_identity(os.path.dirname(t.path), t.ident)
            if old is not None:
                self._read_new(t, old, now)
            self._flush_tail(t, force=True)
            if st is None:
                self.files.pop(t.path, None)
                return
            new = _Tracked(t.path, ident, 0)
            self.files[t.path] = new
            if self.container == "docker":
                self._write_docker_labels(t.path)
            t = new
        elif st.st_size < t.read_pos:
            logger.warning(f"{self.name}: {t.path} was truncated; reading from the start")
            t.read_pos, t.buf, t.pending = 0, b"", []
        if st.st_size > t.read_pos:
            self._read_new(t, t.path, now)
            t.eof_since = now
        self._flush_tail(t, force=False, now=now)

    def _flush_tail(self, t: _Tracked, force: bool, now: float | None = None) -> None:
        """Emit a pending multiline event after its timeout, or anything left when a file ends."""
        now = now or time.time()
        records = []
        if t.pending and (force or (self.ml_timeout and now - t.pending_since >= self.ml_timeout)):
            records.append(b"\n".join(t.pending))
            t.pending = []
        if force and t.buf.strip():
            records.append(t.buf.rstrip(b"\r"))
            t.buf = b""
        if records:
            self._emit(t, records)

    @staticmethod
    def _find_by_identity(directory: str, ident: str) -> str | None:
        try:
            names = os.listdir(directory or ".")
        except OSError:
            return None
        for n in names:
            p = os.path.join(directory, n)
            try:
                if os.path.isfile(p) and file_identity(p) == ident:
                    return p
            except OSError:
                continue
        return None

    # ---- container metadata ------------------------------------------
    def _write_docker_labels(self, path: str) -> None:
        cdir = os.path.dirname(path)
        cfg_path = os.path.join(cdir, "config.v2.json")
        cid = os.path.basename(cdir)
        info = {"id": cid, "runtime": "docker"}
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                c = json.load(f)
            info.update(name=(c.get("Name") or "").lstrip("/"), image=(c.get("Config") or {}).get("Image"),
                        labels=(c.get("Config") or {}).get("Labels") or {})
        except (OSError, ValueError):
            pass
        out = os.path.join(self.ctx.data_dir, "containers")
        os.makedirs(out, exist_ok=True)
        tmp = os.path.join(out, f"{cid}.json.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(info, f)
        os.replace(tmp, os.path.join(out, f"{cid}.json"))

    # ---- lifecycle ---------------------------------------------------
    def run(self, stop: threading.Event) -> None:
        first = True
        while not stop.is_set():
            now = time.time()
            for path in self._discover():
                if path not in self.files:
                    t = self._track(path, first)
                    if t is not None:
                        self.files[path] = t
            for t in list(self.files.values()):
                try:
                    self._poll_file(t, now)
                except OSError as e:
                    self.stats.errors += 1
                    self.stats.last_error = f"{t.path}: {e}"
            first = False
            stop.wait(self.poll)
        for t in list(self.files.values()):
            self._flush_tail(t, force=False)

    def describe(self) -> dict:
        d = super().describe()
        d["files"] = {p: {"offset": t.committed_offset(), "pending_lines": len(t.pending)}
                      for p, t in list(self.files.items())[:200]}
        return d
