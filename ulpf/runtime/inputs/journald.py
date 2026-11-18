"""
systemd journal input (Linux): follows ``journalctl -o json``.

The journal cursor of the last journaled entry is the checkpoint, so a
restart resumes exactly after it. Each record is the entry's JSON (all
fields kept); the workers hand ``MESSAGE`` to the parsers and keep the unit,
PID, priority and host as metadata.
"""
from __future__ import annotations

import json
import queue
import shutil
import subprocess
import threading

from ulpf.runtime.inputs.base import Input


class JournaldInput(Input):
    def run(self, stop: threading.Event) -> None:
        exe = shutil.which("journalctl")
        if not exe:
            raise RuntimeError("journalctl not found: the journald input needs a systemd host")
        key = f"journald:{self.name}"
        ck = self.ctx.checkpoints.durable(key)
        cmd = [exe, "-o", "json", "--follow", "--no-pager"]
        cmd += [f"--after-cursor={ck['value']}"] if ck else ["--lines", "0"]
        for unit in self.opts.get("units") or []:
            cmd += ["-u", unit]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        lines: queue.Queue = queue.Queue(maxsize=10_000)

        def reader():
            for line in iter(proc.stdout.readline, b""):
                lines.put(line.rstrip(b"\n"))
            lines.put(None)

        threading.Thread(target=reader, name=f"ulpf-in-{self.name}-read", daemon=True).start()
        batch: list[bytes] = []
        cursor = None
        ended = False
        try:
            while not stop.is_set() and not ended:
                try:
                    line = lines.get(timeout=0.2)
                except queue.Empty:
                    line = b""
                if line is None:
                    ended = True
                elif line:
                    batch.append(line)
                    try:
                        cursor = json.loads(line).get("__CURSOR") or cursor
                    except ValueError:
                        pass
                    if len(batch) < 500:
                        continue
                if batch:
                    self.accept("journald", batch, block=True)
                    batch = []
                    if cursor:
                        self.ctx.checkpoints.set(key, cursor, self.last_seq)
            if ended and proc.wait(5) not in (0, None) and not stop.is_set():
                raise RuntimeError(proc.stderr.read().decode(errors="replace")[:500] or "journalctl exited")
        finally:
            if batch:
                self.accept("journald", batch, block=True)
                if cursor:
                    self.ctx.checkpoints.set(key, cursor, self.last_seq)
            if proc.poll() is None:
                proc.terminate()
