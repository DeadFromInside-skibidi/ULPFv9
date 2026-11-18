"""
A Delta Lake table (protocol reader 1 / writer 2) on any ``Store``.

Commits are ``_delta_log/<version>.json`` files created with put-if-absent, so concurrent
writers (the flusher, the compactor, other nodes) serialise on the version number: the loser
re-reads the log and rebases (appends always can; a compaction only if the files it removes
are still live). ``txn`` actions make hot-to-cold flushes idempotent across crashes. Every 10
commits a Parquet checkpoint is written (with ``_last_checkpoint``) so readers replay a bounded
log. Spark, Databricks and delta-rs can read the table; encrypted data files need the key.
"""
from __future__ import annotations

import io
import json
import threading
import time
import uuid
from dataclasses import dataclass, field

import pyarrow as pa
import pyarrow.parquet as pq

from ulpf.lake.crypto import LakeKey, commit_mac, mac_equal
from ulpf.lake.store import Exists, Store

LOG = "_delta_log"
CHECKPOINT_EVERY = 10
PROTOCOL = {"minReaderVersion": 1, "minWriterVersion": 2}


class ConcurrentCommit(Exception):
    pass


class TamperedLog(Exception):
    pass


def _delta_type(t: pa.DataType) -> str:
    if pa.types.is_string(t):
        return "string"
    if pa.types.is_timestamp(t):
        return "timestamp"
    return {pa.int8(): "byte", pa.int16(): "short", pa.int32(): "integer", pa.int64(): "long",
            pa.float64(): "double", pa.bool_(): "boolean"}[t]


def schema_string(schema: pa.Schema) -> str:
    return json.dumps({"type": "struct", "fields": [
        {"name": f.name, "type": _delta_type(f.type), "nullable": True, "metadata": {}} for f in schema]})


def _vkey(v: int) -> str:
    return f"{LOG}/{v:020d}.json"


@dataclass
class Snapshot:
    version: int = -1
    files: dict = field(default_factory=dict)        # path -> add action
    removed: dict = field(default_factory=dict)      # path -> remove action (tombstones)
    txns: dict = field(default_factory=dict)         # appId -> version
    metadata: dict | None = None
    protocol: dict | None = None
    mac: str = ""

    def apply(self, actions: list[dict]) -> None:
        for a in actions:
            if "add" in a:
                p = a["add"]["path"]
                self.files[p] = a["add"]
                self.removed.pop(p, None)
            elif "remove" in a:
                p = a["remove"]["path"]
                self.files.pop(p, None)
                self.removed[p] = a["remove"]
            elif "txn" in a:
                self.txns[a["txn"]["appId"]] = a["txn"]["version"]
            elif "metaData" in a:
                self.metadata = a["metaData"]
            elif "protocol" in a:
                self.protocol = a["protocol"]


def _split(body: bytes) -> tuple[list[dict], dict]:
    actions, info = [], {}
    for line in body.splitlines():
        if line.strip():
            a = json.loads(line)
            if "commitInfo" in a:
                info = a["commitInfo"]
            else:
                actions.append(a)
    return actions, info


def _canonical(actions: list[dict]) -> bytes:
    return b"\n".join(json.dumps(a, sort_keys=True, separators=(",", ":")).encode() for a in actions)


class DeltaTable:
    def __init__(self, store: Store, key: LakeKey | None = None):
        self.store = store
        self.key = key
        self._lock = threading.Lock()
        self._snap = Snapshot()

    # ------------------------------------------------------------------ reading

    def exists(self) -> bool:
        return self.store.exists(_vkey(0))

    def _versions_after(self, v: int) -> list[int]:
        out = []
        for k, _ in self.store.list(LOG):
            name = k.rsplit("/", 1)[-1]
            if name.endswith(".json") and name[:-5].isdigit() and int(name[:-5]) > v:
                out.append(int(name[:-5]))
        return sorted(out)

    def _read_commit(self, v: int) -> tuple[list[dict], dict]:
        return _split(self.store.get(_vkey(v)))

    def _from_checkpoint(self) -> Snapshot:
        try:
            last = json.loads(self.store.get(f"{LOG}/_last_checkpoint"))
        except KeyError:
            return Snapshot()
        v = int(last["version"])
        table = pq.read_table(io.BytesIO(self.store.get(f"{LOG}/{v:020d}.checkpoint.parquet")))
        s = Snapshot()
        acts = []
        for row in table.to_pylist():
            for col in ("protocol", "metaData", "txn", "add", "remove"):
                a = row.get(col)
                if a is not None:
                    for m in ("partitionValues", "tags", "configuration"):
                        if isinstance(a.get(m), list):
                            a[m] = dict(a[m])
                    if col == "metaData" and isinstance(a.get("format", {}).get("options"), list):
                        a["format"]["options"] = dict(a["format"]["options"])
                    acts.append({col: {k: x for k, x in a.items() if x is not None}})
        s.apply(acts)
        s.version = v
        s.mac = self._read_commit(v)[1].get("ulpfMac", "")
        return s

    def snapshot(self, refresh: bool = True) -> Snapshot:
        """The table's current state (incremental: only new commits are read)."""
        with self._lock:
            s = self._snap
            if s.version < 0:
                s = self._from_checkpoint()
            if refresh:
                for v in self._versions_after(s.version):
                    actions, info = self._read_commit(v)
                    s.apply(actions)
                    s.version, s.mac = v, info.get("ulpfMac", "")
            self._snap = s
            return s

    def verify(self) -> dict:
        """Replay every commit and check the MAC chain. Raises TamperedLog."""
        if self.key is None:
            raise ValueError("verifying the commit chain needs the master key")
        prev, n = "", 0
        for v in self._versions_after(-1):
            if v != n:
                raise TamperedLog(f"commit {n} is missing")
            actions, info = self._read_commit(v)
            mac = info.get("ulpfMac")
            if mac is None or not mac_equal(mac, commit_mac(self.key.mac_key, prev, _canonical(actions))):
                raise TamperedLog(f"commit {v}: MAC mismatch (edited, reordered or foreign)")
            prev, n = mac, n + 1
        return {"commits": n, "head_mac": prev}

    # ------------------------------------------------------------------ writing

    def create(self, schema: pa.Schema, partition_columns: list[str], name: str = "") -> None:
        meta = {"id": str(uuid.uuid4()), "name": name or None, "format": {"provider": "parquet", "options": {}},
                "schemaString": schema_string(schema), "partitionColumns": list(partition_columns),
                "configuration": {}, "createdTime": int(time.time() * 1000)}
        try:
            self.commit([{"protocol": dict(PROTOCOL)}, {"metaData": {k: v for k, v in meta.items() if v is not None}}],
                        -1, "CREATE TABLE")
        except ConcurrentCommit:
            pass                                     # another writer created it

    def commit(self, actions: list[dict], read_version: int, operation: str) -> int:
        """Write ``actions`` as version ``read_version + 1``; ConcurrentCommit if it exists."""
        v = read_version + 1
        prev = self._snap.mac if self._snap.version == read_version else self._mac_of(read_version)
        info = {"timestamp": int(time.time() * 1000), "operation": operation, "engineInfo": "ulpf-lakehouse"}
        if self.key is not None:
            info["ulpfMac"] = commit_mac(self.key.mac_key, prev, _canonical(actions))
            info["ulpfKeyId"] = self.key.key_id
        body = b"\n".join(json.dumps(a, separators=(",", ":")).encode() for a in actions + [{"commitInfo": info}]) + b"\n"
        try:
            self.store.put_if_absent(_vkey(v), body)
        except Exists:
            raise ConcurrentCommit(v) from None
        if v % CHECKPOINT_EVERY == 0 and v > 0:
            try:
                self.checkpoint()
            except Exception:
                pass                                 # the JSON log is complete without it
        return v

    def _mac_of(self, v: int) -> str:
        return "" if v < 0 else self._read_commit(v)[1].get("ulpfMac", "")

    def commit_with_retry(self, build, operation: str, attempts: int = 20) -> int | None:
        """``build(snapshot) -> actions | None`` against the latest snapshot until it commits.
        None from ``build`` means nothing to do (e.g. a compaction's inputs are gone)."""
        for _ in range(attempts):
            s = self.snapshot()
            actions = build(s)
            if not actions:
                return None
            try:
                return self.commit(actions, s.version, operation)
            except ConcurrentCommit:
                time.sleep(0.01)
        raise ConcurrentCommit(f"{operation}: gave up after {attempts} conflicts")

    def checkpoint(self) -> int:
        s = self.snapshot()
        rows = [{"protocol": s.protocol}, {"metaData": {**s.metadata, "format": {
            "provider": s.metadata["format"]["provider"], "options": list(s.metadata["format"].get("options", {}).items())},
            "configuration": list(s.metadata.get("configuration", {}).items())}}]
        rows += [{"txn": {"appId": k, "version": v}} for k, v in s.txns.items()]
        rows += [{"add": {**a, "partitionValues": list(a.get("partitionValues", {}).items()),
                          "tags": list((a.get("tags") or {}).items())}} for a in s.files.values()]
        rows += [{"remove": r} for r in s.removed.values()]
        smap = pa.map_(pa.string(), pa.string())
        schema = pa.schema([
            ("txn", pa.struct([("appId", pa.string()), ("version", pa.int64()), ("lastUpdated", pa.int64())])),
            ("add", pa.struct([("path", pa.string()), ("partitionValues", smap), ("size", pa.int64()),
                               ("modificationTime", pa.int64()), ("dataChange", pa.bool_()), ("stats", pa.string()),
                               ("tags", smap)])),
            ("remove", pa.struct([("path", pa.string()), ("deletionTimestamp", pa.int64()), ("dataChange", pa.bool_()),
                                  ("extendedFileMetadata", pa.bool_()), ("partitionValues", smap), ("size", pa.int64())])),
            ("metaData", pa.struct([("id", pa.string()), ("name", pa.string()), ("description", pa.string()),
                                    ("format", pa.struct([("provider", pa.string()), ("options", smap)])),
                                    ("schemaString", pa.string()), ("partitionColumns", pa.list_(pa.string())),
                                    ("configuration", smap), ("createdTime", pa.int64())])),
            ("protocol", pa.struct([("minReaderVersion", pa.int32()), ("minWriterVersion", pa.int32())])),
        ])
        for r in rows:
            if "remove" in r:
                r["remove"] = {k: (list(v.items()) if k == "partitionValues" else v) for k, v in r["remove"].items()}
        table = pa.Table.from_pylist(rows, schema=schema)
        buf = io.BytesIO()
        pq.write_table(table, buf)
        self.store.put(f"{LOG}/{s.version:020d}.checkpoint.parquet", buf.getvalue())
        self.store.put(f"{LOG}/_last_checkpoint", json.dumps({"version": s.version, "size": len(rows)}).encode())
        return s.version
