"""
S3-compatible data-lake output (AWS S3, MinIO, Ceph RGW, ...): partitioned
Parquet objects written with a single signed PUT each.

Object keys are deterministic (sink name + first buffered segment + count),
so a redelivery after a crash overwrites the same object instead of adding a
duplicate.
"""
from __future__ import annotations

import io
import urllib.parse

from ulpf.runtime.buffer import Segment
from ulpf.runtime.net import HttpClient, sigv4_headers
from ulpf.runtime.retry import classify_http
from ulpf.runtime.sinks.base import Sink, env_secret
from ulpf.runtime.sinks.lake import encode_lake, partitioned_tables


class S3ParquetSink(Sink):
    ext = "parquet"
    batch_segments = 256
    idempotent = True
    remote = True

    def encode(self, events: list[dict]) -> bytes:
        return encode_lake(events, self.view)

    def open(self) -> None:
        o = self.opts
        self.access = env_secret(o.get("access_key_env"), "S3 access key") or ""
        self.secret = env_secret(o.get("secret_key_env"), "S3 secret key") or ""
        self.token = env_secret(o.get("session_token_env"), "S3 session token") if o.get("session_token_env") else None
        if o.get("endpoint"):                       # path-style for S3-compatible stores
            self.base = o["endpoint"].rstrip("/") + "/" + o["bucket"]
        else:
            self.base = f"https://{o['bucket']}.s3.{o['region']}.amazonaws.com"
        self.client = HttpClient(self.base, timeout=300)
        self.rotate_bytes = int(o.get("rotate_mb", 128) * 2**20)

    def deliver_many(self, segs: list[Segment], read) -> None:
        import pyarrow as pa
        import pyarrow.parquet as pq
        group, size = [], 0
        for seg in segs:
            if group and size + seg.size > self.rotate_bytes:
                self._put_group(group, read, pa, pq)
                group, size = [], 0
            group.append(seg)
            size += seg.size
        if group:
            self._put_group(group, read, pa, pq)

    def _put_group(self, group, read, pa, pq) -> None:
        table = pa.concat_tables([pq.read_table(io.BytesIO(read(s))) for s in group], promote_options="default")
        stem = f"{self.name}-{group[0].name.split('.')[0]}-{len(group)}"
        prefix = (self.opts.get("prefix") or "").strip("/")
        for rel, part in partitioned_tables(table, list(self.opts.get("partition") or ["dt"])):
            buf = io.BytesIO()
            pq.write_table(part, buf, compression="zstd")
            key = "/".join(p for p in (prefix, rel, stem + ".parquet") if p)
            self._put(key, buf.getvalue())

    def _put(self, key: str, body: bytes) -> None:
        path = "/" + urllib.parse.quote(key, safe="/-_.~=")
        url = self.base + path
        headers = sigv4_headers("PUT", url, self.opts["region"], "s3", self.access, self.secret, body,
                                self.token, {"content-type": "application/vnd.apache.parquet"})
        r = self.client.request("PUT", path, body, headers)
        err = classify_http(r.status, r.text)
        if err is not None:
            raise err

    def records(self, payload: bytes) -> list[bytes]:
        import orjson
        import pyarrow.parquet as pq
        return [orjson.dumps(r, default=str) for r in pq.read_table(io.BytesIO(payload)).to_pylist()]
