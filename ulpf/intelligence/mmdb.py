"""
Reader for MaxMind DB (``.mmdb``) files: GeoLite2 / GeoIP2 City and Country,
DB-IP Lite, IPinfo and other databases in the MaxMind DB format.

Pure Python, no dependencies (air-gap friendly); the file is memory-mapped
and lookups are cached by the caller. Format: https://maxmind.github.io/MaxMind-DB/
"""
from __future__ import annotations

import ipaddress
import mmap
import os
import struct

_META_MARKER = b"\xab\xcd\xefMaxMind.com"


class MMDBError(ValueError):
    pass


class MMDBReader:
    def __init__(self, path: str):
        self.path = path
        self._f = open(path, "rb")
        try:
            self._buf = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError as e:      # empty file
            self._f.close()
            raise MMDBError(f"{path}: empty file") from e
        start = self._buf.rfind(_META_MARKER, max(0, len(self._buf) - 128 * 1024))
        if start < 0:
            self.close()
            raise MMDBError(f"{path}: not a MaxMind DB file (metadata marker missing)")
        self.metadata, _ = self._decode(start + len(_META_MARKER), start + len(_META_MARKER))
        m = self.metadata
        try:
            self.node_count = int(m["node_count"])
            self.record_size = int(m["record_size"])
            self.ip_version = int(m["ip_version"])
        except (KeyError, TypeError) as e:
            self.close()
            raise MMDBError(f"{path}: incomplete metadata") from e
        if self.record_size not in (24, 28, 32):
            self.close()
            raise MMDBError(f"{path}: unsupported record size {self.record_size}")
        self.node_bytes = self.record_size * 2 // 8
        self.tree_size = self.node_count * self.node_bytes
        self.data_start = self.tree_size + 16
        self._ipv4_start = None

    # ------------------------------------------------------------------

    def close(self) -> None:
        try:
            self._buf.close()
        except (AttributeError, ValueError):
            pass
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    @property
    def database_type(self) -> str:
        return str(self.metadata.get("database_type", ""))

    @property
    def build_epoch(self) -> int:
        return int(self.metadata.get("build_epoch") or 0)

    def _record(self, node: int, bit: int) -> int:
        b = self._buf
        off = node * self.node_bytes
        rs = self.record_size
        if rs == 24:
            o = off + bit * 3
            return (b[o] << 16) | (b[o + 1] << 8) | b[o + 2]
        if rs == 28:
            if bit == 0:
                return ((b[off + 3] & 0xF0) << 20) | (b[off] << 16) | (b[off + 1] << 8) | b[off + 2]
            return ((b[off + 3] & 0x0F) << 24) | (b[off + 4] << 16) | (b[off + 5] << 8) | b[off + 6]
        o = off + bit * 4
        return struct.unpack_from(">I", b, o)[0]

    def _start_node(self, bits: int) -> int:
        if self.ip_version == 6 and bits == 32:
            if self._ipv4_start is None:
                node = 0
                for _ in range(96):
                    if node >= self.node_count:
                        break
                    node = self._record(node, 0)
                self._ipv4_start = node
            return self._ipv4_start
        return 0

    def lookup(self, ip: str) -> tuple[dict | None, int]:
        """(record, prefix length) for an address; (None, 0) when not in the database."""
        addr = ipaddress.ip_address(ip)
        if addr.version == 6 and self.ip_version == 4:
            v4 = addr.ipv4_mapped
            if v4 is None:
                return None, 0
            addr = v4
        bits = 32 if addr.version == 4 else 128
        value = int(addr)
        node = self._start_node(bits)
        depth = 0
        while depth < bits and node < self.node_count:
            node = self._record(node, (value >> (bits - 1 - depth)) & 1)
            depth += 1
        if node == self.node_count:
            return None, depth
        if node < self.node_count:
            raise MMDBError("invalid search tree")
        offset = node - self.node_count - 16 + self.data_start
        if offset >= len(self._buf):
            raise MMDBError("data pointer outside the file")
        rec, _ = self._decode(offset, self.data_start)
        return rec, depth

    # ------------------------------------------------------------------
    # Data section decoder
    # ------------------------------------------------------------------

    def _decode(self, off: int, base: int):
        b = self._buf
        ctrl = b[off]
        off += 1
        kind = ctrl >> 5
        if kind == 1:   # pointer
            ss = (ctrl >> 3) & 3
            v = ctrl & 7
            if ss == 0:
                p = (v << 8) | b[off]
                off += 1
            elif ss == 1:
                p = ((v << 16) | (b[off] << 8) | b[off + 1]) + 2048
                off += 2
            elif ss == 2:
                p = ((v << 24) | (b[off] << 16) | (b[off + 1] << 8) | b[off + 2]) + 526336
                off += 3
            else:
                p = struct.unpack_from(">I", b, off)[0]
                off += 4
            val, _ = self._decode(base + p, base)
            return val, off
        if kind == 0:   # extended type
            kind = 7 + b[off]
            off += 1
        size = ctrl & 0x1F
        if size >= 29:
            if size == 29:
                size = 29 + b[off]
                off += 1
            elif size == 30:
                size = 285 + ((b[off] << 8) | b[off + 1])
                off += 2
            else:
                size = 65821 + ((b[off] << 16) | (b[off + 1] << 8) | b[off + 2])
                off += 3
        if kind == 2:     # utf-8 string
            return bytes(b[off:off + size]).decode("utf-8", "replace"), off + size
        if kind == 7:     # map
            out = {}
            for _ in range(size):
                k, off = self._decode(off, base)
                v, off = self._decode(off, base)
                out[k] = v
            return out, off
        if kind == 11:    # array
            arr = []
            for _ in range(size):
                v, off = self._decode(off, base)
                arr.append(v)
            return arr, off
        if kind == 3:     # double
            return struct.unpack_from(">d", b, off)[0], off + 8
        if kind == 15:    # float
            return struct.unpack_from(">f", b, off)[0], off + 4
        if kind in (5, 6, 9, 10):   # unsigned ints of `size` bytes
            return int.from_bytes(b[off:off + size], "big"), off + size
        if kind == 8:     # int32
            v = int.from_bytes(b[off:off + size], "big")
            if size == 4 and v & 0x80000000:
                v -= 1 << 32
            return v, off + size
        if kind == 4:     # bytes
            return bytes(b[off:off + size]), off + size
        if kind == 14:    # boolean
            return bool(size), off
        if kind in (12, 13):
            return None, off
        raise MMDBError(f"unknown data type {kind}")


def geo_from_record(rec: dict, lang: str = "en") -> dict:
    """GeoIP2/GeoLite2/DB-IP City or Country record -> enricher fields."""
    def name(d):
        return ((d or {}).get("names") or {}).get(lang)
    country = rec.get("country") or rec.get("registered_country") or {}
    loc = rec.get("location") or {}
    subs = rec.get("subdivisions") or []
    out = {"country": name(country), "cc": country.get("iso_code"), "city": name(rec.get("city")),
           "region": name(subs[0]) if subs else None,
           "lat": loc.get("latitude"), "lon": loc.get("longitude")}
    if rec.get("autonomous_system_number"):
        out["asn"] = f"AS{rec['autonomous_system_number']}"
        out["asn_name"] = rec.get("autonomous_system_organization")
    return {k: v for k, v in out.items() if v is not None}


def find_databases(*dirs: str) -> list[str]:
    """``.mmdb`` files in the given directories (City before Country before ASN)."""
    found = []
    for d in dirs:
        if d and os.path.isdir(d):
            found += [os.path.join(d, n) for n in sorted(os.listdir(d)) if n.lower().endswith(".mmdb")]

    def rank(p):
        n = os.path.basename(p).lower()
        return 0 if "city" in n else 1 if "country" in n else 2
    return sorted(found, key=rank)
