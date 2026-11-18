"""
Indicator matching against events: the compiled ``ulpf_core.IocMatcher`` (Cuckoo filter + exact map,
CIDR, wildcard suffixes, Aho-Corasick; ``native/ulpf_core/src/intel.rs``) or, without the core, the
equivalent ``PyMatcher`` below. Both read the snapshot ``write_snapshot`` produces and return the same
hit for the same event (``tests/test_tip.py``).

Candidates, in order: source IP, destination IP, then the tokens of the raw event text (URLs and their
hosts, e-mail addresses and their domains, IPv4 addresses, hashes, domains), then mutex / registry
patterns. The first candidate that is an indicator wins.
"""
from __future__ import annotations

import ipaddress
import os
import struct

from ulpf.intelligence.tip.indicators import (KINDS, KIND_CODE, ascii_lower, hive_variants, ip_display, ip_key,
                                              json_escaped, norm_domain, norm_url, parse_ip, url_host)

MAGIC = b"ULPFIOC1"
MAX_TEXT = 64 * 1024
_REC = struct.Struct("<BBId6I")
_TOKEN = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._%+@:/?#=&~-[]")
_EDGES = ".,;:)]'\"-_!?("
_SPLIT = str.maketrans({c: " " for c in "/:?#=&@%+~[]"})
_HEXCH = frozenset("0123456789abcdefABCDEF")
_HASH = {32: 6, 40: 7, 64: 8}


# ------------------------------------------------------------------------------- snapshot

def write_snapshot(rows, path: str | None = None) -> bytes:
    """rows: (kind, value, confidence, category, actor, campaign, kill_chain, id, source, flags), best
    first (the first row of a value wins). Written atomically when ``path`` is given."""
    strings: dict[str, int] = {"": 0}
    recs = bytearray()
    n = 0

    def sid(s) -> int:
        s = "" if s is None else str(s)
        i = strings.get(s)
        if i is None:
            i = strings[s] = len(strings)
        return i

    for kind, value, conf, cat, actor, campaign, kill, ioc_id, source, flags in rows:
        recs += _REC.pack(KIND_CODE[kind], flags & 0xFF, sid(value), float(conf), sid(cat), sid(actor),
                          sid(campaign), sid(kill), sid(ioc_id), sid(source))
        n += 1
    out = bytearray(MAGIC)
    out += struct.pack("<I", len(strings))
    for s in strings:
        b = s.encode("utf-8")
        out += struct.pack("<I", len(b))
        out += b
    out += struct.pack("<I", n)
    out += recs
    data = bytes(out)
    if path:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = f"{path}.{os.getpid()}.tmp"
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    return data


def read_snapshot(data: bytes):
    if len(data) < 16 or data[:8] != MAGIC:
        raise ValueError("not a ULPF indicator snapshot")
    p = 8
    (n,) = struct.unpack_from("<I", data, p)
    p += 4
    if n > 50_000_000:
        raise ValueError("snapshot string table too large")
    strings = []
    for _ in range(n):
        (ln,) = struct.unpack_from("<I", data, p)
        p += 4
        if p + ln > len(data):
            raise ValueError("truncated snapshot")
        strings.append(data[p:p + ln].decode("utf-8"))
        p += ln
    (m,) = struct.unpack_from("<I", data, p)
    p += 4
    if m > 50_000_000 or p + m * _REC.size > len(data):
        raise ValueError("truncated snapshot")
    rows = []
    for kind, flags, v, conf, *f in _REC.iter_unpack(data[p:p + m * _REC.size]):
        if not 0 < kind < len(KINDS) or max(v, *f) >= len(strings):
            raise ValueError("snapshot: bad indicator record")
        rows.append((kind, flags, strings[v], conf, *(strings[i] for i in f)))
    return rows


# ------------------------------------------------------------------------------- event tokens

def _trim(s: str) -> str:
    return s.strip(_EDGES)


def _truncate(text: str) -> str:
    if len(text) <= MAX_TEXT // 4 or len(text.encode("utf-8")) <= MAX_TEXT:
        return text
    return text.encode("utf-8")[:MAX_TEXT].decode("utf-8", "ignore")


def tokens(text: str) -> list:
    """("ip", addr, raw) | ("domain", d) | ("url", u) | ("hash", code, h) | ("email", e), in order."""
    out = []
    t = _truncate(text)
    i, n = 0, len(t)
    while i < n:
        if t[i] not in _TOKEN:
            i += 1
            continue
        s = i
        while i < n and t[i] in _TOKEN:
            i += 1
        tok = _trim(t[s:i])
        if len(tok) < 4:
            continue
        low = ascii_lower(tok)
        if low.startswith(("http://", "https://", "hxxp", "ftp://")):
            u = norm_url(tok)
            if u is not None:
                h = url_host(u)
                out.append(("url", u))
                if h is not None:
                    a = parse_ip(h)
                    if a is not None:
                        out.append(("ip", a, ""))
                    else:
                        d = norm_domain(h)
                        if d:
                            out.append(("domain", d))
            continue
        if "@" in tok:
            local, dom = tok.split("@", 1)
            if local and "@" not in dom:
                d = norm_domain(dom)
                if d:
                    out.append(("email", f"{ascii_lower(local)}@{d}"))
                    out.append(("domain", d))
                    continue
        for part in tok.translate(_SPLIT).split(" "):
            part = _trim(part)
            if len(part) < 4:
                continue
            if part.count(".") == 3 and part.replace(".", "").isdigit():
                try:
                    out.append(("ip", ipaddress.IPv4Address(part), part))
                    continue
                except ValueError:
                    pass
            if set(part) <= _HEXCH:
                if len(part) in _HASH:
                    out.append(("hash", _HASH[len(part)], ascii_lower(part)))
                continue
            d = norm_domain(part)
            if d:
                tld = d.rsplit(".", 1)[-1]
                if 2 <= len(tld) <= 24 and tld.isascii() and tld.isalpha():
                    out.append(("domain", d))
    return out


# ------------------------------------------------------------------------------- matcher

class PyMatcher:
    """Pure-Python ``ulpf_core.IocMatcher`` (same interface, same results; dict lookups)."""

    def __init__(self):
        self._set([])

    def _set(self, rows) -> None:
        exact: dict = {}
        c4: dict = {}
        c6: dict = {}
        pats: list = []
        counts = [0] * len(KINDS)
        for i, (kind, _flags, value, *_rest) in enumerate(rows):
            counts[kind] += 1
            k = KINDS[kind]
            if k == "ip":
                a = parse_ip(value)
                if a is not None:
                    exact.setdefault((1, ip_key(a)), i)
            elif k == "cidr":
                try:
                    net = ipaddress.ip_network(value, strict=True)
                except ValueError:
                    continue
                (c4 if net.version == 4 else c6).setdefault(net.prefixlen, {}).setdefault(
                    int(net.network_address), i)
            elif k == "mutex":
                low = ascii_lower(value)
                if "\\" in low:
                    pats.append((json_escaped(low), i))
                pats.append((low, i))
            elif k == "registry":
                pats.extend((p, i) for p in hive_variants(value))
            else:
                exact.setdefault((kind, value), i)
        self.rows = rows
        self.exact = exact
        self.cidr4 = sorted(c4.items(), reverse=True)
        self.cidr6 = sorted(c6.items(), reverse=True)
        self.pats = pats
        self.counts = counts

    def load_bytes(self, data: bytes) -> int:
        self._set(read_snapshot(data))
        return len(self.rows)

    def load(self, path: str) -> int:
        with open(path, "rb") as f:
            return self.load_bytes(f.read())

    def _ip(self, a):
        key = ip_key(a)
        e = self.exact.get((1, key))
        if e is not None:
            return e, 1
        if len(key) == 4:
            x = int.from_bytes(key, "big")
            for ln, m in self.cidr4:
                e = m.get(x & ((0xFFFFFFFF << (32 - ln)) & 0xFFFFFFFF if ln else 0))
                if e is not None:
                    return e, 2
        else:
            x = int(a)
            for ln, m in self.cidr6:
                e = m.get(x & (((1 << 128) - 1) << (128 - ln) & ((1 << 128) - 1) if ln else 0))
                if e is not None:
                    return e, 2
        return None

    def _domain(self, d: str):
        e = self.exact.get((3, d))
        if e is not None:
            return e, 3
        rest = d
        while "." in rest:
            rest = rest.split(".", 1)[1]
            if "." not in rest:
                break
            e = self.exact.get((4, rest))
            if e is not None:
                return e, 4
        return None

    def _first(self, src_ip, dst_ip, text):
        for ip in (src_ip, dst_ip):
            if ip:
                a = parse_ip(ip.strip())
                if a is not None:
                    h = self._ip(a)
                    if h:
                        return h[0], h[1], ip
        if text is None:
            return None
        for c in tokens(text):
            typ = c[0]
            if typ == "ip":
                h = self._ip(c[1])
                if h and not self.rows[h[0]][1] & 1:
                    return h[0], h[1], c[2] or ip_display(c[1])
            elif typ == "domain":
                h = self._domain(c[1])
                if h:
                    return h[0], h[1], c[1]
            elif typ == "url":
                e = self.exact.get((5, c[1]))
                if e is not None:
                    return e, 5, c[1]
            elif typ == "hash":
                e = self.exact.get((c[1], c[2]))
                if e is not None:
                    return e, c[1], c[2]
            else:
                e = self.exact.get((9, c[1]))
                if e is not None:
                    return e, 9, c[1]
        if self.pats:
            t = _truncate(text)
            low = ascii_lower(t)
            best = None
            for p, e in self.pats:
                j = low.find(p)
                if j >= 0 and (best is None or j < best[0] or (j == best[0] and len(p) > best[1])):
                    best = (j, len(p), e)
            if best:
                j, ln, e = best
                return e, self.rows[e][0], t[j:j + ln]
        return None

    def match_event(self, src_ip=None, dst_ip=None, text=None):
        h = self._first(src_ip, dst_ip, text)
        if h is None:
            return None
        e, kind, value = h
        _k, _f, _v, conf, cat, actor, campaign, kill, ioc_id, source = self.rows[e]
        return KINDS[kind], value, cat, conf, ioc_id, source, actor, campaign, kill

    def count_matches(self, texts) -> int:
        return sum(1 for t in texts if self.match_event(None, None, t) is not None)

    def stats(self) -> dict:
        out = {"indicators": len(self.rows), "memory_bytes": 0}
        out.update({k: self.counts[i] for i, k in enumerate(KINDS) if k})
        return out


def new_matcher(prefer_core: bool = True):
    if prefer_core:
        try:
            from ulpf import ulpf_core
            return ulpf_core.IocMatcher()
        except (ImportError, AttributeError):
            pass
    return PyMatcher()


def apply_hit(event: dict, hit, tags: list) -> None:
    """threat.* and tags of a match (``intel_hit`` in ``native/ulpf_core/src/engine.rs``)."""
    kind, value, cat, conf, ioc_id, source, actor, campaign, kill = hit
    cat = cat or "Unknown"
    threat = event["threat"]
    threat["category"] = cat
    threat["confidence"] = float(conf)
    threat["ioc_type"] = kind
    threat["ioc_value"] = value
    threat["intel"] = {"id": ioc_id or None, "source": source or None, "threat_actor": actor or None,
                       "campaign": campaign or None, "kill_chain_phase": kill or None}
    tags.append("threat:" + cat.lower().replace(" ", "_"))
    tags.append("ioc_match")
