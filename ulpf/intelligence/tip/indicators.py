"""
Indicator kinds and their canonical forms (what the matcher compares).

The normalisers here and the event tokeniser in ``matcher.py`` mirror ``native/ulpf_core/src/intel.rs``
(``norm_domain``, ``norm_url``, ``url_host``, ``tokens``); ``tests/test_tip.py`` compares both.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

KINDS = ("", "ip", "cidr", "domain", "domain_wildcard", "url", "md5", "sha1", "sha256", "email", "mutex", "registry")
KIND_CODE = {k: i for i, k in enumerate(KINDS) if k}
HASH_KIND = {32: "md5", 40: "sha1", 64: "sha256"}
MAX_VALUE = 2048
_TLD_MAX = 24
_LABEL = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_")
_HEX = frozenset("0123456789abcdefABCDEF")
_HIVES = (("hkey_local_machine\\", "hklm\\"), ("hkey_current_user\\", "hkcu\\"), ("hkey_classes_root\\", "hkcr\\"),
          ("hkey_users\\", "hku\\"), ("hkey_current_config\\", "hkcc\\"), ("\\registry\\machine\\", "hklm\\"),
          ("\\registry\\user\\", "hku\\"))
_ASCII_LOWER = {c: c + 32 for c in range(65, 91)}


def ascii_lower(s: str) -> str:
    """Lower-case A-Z only (Rust ``to_ascii_lowercase``)."""
    return s.translate(_ASCII_LOWER)


@dataclass
class Indicator:
    kind: str
    value: str
    confidence: float = 0.5              # 0.0 - 1.0, as published (decay applies on top)
    category: str = "Unknown"
    threat_actor: str = ""
    campaign: str = ""
    kill_chain_phase: str = ""
    diamond: dict = field(default_factory=dict)   # adversary, capability, infrastructure, victim
    first_seen: float | None = None
    last_seen: float | None = None
    valid_until: float | None = None
    stix_id: str = ""
    source: str = ""
    flags: int = 0                       # 1: event source / destination IP only (legacy iocs.json)


# ------------------------------------------------------------------------------- normalisation

def norm_domain(s: str) -> str | None:
    d = ascii_lower(s.strip().rstrip("."))
    if not d or not d.isascii() or "." not in d or len(d) > 253:
        return None
    for label in d.split("."):
        if not label or len(label) > 63 or not set(label) <= _LABEL:
            return None
    return d


def norm_url(s: str) -> str | None:
    s = s.strip()
    if "://" not in s:
        return None
    scheme, rest = s.split("://", 1)
    scheme = ascii_lower(scheme)
    if scheme not in ("http", "https", "ftp", "hxxp", "hxxps"):
        return None
    scheme = scheme.replace("hxxp", "http")
    rest = rest.split("#", 1)[0]
    cut = min((i for i in (rest.find("/"), rest.find("?")) if i >= 0), default=len(rest))
    auth, path = rest[:cut], rest[cut:]
    host_port = ascii_lower(auth.rsplit("@", 1)[-1])
    host = host_port
    if ":" in host_port:
        h, p = host_port.rsplit(":", 1)
        if not h.endswith("]") or host_port.startswith("["):
            if (scheme, p) in (("http", "80"), ("https", "443"), ("ftp", "21")):
                host = h
    host = host.rstrip(".")
    if not host:
        return None
    return f"{scheme}://{host}{path or '/'}"


def url_host(u: str) -> str | None:
    if "://" not in u:
        return None
    rest = u.split("://", 1)[1]
    cut = min((i for i in (rest.find("/"), rest.find("?"), rest.find("#")) if i >= 0), default=len(rest))
    hp = rest[:cut].rsplit("@", 1)[-1]
    if hp.startswith("["):
        return hp.lstrip("[").split("]", 1)[0]
    return hp.rsplit(":", 1)[0] if ":" in hp else hp


def parse_ip(s: str):
    """``IpAddr::from_str``: dotted quad or IPv6 (no zone id)."""
    if not s or "%" in s or "/" in s:
        return None
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        return None


def ip_key(a) -> bytes:
    """IPv4-mapped IPv6 compares as its IPv4 address."""
    if a.version == 6 and a.ipv4_mapped is not None:
        return a.ipv4_mapped.packed
    return a.packed


def ip_display(a) -> str:
    """Rust ``IpAddr`` Display (an IPv4-mapped address keeps its dotted tail)."""
    if a.version == 6 and a.ipv4_mapped is not None:
        return f"::ffff:{a.ipv4_mapped}"
    return str(a)


def hive_variants(k: str) -> list[str]:
    k = ascii_lower(k.strip()).replace("/", "\\")
    out = {k}
    for long, short in _HIVES:
        if k.startswith(long):
            out.add(short + k[len(long):])
        elif k.startswith(short):
            out.add(long + k[len(short):])
    out |= {json_escaped(v) for v in out}
    return sorted(out, key=lambda v: v.encode("utf-8"))


def json_escaped(v: str) -> str:
    """A pattern as it appears inside a JSON string (backslashes doubled)."""
    return v.replace("\\", "\\\\")


def normalize(kind: str, value) -> tuple[str, str] | None:
    """(kind, canonical value) or None when the value is not a valid indicator of that kind.

    ``kind`` may be "auto" (guess from the value) or "hash" (by length)."""
    if value is None:
        return None
    v = str(value).strip()
    if not v or len(v) > MAX_VALUE:
        return None
    kind = (kind or "auto").lower()
    if kind == "auto":
        kind = guess_kind(v)
        if kind is None:
            return None
    if kind in ("ip", "ipv4", "ipv6", "cidr"):
        if "/" in v:
            try:
                n = ipaddress.ip_network(v, strict=False)
            except ValueError:
                return None
            if n.prefixlen == n.max_prefixlen:
                return "ip", str(n.network_address)
            return "cidr", str(n)
        a = parse_ip(v)
        if a is None:
            return None
        return "ip", str(a.ipv4_mapped) if a.version == 6 and a.ipv4_mapped else str(a)
    if kind in ("domain", "hostname", "domain_wildcard"):
        if v.startswith("*."):
            d = norm_domain(v[2:])
            return ("domain_wildcard", d) if d and "." in d else None
        if kind == "domain_wildcard":
            d = norm_domain(v)
            return ("domain_wildcard", d) if d else None
        if parse_ip(v) is not None:
            return normalize("ip", v)
        d = norm_domain(v)
        return ("domain", d) if d else None
    if kind == "url":
        u = norm_url(v if "://" in v else "http://" + v)
        return ("url", u) if u else None
    if kind in ("md5", "sha1", "sha256", "hash"):
        if not set(v) <= _HEX or len(v) not in HASH_KIND:
            return None
        k = HASH_KIND[len(v)]
        return (k, v.lower()) if kind in ("hash", k) else None
    if kind == "email":
        local, at, dom = v.rpartition("@")
        d = norm_domain(dom) if at else None
        if not local or "@" in local or not d:
            return None
        return "email", f"{ascii_lower(local)}@{d}"
    if kind == "mutex":
        return ("mutex", v) if 3 <= len(v) <= 512 else None
    if kind == "registry":
        return ("registry", ascii_lower(v).replace("/", "\\")) if 6 <= len(v) <= 1024 else None
    return None


def guess_kind(v: str) -> str | None:
    if parse_ip(v) is not None or ("/" in v and parse_ip(v.split("/", 1)[0]) is not None):
        return "ip"
    if "://" in v:
        return "url"
    if len(v) in HASH_KIND and set(v) <= _HEX:
        return "hash"
    if v.startswith("*."):
        return "domain"
    if "@" in v:
        return "email"
    low = ascii_lower(v)
    if low.startswith(("hkey_", "hklm\\", "hkcu\\", "hkcr\\", "hku\\", "\\registry\\")):
        return "registry"
    if norm_domain(v):
        return "domain"
    return None
