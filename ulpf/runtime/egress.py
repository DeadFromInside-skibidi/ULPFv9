"""
Egress guard (U4): every outbound connection the process makes is checked.

Installed with ``sys.addaudithook`` in the host and in every worker, so it
also covers code the config does not know about (libraries, plugins,
enrichment). It sees ``socket.connect`` (all TCP / TLS and connected UDP) and
``socket.sendto`` (UDP), except replies sent from a listening input's socket
(SNMP inform acknowledgements).

* ``record``  (industry default): every non-loopback destination is counted;
  ``ulpf run`` reports them, so "no outbound traffic" is observable.
* ``enforce`` (``airgap.enforce``, always on in defence mode): a destination
  that is not loopback and not in ``airgap.allow`` raises ``PermissionError``
  before any packet leaves.

Allowed host names follow DNS changes: their addresses are re-resolved every
``airgap.dns_refresh_seconds`` by a background thread, and whenever the
process itself resolves an allowed name (``socket.getaddrinfo``) the answer
is allowed at once. An address a name stops resolving to stays allowed for
``airgap.dns_grace_seconds`` (connections being drained during a fail-over).

What this guard cannot see: native code that calls ``connect(2)`` itself
(librdkafka, the AWS C++ SDK in pyarrow, DuckDB extensions). For those,
``vet_endpoints`` checks configured broker/endpoint lists before they reach
the C library, ``ulpf.storage.database`` locks DuckDB's external access in
defence mode, and ``ulpf.runtime.egress_os`` renders a kernel-level policy
(nftables / systemd) that also binds native threads.

Audit hooks cannot be removed, so ``uninstall`` only disables the policy.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import sys
import threading
import time

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_policy: "EgressPolicy | None" = None
_hooked = False
_real_getaddrinfo = socket.getaddrinfo
_FOREVER = float("inf")


def _ip(host: str):
    try:
        return ipaddress.ip_address(str(host).split("%")[0])
    except ValueError:
        return None


class EgressPolicy:
    def __init__(self, allow: list[str], enforce: bool, listener_ports: set[int] | None = None,
                 dns_refresh_s: float = 60.0, dns_grace_s: float = 300.0, resolve=None):
        self.enforce = enforce
        self.nets: list = []                    # CIDR entries (checked by scan; few)
        self.names: set[str] = set()
        self.dns_refresh_s = float(dns_refresh_s or 0)
        self.dns_grace_s = float(dns_grace_s or 0)
        self._resolve = resolve or _real_getaddrinfo
        # address -> monotonic expiry; read lock-free by the hook (dict get is atomic)
        self._addrs: dict[str, float] = {}
        for a in allow or []:
            host = str(a).strip()
            if not host:
                continue
            try:
                net = ipaddress.ip_network(host, strict=False)
            except ValueError:
                self.names.add(host.lower().rstrip("."))
                continue
            if net.num_addresses == 1:
                self._addrs[str(net.network_address)] = _FOREVER
            else:
                self.nets.append(net)
        self.listener_ports = set(listener_ports or ())
        self.destinations: dict[str, int] = {}
        self.blocked: dict[str, int] = {}
        self.dns_refreshes = 0
        self.dns_failures: dict[str, str] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        for name in sorted(self.names):
            if not self.refresh_name(name):
                logger.warning(f"egress: allowed host {name!r} does not resolve now; only its "
                               "name-based connections (proxies) can match until it does")

    # ------------------------------------------------------------------
    # DNS
    # ------------------------------------------------------------------

    def _expiry(self) -> float:
        if self.dns_refresh_s <= 0:
            return _FOREVER                      # resolved once, at start (pre-9.1 behaviour)
        return time.monotonic() + self.dns_refresh_s + self.dns_grace_s

    def learn(self, name: str, infos) -> int:
        """Allow the addresses ``name`` resolved to (``getaddrinfo`` results). Returns how many."""
        if str(name).lower().rstrip(".") not in self.names:
            return 0
        exp = self._expiry()
        n = 0
        for info in infos or ():
            try:
                ip = _ip(info[4][0])
            except (IndexError, TypeError):
                continue
            if ip is None:
                continue
            key = str(ip)
            if self._addrs.get(key, 0) < exp:
                self._addrs[key] = exp
            n += 1
        return n

    def refresh_name(self, name: str) -> bool:
        try:
            infos = self._resolve(name, None)
        except OSError as e:
            self.dns_failures[name] = str(e)
            return False
        self.dns_failures.pop(name, None)
        return self.learn(name, infos) > 0

    def refresh(self) -> None:
        """Re-resolve every allowed name and expire addresses past their grace period."""
        for name in sorted(self.names):
            self.refresh_name(name)
        now = time.monotonic()
        for addr, exp in list(self._addrs.items()):
            if exp < now:
                self._addrs.pop(addr, None)
        self.dns_refreshes += 1

    def start(self) -> None:
        if not self.names or self.dns_refresh_s <= 0 or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._refresh_loop, name="ulpf-egress-dns", daemon=True)
        self._thread.start()

    def _refresh_loop(self) -> None:
        while not self._stop.wait(self.dns_refresh_s):
            try:
                self.refresh()
            except Exception:
                logger.debug("egress: DNS refresh failed", exc_info=True)

    def stop(self) -> None:
        self._stop.set()

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    def allowed(self, host: str) -> bool:
        ip = _ip(host)
        if ip is None:
            return str(host).lower().rstrip(".") in self.names
        if ip.is_loopback or (ip.version == 6 and ip.ipv4_mapped and ip.ipv4_mapped.is_loopback):
            return True
        if ip.is_unspecified:
            return True
        if ip.version == 6 and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        exp = self._addrs.get(str(ip))
        if exp is not None and exp >= time.monotonic():
            return True
        return any(ip in n for n in self.nets)

    def check(self, event: str, sock, address) -> None:
        if not isinstance(address, tuple) or not address:
            return                     # AF_UNIX path or similar: local
        host = str(address[0])
        ip = _ip(host)
        if ip is not None and ip.is_loopback:
            return
        if event == "socket.sendto" and self.listener_ports:
            try:
                if sock.getsockname()[1] in self.listener_ports:
                    return             # a reply from a listening input (SNMP inform ack)
            except OSError:
                pass
        dest = f"{host}:{address[1]}" if len(address) > 1 else host
        if self.allowed(host):
            with _lock:
                self.destinations[dest] = self.destinations.get(dest, 0) + 1
            return
        with _lock:
            if self.enforce:
                self.blocked[dest] = self.blocked.get(dest, 0) + 1
            else:
                self.destinations[dest] = self.destinations.get(dest, 0) + 1
        if self.enforce:
            raise PermissionError(f"ULPF egress guard: {dest} is not in airgap.allow")

    def snapshot(self) -> dict:
        with _lock:
            return {"mode": "enforce" if self.enforce else "record",
                    "destinations": dict(self.destinations), "blocked": dict(self.blocked),
                    "dns": {"names": sorted(self.names), "refreshes": self.dns_refreshes,
                            "failures": dict(self.dns_failures)}}


_local = threading.local()


class route_probe:
    """Context for a UDP ``connect()`` that only asks the kernel for a route (no packet)."""

    def __enter__(self):
        _local.probe = True
        return self

    def __exit__(self, *exc):
        _local.probe = False


def _hook(event: str, args) -> None:
    p = _policy
    if p is None or event not in ("socket.connect", "socket.sendto"):
        return
    if getattr(_local, "probe", False) and event == "socket.connect":
        return
    p.check(event, args[0], args[1])


def _getaddrinfo(host, *args, **kwargs):
    infos = _real_getaddrinfo(host, *args, **kwargs)
    p = _policy
    if p is not None and host and p.names:
        try:
            p.learn(host.decode() if isinstance(host, bytes) else str(host), infos)
        except Exception:
            logger.debug("egress: could not record resolved addresses", exc_info=True)
    return infos


def install(allow: list[str], enforce: bool, listener_ports: set[int] | None = None,
            dns_refresh_s: float = 60.0, dns_grace_s: float = 300.0) -> EgressPolicy:
    global _policy, _hooked
    policy = EgressPolicy(allow, enforce, listener_ports, dns_refresh_s, dns_grace_s)
    with _lock:
        old, _policy = _policy, policy
        if not _hooked:
            sys.addaudithook(_hook)
            socket.getaddrinfo = _getaddrinfo
            _hooked = True
    if old is not None:
        old.stop()
    policy.start()
    return policy


def uninstall() -> None:
    global _policy
    old, _policy = _policy, None
    if old is not None:
        old.stop()


def current() -> EgressPolicy | None:
    return _policy


def _split_endpoint(ep: str) -> str:
    """Host part of ``host``, ``host:port``, ``[v6]:port``, ``scheme://host:port/path``."""
    ep = str(ep).strip()
    if "://" in ep:
        ep = ep.split("://", 1)[1]
    ep = ep.split("/", 1)[0].rsplit("@", 1)[-1]
    if ep.startswith("["):
        return ep[1:].split("]", 1)[0]
    if ep.count(":") == 1:
        return ep.split(":", 1)[0]
    return ep


def vet_endpoints(endpoints, what: str) -> None:
    """Refuse a native client's endpoint list unless every host is allowed (enforce mode).

    Native libraries connect without passing through the audit hook, so their
    configured endpoints are checked here, before the library is handed them.
    (Brokers a Kafka cluster *advertises* later are not visible here; the
    OS-level policy in ``egress_os`` covers those.)
    """
    p = _policy
    if p is None or not p.enforce:
        return
    if isinstance(endpoints, str):
        endpoints = endpoints.split(",")
    bad = [e for e in endpoints if e and not p.allowed(_split_endpoint(e))]
    if bad:
        with _lock:
            for e in bad:
                p.blocked[str(e)] = p.blocked.get(str(e), 0) + 1
        raise PermissionError(f"ULPF egress guard: {what} endpoint(s) {', '.join(map(str, bad))} "
                              "not in airgap.allow")
