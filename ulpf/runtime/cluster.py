"""
Multi-node operation (plan G6).

Ingest nodes are independent runtimes that share one directory
(``cluster.shared_dir``: an NFS/SMB share or any mounted volume):

    <shared>/nodes/<node>.json        heartbeat {node, address, epoch, seq, ts, ...}
    <shared>/leases/<input>.json      lease {input, holder, epoch, token}
    <shared>/leases/<input>.lock      record-locked while a lease is read and changed
    <shared>/checkpoints/<key>.json   input positions, written with the lease's token

Push inputs (syslog, HTTP, OTLP, NetFlow, SNMP) run on every node; senders
or a load balancer pick the node. Inputs with ``placement: one`` (the
default for cloud pull inputs) run on exactly one node:

* **Liveness without clocks.** A heartbeat carries a per-boot ``epoch`` and a
  ``seq`` that grows with every beat. A peer is live while its ``seq`` keeps
  advancing, measured on *this* node's monotonic clock; wall-clock time
  stamps (skewed hosts, cached file attributes) are not compared.
* **Leases with fencing tokens.** The preferred owner (rendezvous hashing over
  the live nodes) takes the input's lease under an OS record lock
  (``fcntl.lockf`` / ``msvcrt.locking``; NFSv4 and SMB servers arbitrate
  these and release them when the client dies). A lease held by a live node
  is never taken; every change of holder increments the lease's ``token``.
* **Fenced checkpoints.** Shared checkpoint writes carry the writer's token and
  are refused when the stored checkpoint has a newer one, so a node that lost
  its lease cannot move the watermark back. Positions are adopted by token.
* **Self-fencing.** A node that cannot write its heartbeat for half of
  ``failover_seconds`` stops its ``placement: one`` inputs, before any other
  node may consider it dead (after ``failover_seconds``).

A graceful stop releases the node's leases after its last checkpoint flush,
so the next owner continues exactly where it stopped. Across a crash,
delivery is at least once: records pulled but not yet checkpointed by the
failed node are pulled again.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
import sys
import threading
import time

logger = logging.getLogger(__name__)


class FencedError(RuntimeError):
    """A write was refused because another node holds a newer lease."""


def score(node: str, key: str) -> int:
    return int.from_bytes(hashlib.sha256(f"{node}\0{key}".encode()).digest()[:8], "big")


def owner(key: str, nodes: list[str]) -> str | None:
    """Rendezvous (highest random weight) hashing: stable, minimal movement."""
    return max(nodes, key=lambda n: score(n, key)) if nodes else None


def _atomic_json(path: str, doc: dict, durable: bool = False) -> None:
    tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f)
        if durable:
            f.flush()
            os.fsync(f.fileno())
    for attempt in range(20):            # Windows/SMB: a reader may hold the target open
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if attempt == 19:
                os.remove(tmp)
                raise
            time.sleep(0.02)


def _read_json(path: str) -> dict | None:
    # open() revalidates with the server (NFS close-to-open), unlike cached stat() attributes
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


_thread_locks: dict[str, threading.Lock] = {}
_thread_locks_guard = threading.Lock()


class FileLock:
    """Exclusive OS record lock on ``path`` (held briefly, never across a lease's lifetime).

    POSIX record locks belong to the process, so an in-process lock per path
    also serialises threads (several runtimes can share one process in tests).
    """

    def __init__(self, path: str, timeout: float = 10.0):
        self.path = path
        self.timeout = timeout
        self.fd = -1
        with _thread_locks_guard:
            self._tlock = _thread_locks.setdefault(os.path.abspath(path), threading.Lock())

    def __enter__(self):
        deadline = time.monotonic() + self.timeout
        if not self._tlock.acquire(timeout=self.timeout):
            raise TimeoutError(f"could not lock {self.path}")
        try:
            self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o644)
            while True:
                try:
                    self._lock(self.fd)
                    return self
                except OSError:
                    if time.monotonic() > deadline:
                        os.close(self.fd)
                        raise TimeoutError(f"could not lock {self.path}")
                    time.sleep(0.02)
        except BaseException:
            self._tlock.release()
            raise

    def __exit__(self, *exc):
        try:
            self._unlock(self.fd)
        finally:
            os.close(self.fd)
            self._tlock.release()

    if sys.platform == "win32":
        @staticmethod
        def _lock(fd: int) -> None:
            import msvcrt
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

        @staticmethod
        def _unlock(fd: int) -> None:
            import msvcrt
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        @staticmethod
        def _lock(fd: int) -> None:
            import fcntl
            fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)   # POSIX record lock: works over NFS

        @staticmethod
        def _unlock(fd: int) -> None:
            import fcntl
            fcntl.lockf(fd, fcntl.LOCK_UN)


def read_heartbeats(shared_dir: str) -> dict[str, dict]:
    d = os.path.join(shared_dir, "nodes")
    out = {}
    if not os.path.isdir(d):
        return out
    for n in os.listdir(d):
        if not n.endswith(".json"):
            continue
        hb = _read_json(os.path.join(d, n))
        if hb and "node" in hb:
            out[hb["node"]] = hb
    return out


def read_leases(shared_dir: str) -> dict[str, dict]:
    d = os.path.join(shared_dir, "leases")
    out = {}
    if os.path.isdir(d):
        for n in os.listdir(d):
            if n.endswith(".json"):
                doc = _read_json(os.path.join(d, n))
                if doc and "input" in doc:
                    out[doc["input"]] = doc
    return out


def status(cfg: dict, now: float | None = None) -> dict:
    """Nodes, liveness and input assignments as seen from the shared directory.

    A one-shot reader cannot watch heartbeats advance, so ``alive`` here uses
    heartbeat ages and is approximate across hosts with skewed clocks; the
    lease holders are authoritative for who runs ``placement: one`` inputs.
    """
    c = cfg["cluster"]
    now = now or time.time()
    hbs = read_heartbeats(c["shared_dir"])
    configured = {n["id"]: n["address"] for n in c.get("nodes") or []}
    nodes = []
    for nid in sorted(set(configured) | set(hbs)):
        hb = hbs.get(nid)
        age = None if hb is None else round(now - hb["ts"], 1)
        nodes.append({"node": nid, "address": (hb or {}).get("address") or configured.get(nid),
                      "configured": nid in configured, "last_heartbeat_age_s": age,
                      "heartbeat_seq": (hb or {}).get("seq"),
                      "alive": hb is not None and age <= c["failover_seconds"] and not hb.get("stopped"),
                      "running_inputs": (hb or {}).get("running_inputs", [])})
    alive = [n["node"] for n in nodes if n["alive"]]
    assignments = {i["name"]: owner(i["name"], alive) for i in cfg.get("inputs") or []
                   if i.get("enabled", True) and placement(i) == "one"}
    leases = {name: {"holder": d.get("holder"), "token": d.get("token")}
              for name, d in read_leases(c["shared_dir"]).items()}
    return {"shared_dir": c["shared_dir"], "nodes": nodes, "alive": alive, "assignments": assignments,
            "leases": leases}


_ONE_BY_DEFAULT = {"cloudtrail", "pubsub", "okta", "entra", "eventhubs"}


def placement(inp: dict) -> str:
    p = inp.get("placement", "auto")
    if p == "auto":
        return "one" if inp.get("type") in _ONE_BY_DEFAULT else "all"
    return p


def input_of_key(key: str) -> str | None:
    """Input name of a checkpoint key (``<type>:<input>[:...]``)."""
    parts = key.split(":", 2)
    return parts[1] if len(parts) >= 2 else None


class PeerView:
    """Which nodes are live, judged by heartbeat progress on this node's monotonic clock."""

    def __init__(self, failover_s: float, clock=time.monotonic):
        self.failover_s = failover_s
        self.clock = clock
        self._seen: dict[str, tuple] = {}     # node -> (epoch, seq, local time it last advanced)

    def observe(self, hbs: dict[str, dict]) -> dict[str, bool]:
        now = self.clock()
        out = {}
        for node, hb in hbs.items():
            if "seq" not in hb:                    # a pre-9.1 node: only its time stamp is available
                out[node] = time.time() - hb.get("ts", 0) <= self.failover_s and not hb.get("stopped")
                continue
            mark = (hb.get("epoch"), hb.get("seq"))
            prev = self._seen.get(node)
            if prev is None or prev[:2] != mark:
                self._seen[node] = (*mark, now)
            out[node] = not hb.get("stopped") and now - self._seen[node][2] <= self.failover_s
        return out


class Cluster:
    def __init__(self, cfg: dict, node: str, on_change=None):
        c = cfg["cluster"]
        self.node = node
        self.shared = c["shared_dir"]
        self.heartbeat_s = float(c["heartbeat_seconds"])
        self.failover_s = float(c["failover_seconds"])
        addr = next((n["address"] for n in c.get("nodes") or [] if n["id"] == node), None)
        self.address = addr or f"http://{socket.gethostname()}:{cfg['api']['port']}"
        for sub in ("nodes", "checkpoints", "leases"):
            os.makedirs(os.path.join(self.shared, sub), exist_ok=True)
        self.on_change = on_change              # fn() -> called when ownership may have changed
        self.running_inputs: list[str] = []
        self.epoch = os.urandom(8).hex()        # this boot; a restarted node is a new holder
        self.seq = 0
        self.peers = PeerView(self.failover_s)
        self._alive: list[str] = [node]
        self._held: dict[str, int] = {}         # input -> lease token
        self._held_lock = threading.Lock()
        self.wanted: set[str] = set()           # preferred here but the lease is not ours yet: retry
        self._last_beat_ok = time.monotonic()
        self.fenced = False                     # cannot reach the shared directory: run no `one` inputs
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def hb_path(self) -> str:
        return os.path.join(self.shared, "nodes", f"{self.node}.json")

    def beat(self, stopped: bool = False) -> None:
        self.seq += 1
        _atomic_json(self.hb_path, {"node": self.node, "address": self.address, "epoch": self.epoch,
                                    "seq": self.seq, "ts": time.time(), "pid": os.getpid(),
                                    "running_inputs": list(self.running_inputs), "stopped": stopped})
        self._last_beat_ok = time.monotonic()

    def alive_nodes(self) -> list[str]:
        live = [n for n, ok in self.peers.observe(read_heartbeats(self.shared)).items() if ok]
        if self.node not in live:
            live.append(self.node)
        return sorted(live)

    def owns(self, key: str) -> bool:
        """Rendezvous preference among live nodes (the lease decides who actually runs it)."""
        return not self.fenced and owner(key, self._alive) == self.node

    def start(self) -> None:
        self.beat()
        self._alive = self.alive_nodes()
        self._thread = threading.Thread(target=self._loop, name="ulpf-cluster", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.wait(self.heartbeat_s):
            self.tick()

    def tick(self) -> bool:
        """One heartbeat round. Returns True (and calls ``on_change``) when ownership may have changed."""
        changed = False
        try:
            self.beat()
            if self.fenced:
                logger.warning("cluster: shared directory reachable again; un-fencing")
                self.fenced, changed = False, True
            alive = self.alive_nodes()
            if alive != self._alive:
                logger.info(f"cluster: live nodes {self._alive} -> {alive}")
                self._alive, changed = alive, True
            lost = self._lost_leases()
            if lost:
                logger.warning(f"cluster: lease(s) taken over by another node: {lost}")
                changed = True
            if self.wanted:
                changed = True                 # the previous holder may have released by now
        except OSError as e:                   # includes TimeoutError (lease lock)
            logger.warning(f"cluster heartbeat failed: {e}")
            if not self.fenced and time.monotonic() - self._last_beat_ok > self.failover_s / 2:
                logger.error("cluster: no heartbeat written for failover_seconds/2; stopping "
                             "placement: one inputs (self-fencing)")
                self.fenced, changed = True, True
        if changed and self.on_change:
            self.on_change()
        return changed

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(5)
        for name in list(self._held):
            try:
                self.release(name)
            except OSError:
                pass
        try:
            self.beat(stopped=True)       # hand inputs over immediately
        except OSError:
            pass

    # ---- leases --------------------------------------------------------------

    def _lease_paths(self, name: str) -> tuple[str, str]:
        safe = hashlib.sha256(name.encode()).hexdigest()[:32]
        base = os.path.join(self.shared, "leases", safe)
        return base + ".json", base + ".lock"

    def acquire(self, name: str) -> int | None:
        """The fencing token if this node holds (or now takes) ``name``'s lease, else None."""
        if self.fenced:
            return None
        path, lock = self._lease_paths(name)
        with FileLock(lock):
            doc = _read_json(path)
            if doc and doc.get("holder") == self.node and doc.get("epoch") == self.epoch:
                token = int(doc["token"])
            else:
                holder = (doc or {}).get("holder")
                if holder and holder != self.node and holder in self._alive:
                    return None            # a live node holds it: never taken from under it
                token = int((doc or {}).get("token", 0)) + 1
                _atomic_json(path, {"input": name, "holder": self.node, "epoch": self.epoch, "token": token,
                                    "previous_holder": holder, "taken_at": time.time()}, durable=True)
                logger.info(f"cluster: lease {name} acquired (token {token}, previous holder {holder})")
        with self._held_lock:
            self._held[name] = token
        return token

    def holds(self, name: str) -> bool:
        token = self._held.get(name)
        if token is None:
            return False
        doc = _read_json(self._lease_paths(name)[0])
        return bool(doc) and doc.get("holder") == self.node and doc.get("epoch") == self.epoch \
            and int(doc.get("token", -1)) == token

    def _lost_leases(self) -> list[str]:
        lost = [n for n in list(self._held) if not self.holds(n)]
        with self._held_lock:
            for n in lost:
                self._held.pop(n, None)
        return lost

    def release(self, name: str) -> None:
        """Give up a lease (after the input stopped and its checkpoints were flushed)."""
        path, lock = self._lease_paths(name)
        with self._held_lock:
            token = self._held.pop(name, None)
        if token is None:
            return
        with FileLock(lock):
            doc = _read_json(path)
            if doc and doc.get("holder") == self.node and int(doc.get("token", -1)) == token:
                _atomic_json(path, {**doc, "holder": None, "released_at": time.time()}, durable=True)

    @property
    def held(self) -> dict[str, int]:
        return dict(self._held)

    def token_for_key(self, key: str) -> int | None:
        name = input_of_key(key)
        return self._held.get(name) if name is not None else None

    # ---- shared checkpoints ------------------------------------------------

    def _ck_path(self, key: str) -> str:
        safe = hashlib.sha256(key.encode()).hexdigest()[:32]
        return os.path.join(self.shared, "checkpoints", f"{safe}.json")

    def save_checkpoint(self, key: str, entry: dict, token: int | None = None) -> None:
        """Mirror a checkpoint. With a lease ``token``, refused (``FencedError``) when the
        shared copy was written under a newer lease."""
        doc = {"key": key, "node": self.node, "updated": time.time(), **entry}
        if token is None:
            _atomic_json(self._ck_path(key), doc)
            return
        doc["token"] = token
        name = input_of_key(key) or key
        with FileLock(self._lease_paths(name)[1]):
            current = _read_json(self._ck_path(key))
            if current and int(current.get("token") or 0) > token:
                raise FencedError(f"checkpoint {key}: lease token {token} is older than {current['token']} "
                                  f"(written by {current.get('node')})")
            _atomic_json(self._ck_path(key), doc, durable=True)

    def load_checkpoint(self, key: str) -> dict | None:
        doc = _read_json(self._ck_path(key))
        return doc if doc and doc.get("key") == key else None


def fan_out_events(nodes: list[dict], params: dict, api_key: str | None, limit: int, timeout: float = 10.0) -> dict:
    """Query /api/v1/events on every live node and merge, newest event time first."""
    import urllib.parse
    import urllib.request
    merged, errors = [], {}
    qs = urllib.parse.urlencode({**{k: v for k, v in params.items() if v is not None}, "limit": limit})
    for n in nodes:
        if not n.get("alive") or not n.get("address"):
            continue
        req = urllib.request.Request(f"{n['address'].rstrip('/')}/api/v1/events?{qs}",
                                     headers={"X-API-Key": api_key} if api_key else {})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                for e in json.loads(r.read()).get("events", []):
                    e.setdefault("_node", n["node"])
                    merged.append(e)
        except Exception as e:     # one node down must not fail the query
            errors[n["node"]] = f"{type(e).__name__}: {e}"
    merged.sort(key=lambda e: str(e.get("timestamp") or ""), reverse=True)
    return {"count": min(len(merged), limit), "events": merged[:limit], "node_errors": errors}
