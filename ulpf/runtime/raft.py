"""
Embedded Raft consensus (zero dependencies) for cluster leases, fencing tokens and checkpoints.

Replaces the shared-directory lock backend when ``cluster.backend: raft``: no
NFS/SMB share, works across Kubernetes pods, VPCs and regions.

Protocol (Ongaro & Ousterhout, "In Search of an Understandable Consensus
Algorithm", plus the thesis' extensions):

* leader election with randomised timeouts and **pre-vote** (a partitioned node
  rejoining cannot depose a healthy leader by inflating terms);
* **check-quorum**: a leader that has not heard from a majority within an
  election timeout steps down, so a minority partition never has a leader;
* log replication with conflict back-off, commit only of current-term entries
  (Figure 8 safety), persistent term/vote/log (fsync) and snapshots;
* single-server membership changes (one at a time, applied at commit).

The replicated state machine (``LeaseMachine``) holds leases, fencing tokens and
fenced checkpoints. A lease's **fencing token is the Raft log index** of the
entry that granted it: strictly increasing across holders, so a deposed
holder's late writes are refused everywhere. Lease time comes from the
leader's clock stamped into the command (monotonic across leaders); holders
self-fence at half the TTL after their last committed renewal, which tolerates
clock skew below TTL/2.

The core is a deterministic, tick-driven state machine (``RaftNode.tick`` /
``step``) with no I/O; ``TcpTransport`` (length-prefixed JSON frames over TCP,
optional mutual TLS) and ``RaftCluster`` (the ``ulpf.runtime.cluster.Cluster``
interface) wrap it. Tests drive several nodes through a simulated network with
partitions, loss and reordering and check the safety invariants.
"""
from __future__ import annotations

import json
import logging
import os
import queue
import random
import socket
import ssl
import struct
import threading
import time

logger = logging.getLogger(__name__)

FOLLOWER, CANDIDATE, LEADER = "follower", "candidate", "leader"
MAX_FRAME = 16 * 2**20
MAX_BATCH = 256


class NotLeader(RuntimeError):
    def __init__(self, leader: str | None):
        super().__init__(f"not the leader (leader: {leader})")
        self.leader = leader


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

class MemoryStorage:
    def __init__(self):
        self.term, self.vote = 0, None
        self.entries: list[dict] = []
        self.snapshot: dict | None = None

    def save_state(self, term: int, vote: str | None) -> None:
        self.term, self.vote = term, vote

    def append(self, entries: list[dict]) -> None:
        self.entries.extend(entries)

    def truncate_from(self, pos: int) -> None:
        del self.entries[pos:]

    def save_snapshot(self, snap: dict, keep: list[dict]) -> None:
        self.snapshot, self.entries = snap, list(keep)


class FileStorage(MemoryStorage):
    """``state.json`` (term, vote), ``log.jsonl`` (entries after the snapshot), ``snapshot.json``; fsync'd."""

    def __init__(self, directory: str):
        super().__init__()
        self.dir = directory
        os.makedirs(directory, exist_ok=True)
        self._state = os.path.join(directory, "state.json")
        self._log = os.path.join(directory, "log.jsonl")
        self._snap = os.path.join(directory, "snapshot.json")
        try:
            with open(self._state, "r", encoding="utf-8") as f:
                st = json.load(f)
            self.term, self.vote = int(st["term"]), st.get("vote")
        except (OSError, ValueError, KeyError):
            pass
        try:
            with open(self._snap, "r", encoding="utf-8") as f:
                self.snapshot = json.load(f)
        except (OSError, ValueError):
            self.snapshot = None
        if os.path.exists(self._log):
            with open(self._log, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        self.entries.append(json.loads(line))
                    except ValueError:
                        break             # torn tail after a crash: everything after it is dropped
        self._fh = open(self._log, "a", encoding="utf-8")

    def _atomic(self, path: str, doc: dict) -> None:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(doc, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def save_state(self, term, vote):
        super().save_state(term, vote)
        self._atomic(self._state, {"term": term, "vote": vote})

    def append(self, entries):
        super().append(entries)
        self._fh.write("".join(json.dumps(e, separators=(",", ":")) + "\n" for e in entries))
        self._fh.flush()
        os.fsync(self._fh.fileno())

    def _rewrite(self) -> None:
        self._fh.close()
        tmp = self._log + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write("".join(json.dumps(e, separators=(",", ":")) + "\n" for e in self.entries))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._log)
        self._fh = open(self._log, "a", encoding="utf-8")

    def truncate_from(self, pos):
        super().truncate_from(pos)
        self._rewrite()

    def save_snapshot(self, snap, keep):
        self._atomic(self._snap, snap)
        super().save_snapshot(snap, keep)
        self._rewrite()

    def close(self) -> None:
        self._fh.close()


# ---------------------------------------------------------------------------
# Replicated state machine
# ---------------------------------------------------------------------------

class LeaseMachine:
    MAX_KEYS = 100_000

    def __init__(self):
        self.leases: dict[str, dict] = {}
        self.checkpoints: dict[str, dict] = {}
        self.nodes: dict[str, dict] = {}
        self.kv: dict[str, object] = {}
        self.clock = 0.0                      # max leader time seen (monotonic across leaders)

    def apply(self, index: int, cmd: dict):
        op = cmd.get("op")
        now = self.clock = max(self.clock, float(cmd.get("now", 0.0)))
        if op == "acquire":
            name, node, epoch = cmd["name"], cmd["node"], cmd.get("epoch")
            cur = self.leases.get(name)
            if cur and cur.get("holder") == node and cur.get("epoch") == epoch:
                cur["expires"] = now + float(cmd["ttl"])
                return {"granted": True, "token": cur["token"], "renewed": True}
            if cur and cur.get("holder") and cur["expires"] > now:
                return {"granted": False, "holder": cur["holder"], "expires": cur["expires"]}
            if len(self.leases) >= self.MAX_KEYS and name not in self.leases:
                return {"granted": False, "error": "lease table full"}
            self.leases[name] = {"holder": node, "epoch": epoch, "token": index, "expires": now + float(cmd["ttl"]),
                                 "previous_holder": (cur or {}).get("holder"), "granted_at": now}
            return {"granted": True, "token": index}
        if op == "release":
            cur = self.leases.get(cmd["name"])
            if cur and cur.get("holder") == cmd["node"] and cur.get("token") == cmd.get("token"):
                cur["holder"], cur["expires"] = None, now
                return {"released": True}
            return {"released": False}
        if op == "checkpoint":
            key, token = cmd["key"], cmd.get("token")
            cur = self.checkpoints.get(key)
            if token is not None and cur and int(cur.get("token") or 0) > int(token):
                return {"stored": False, "fenced_by": cur.get("token")}
            if len(self.checkpoints) >= self.MAX_KEYS and key not in self.checkpoints:
                return {"stored": False, "error": "checkpoint table full"}
            self.checkpoints[key] = {**cmd["entry"], "key": key, "token": token, "node": cmd.get("node"),
                                     "updated": now}
            return {"stored": True}
        if op == "heartbeat":
            self.nodes[cmd["node"]] = {**(cmd.get("info") or {}), "last": now}
            return {"ok": True}
        if op == "kv":
            self.kv[cmd["key"]] = cmd.get("value")
            return {"ok": True}
        if op in ("noop", "config"):
            return {"ok": True}
        return {"error": f"unknown op {op!r}"}

    def snapshot(self) -> dict:
        return {"leases": self.leases, "checkpoints": self.checkpoints, "nodes": self.nodes, "kv": self.kv,
                "clock": self.clock}

    def restore(self, data: dict) -> None:
        self.leases = dict(data.get("leases") or {})
        self.checkpoints = dict(data.get("checkpoints") or {})
        self.nodes = dict(data.get("nodes") or {})
        self.kv = dict(data.get("kv") or {})
        self.clock = float(data.get("clock") or 0.0)


# ---------------------------------------------------------------------------
# Raft node (deterministic core)
# ---------------------------------------------------------------------------

class RaftNode:
    def __init__(self, node_id: str, members: list[str], storage=None, send=None, machine=None,
                 election_ticks: tuple[int, int] = (10, 20), heartbeat_ticks: int = 2, rng=None,
                 snapshot_every: int = 5000, prevote: bool = True):
        self.id = node_id
        self.storage = storage or MemoryStorage()
        self.send = send or (lambda to, msg: None)
        self.machine = machine or LeaseMachine()
        self.rng = rng or random.Random()
        self.e_lo, self.e_hi = election_ticks
        self.hb_ticks = heartbeat_ticks
        self.snapshot_every = snapshot_every
        self.prevote_enabled = prevote
        self.role = FOLLOWER
        self.leader: str | None = None
        self.term, self.vote = self.storage.term, self.storage.vote
        snap = self.storage.snapshot
        self.snap_index = int(snap["index"]) if snap else 0
        self.snap_term = int(snap["term"]) if snap else 0
        self.members = list(snap["members"]) if snap else sorted(set(members) | {node_id})
        if snap:
            self.machine.restore(snap["data"])
        self.log: list[dict] = list(self.storage.entries)
        self.commit = self.applied = self.snap_index
        self.results: dict[int, object] = {}
        self.next_index: dict[str, int] = {}
        self.match_index: dict[str, int] = {}
        self.heard: dict[str, int] = {}
        self.votes: set[str] = set()
        self.prevotes: set[str] = set()
        self.ticks = 0
        self.elapsed = 0
        self.last_leader_contact = -10**9
        self.timeout = self._new_timeout()
        for e in self.log:                       # membership is whatever the newest config entry says
            if e["cmd"].get("op") == "config":
                self.members = list(e["cmd"]["members"])

    # -- log helpers -------------------------------------------------------
    def _new_timeout(self) -> int:
        return self.rng.randint(self.e_lo, self.e_hi)

    @property
    def last_index(self) -> int:
        return self.snap_index + len(self.log)

    def term_at(self, i: int) -> int | None:
        if i == self.snap_index:
            return self.snap_term
        if i < self.snap_index or i > self.last_index:
            return None
        return self.log[i - self.snap_index - 1]["term"]

    @property
    def last_term(self) -> int:
        return self.term_at(self.last_index) or 0

    def quorum(self) -> int:
        return len(self.members) // 2 + 1

    def peers(self) -> list[str]:
        return [m for m in self.members if m != self.id]

    def _set_term(self, term: int, vote: str | None = None) -> None:
        self.term, self.vote = term, vote
        self.storage.save_state(term, vote)

    def _msg(self, to: str, **kw) -> None:
        self.send(to, {"from": self.id, "to": to, "term": self.term, **kw})

    # -- roles -------------------------------------------------------------
    def _become_follower(self, term: int, leader: str | None) -> None:
        if term > self.term:
            self._set_term(term, None)
        self.role, self.leader = FOLLOWER, leader
        self.elapsed, self.timeout = 0, self._new_timeout()

    def _start_prevote(self) -> None:
        self.prevotes = {self.id}
        self.elapsed, self.timeout = 0, self._new_timeout()
        if self.id not in self.members:
            return
        if len(self.prevotes) >= self.quorum():
            return self._start_election()
        for p in self.peers():
            self._msg(p, type="prevote", next_term=self.term + 1, last_index=self.last_index,
                      last_term=self.last_term)

    def _start_election(self) -> None:
        self.role, self.leader = CANDIDATE, None
        self._set_term(self.term + 1, self.id)
        self.votes = {self.id}
        self.elapsed, self.timeout = 0, self._new_timeout()
        if len(self.votes) >= self.quorum():
            return self._become_leader()
        for p in self.peers():
            self._msg(p, type="vote", last_index=self.last_index, last_term=self.last_term)

    def _become_leader(self) -> None:
        self.role, self.leader = LEADER, self.id
        self.next_index = {p: self.last_index + 1 for p in self.peers()}
        self.match_index = {p: 0 for p in self.peers()}
        self.heard = {p: self.ticks for p in self.peers()}
        self._append_local({"op": "noop", "now": 0.0})          # commits entries of earlier terms
        self._broadcast()

    # -- driving -----------------------------------------------------------
    def tick(self) -> None:
        self.ticks += 1
        self.elapsed += 1
        if self.role == LEADER:
            if self.elapsed >= self.hb_ticks:
                self.elapsed = 0
                self._broadcast()
            # check-quorum: step down when a majority has been silent for an election timeout
            alive = 1 + sum(1 for p in self.peers() if self.ticks - self.heard.get(p, -10**9) <= self.e_hi)
            if self.peers() and alive < self.quorum():
                logger.warning(f"raft {self.id}: lost quorum in term {self.term}; stepping down")
                self._become_follower(self.term, None)
        elif self.elapsed >= self.timeout:
            if self.prevote_enabled:
                self._start_prevote()
            else:
                self._start_election()

    def propose(self, cmd: dict) -> int:
        if self.role != LEADER:
            raise NotLeader(self.leader)
        if cmd.get("op") == "config":
            pending = any(e["cmd"].get("op") == "config" for e in self.log[self.commit - self.snap_index:])
            if pending:
                raise RuntimeError("a membership change is already in progress")
        idx = self._append_local(cmd)
        self._broadcast()
        return idx

    def _append_local(self, cmd: dict) -> int:
        e = {"term": self.term, "cmd": cmd}
        self.log.append(e)
        self.storage.append([e])
        if cmd.get("op") == "config":
            self.members = list(cmd["members"])
            for p in self.peers():
                self.next_index.setdefault(p, self.last_index)
                self.match_index.setdefault(p, 0)
                self.heard.setdefault(p, self.ticks)
        self._advance_commit()
        return self.last_index

    def _broadcast(self) -> None:
        for p in self.peers():
            self._replicate(p)

    def _replicate(self, p: str) -> None:
        nxt = self.next_index.get(p, self.last_index + 1)
        if nxt <= self.snap_index:
            snap = self.storage.snapshot
            self._msg(p, type="snapshot", index=self.snap_index, snap_term=self.snap_term,
                      members=snap["members"] if snap else self.members, data=snap["data"] if snap else {})
            return
        prev = nxt - 1
        entries = self.log[nxt - self.snap_index - 1:nxt - self.snap_index - 1 + MAX_BATCH]
        self._msg(p, type="append", prev_index=prev, prev_term=self.term_at(prev), entries=entries,
                  commit=self.commit)

    def step(self, m: dict) -> None:
        t = m.get("type")
        term = int(m.get("term", 0))
        if t == "prevote":
            # grant if the candidate's log is up to date and no leader was heard recently
            recent = self.ticks - self.last_leader_contact < self.e_lo and self.leader is not None
            ok = (m["next_term"] > self.term and not recent and
                  (m["last_term"], m["last_index"]) >= (self.last_term, self.last_index))
            self._msg(m["from"], type="prevote_resp", granted=ok, req_term=m["next_term"])
            return
        if t == "prevote_resp":
            if m.get("granted") and m.get("req_term") == self.term + 1 and self.role != LEADER:
                self.prevotes.add(m["from"])
                if len(self.prevotes) >= self.quorum():
                    self._start_election()
            elif term > self.term:
                self._become_follower(term, None)
            return
        if term > self.term:
            self._become_follower(term, m["from"] if t in ("append", "snapshot") else None)
        if t == "vote":
            ok = (term == self.term and self.vote in (None, m["from"]) and
                  (m["last_term"], m["last_index"]) >= (self.last_term, self.last_index))
            if ok:
                self._set_term(self.term, m["from"])
                self.elapsed = 0
            self._msg(m["from"], type="vote_resp", granted=ok)
        elif t == "vote_resp":
            if self.role == CANDIDATE and term == self.term and m.get("granted"):
                self.votes.add(m["from"])
                if len(self.votes) >= self.quorum():
                    self._become_leader()
        elif t == "append":
            self._on_append(m, term)
        elif t == "snapshot":
            self._on_snapshot(m, term)
        elif t == "append_resp":
            if self.role != LEADER or term != self.term:
                return
            p = m["from"]
            self.heard[p] = self.ticks
            if m.get("success"):
                self.match_index[p] = max(self.match_index.get(p, 0), m["match"])
                self.next_index[p] = self.match_index[p] + 1
                self._advance_commit()
                if self.next_index[p] <= self.last_index:
                    self._replicate(p)
            else:
                self.next_index[p] = max(1, min(self.next_index.get(p, 1) - 1, int(m.get("hint", 1))))
                self._replicate(p)

    def _on_append(self, m: dict, term: int) -> None:
        if term < self.term:
            self._msg(m["from"], type="append_resp", success=False, match=0, hint=self.last_index + 1)
            return
        self.role, self.leader = FOLLOWER, m["from"]
        self.elapsed = 0
        self.last_leader_contact = self.ticks
        prev, prev_term = m["prev_index"], m["prev_term"]
        if prev > self.last_index:
            self._msg(m["from"], type="append_resp", success=False, match=0, hint=self.last_index + 1)
            return
        if prev >= self.snap_index and self.term_at(prev) != prev_term:
            # back off to the first index of the conflicting term
            ct = self.term_at(prev)
            i = prev
            while i > self.snap_index + 1 and self.term_at(i - 1) == ct:
                i -= 1
            self._msg(m["from"], type="append_resp", success=False, match=0, hint=max(1, i))
            return
        idx = prev
        new = []
        for e in m["entries"]:
            idx += 1
            if idx <= self.snap_index:
                continue
            have = self.term_at(idx)
            if have is not None and have != e["term"]:
                if idx <= self.commit:
                    logger.error(f"raft {self.id}: refusing to truncate committed entry {idx}")
                    return
                self.log = self.log[:idx - self.snap_index - 1]
                self.storage.truncate_from(idx - self.snap_index - 1)
                have = None
            if have is None:
                new.append(e)
        if new:
            self.log.extend(new)
            self.storage.append(new)
            for e in new:
                if e["cmd"].get("op") == "config":
                    self.members = list(e["cmd"]["members"])
        match = prev + len(m["entries"])
        if m["commit"] > self.commit:
            self.commit = min(m["commit"], match)
            self._apply()
        self._msg(m["from"], type="append_resp", success=True, match=match)

    def _on_snapshot(self, m: dict, term: int) -> None:
        if term < self.term:
            return
        self.role, self.leader = FOLLOWER, m["from"]
        self.elapsed = 0
        self.last_leader_contact = self.ticks
        idx = m["index"]
        if idx > self.commit:
            snap = {"index": idx, "term": m["snap_term"], "members": m["members"], "data": m["data"]}
            keep = self.log[idx - self.snap_index:] if self.term_at(idx) == m["snap_term"] else []
            self.storage.save_snapshot(snap, keep)
            self.log = keep
            self.snap_index, self.snap_term = idx, m["snap_term"]
            self.members = list(m["members"])
            self.machine.restore(m["data"])
            self.commit = self.applied = idx
        self._msg(m["from"], type="append_resp", success=True, match=max(idx, self.commit))

    def _advance_commit(self) -> None:
        if self.role != LEADER:
            return
        for n in range(self.last_index, self.commit, -1):
            if self.term_at(n) != self.term:
                break                        # only entries of the current term are committed by counting
            votes = 1 + sum(1 for p in self.peers() if self.match_index.get(p, 0) >= n)
            if votes >= self.quorum():
                self.commit = n
                self._apply()
                break

    def _apply(self) -> None:
        while self.applied < self.commit:
            self.applied += 1
            e = self.log[self.applied - self.snap_index - 1]
            self.results[self.applied] = self.machine.apply(self.applied, e["cmd"])
            if len(self.results) > 10_000:
                for k in sorted(self.results)[:5000]:
                    self.results.pop(k, None)
            if self.id not in self.members and e["cmd"].get("op") == "config" and self.role == LEADER:
                self._become_follower(self.term, None)          # removed from the cluster
        if self.applied - self.snap_index >= self.snapshot_every:
            self._compact()

    def _compact(self) -> None:
        idx = self.applied
        snap = {"index": idx, "term": self.term_at(idx), "members": self.members, "data": self.machine.snapshot()}
        keep = self.log[idx - self.snap_index:]
        self.storage.save_snapshot(json.loads(json.dumps(snap)), keep)
        self.snap_index, self.snap_term = idx, snap["term"]
        self.log = keep


# ---------------------------------------------------------------------------
# Network transport (TCP, optional mutual TLS)
# ---------------------------------------------------------------------------

def _tls_contexts(tls: dict | None):
    if not tls or not tls.get("cert"):
        return None, None
    srv = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv.minimum_version = ssl.TLSVersion.TLSv1_2
    srv.load_cert_chain(tls["cert"], tls.get("key"))
    srv.load_verify_locations(tls["ca"])
    srv.verify_mode = ssl.CERT_REQUIRED                 # mutual TLS: peers present CA-signed certificates
    cli = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cli.minimum_version = ssl.TLSVersion.TLSv1_2
    cli.load_cert_chain(tls["cert"], tls.get("key"))
    cli.load_verify_locations(tls["ca"])
    cli.check_hostname = bool(tls.get("check_hostname", False))
    return srv, cli


class TcpTransport:
    def __init__(self, node_id: str, bind: str, peers: dict[str, str], on_message, tls: dict | None = None,
                 queue_size: int = 10_000):
        self.id = node_id
        self.peers = dict(peers)
        self.on_message = on_message
        self.srv_ctx, self.cli_ctx = _tls_contexts(tls)
        host, port = bind.rsplit(":", 1)
        self.sock = socket.create_server((host, int(port)), reuse_port=False)
        self.port = self.sock.getsockname()[1]
        self._queues = {p: queue.Queue(queue_size) for p in self.peers}
        self._stop = threading.Event()
        self.dropped = 0
        self._threads = [threading.Thread(target=self._accept, name="ulpf-raft-accept", daemon=True)]
        self._threads += [threading.Thread(target=self._sender, args=(p,), name=f"ulpf-raft-send-{p}", daemon=True)
                          for p in self.peers]
        for t in self._threads:
            t.start()

    def send(self, to: str, msg: dict) -> None:
        q = self._queues.get(to)
        if q is None:
            return
        try:
            q.put_nowait(msg)
        except queue.Full:                      # Raft tolerates loss; never block the state machine
            self.dropped += 1

    def _accept(self) -> None:
        self.sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                c, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._reader, args=(c,), daemon=True).start()

    def _reader(self, c: socket.socket) -> None:
        try:
            if self.srv_ctx is not None:
                c = self.srv_ctx.wrap_socket(c, server_side=True)
            c.settimeout(30)
            f = c.makefile("rb")
            while not self._stop.is_set():
                hdr = f.read(4)
                if len(hdr) < 4:
                    return
                n = struct.unpack(">I", hdr)[0]
                if n > MAX_FRAME:
                    return
                body = f.read(n)
                if len(body) < n:
                    return
                try:
                    self.on_message(json.loads(body))
                except ValueError:
                    return
        except (OSError, ssl.SSLError):
            return
        finally:
            try:
                c.close()
            except OSError:
                pass

    def _sender(self, peer: str) -> None:
        q = self._queues[peer]
        conn = None
        backoff = 0.05
        while not self._stop.is_set():
            try:
                msg = q.get(timeout=0.5)
            except queue.Empty:
                continue
            data = json.dumps(msg, separators=(",", ":")).encode()
            for _ in range(2):
                try:
                    if conn is None:
                        host, port = self.peers[peer].rsplit(":", 1)
                        s = socket.create_connection((host, int(port)), timeout=2)
                        conn = self.cli_ctx.wrap_socket(s, server_hostname=host) if self.cli_ctx else s
                        backoff = 0.05
                    conn.sendall(struct.pack(">I", len(data)) + data)
                    break
                except (OSError, ssl.SSLError):
                    if conn is not None:
                        try:
                            conn.close()
                        except OSError:
                            pass
                    conn = None
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 2.0)

    def close(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Cluster adapter (same interface as ulpf.runtime.cluster.Cluster)
# ---------------------------------------------------------------------------

class RaftCluster:
    def __init__(self, cfg: dict, node: str, on_change=None, transport_factory=None):
        from ulpf.runtime.cluster import owner
        self._owner = owner
        c = cfg["cluster"]
        r = c.get("raft") or {}
        self.node = node
        self.on_change = on_change
        self.heartbeat_s = float(c.get("heartbeat_seconds", 2))
        self.failover_s = float(c.get("failover_seconds", 10))
        self.lease_ttl = float(r.get("lease_ttl_seconds", self.failover_s))
        tick_ms = float(r.get("tick_ms", 50))
        self.tick_s = tick_ms / 1000.0
        peers = {str(k): str(v) for k, v in (r.get("peers") or {}).items()}
        data_dir = r.get("data_dir") or os.path.join(cfg.get("node", {}).get("data_dir") or ".", "raft")
        self._lock = threading.RLock()
        self.raft = RaftNode(node, sorted(peers), FileStorage(os.path.join(data_dir, node)),
                             send=lambda to, m: self.transport.send(to, m),
                             election_ticks=(int(r.get("election_ticks_min", 10)), int(r.get("election_ticks_max", 20))),
                             heartbeat_ticks=int(r.get("heartbeat_ticks", 2)))
        bind = r.get("bind") or peers.get(node) or "0.0.0.0:7946"
        others = {k: v for k, v in peers.items() if k != node}
        self.transport = (transport_factory or TcpTransport)(node, bind, others, self._on_message, r.get("tls"))
        self.epoch = os.urandom(8).hex()
        self.running_inputs: list[str] = []
        self.wanted: set[str] = set()
        self._held: dict[str, int] = {}
        self._renewed: dict[str, float] = {}
        self._alive: list[str] = [node]
        self.fenced = False
        self._pending: dict[str, tuple[threading.Event, list]] = {}
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    # -- message pump ------------------------------------------------------
    def _on_message(self, m: dict) -> None:
        with self._lock:
            if m.get("type") == "propose":
                try:
                    idx = self.raft.propose(m["cmd"])
                    self.transport.send(m["from"], {"type": "propose_resp", "from": self.node, "req": m["req"],
                                                    "index": idx})
                except (NotLeader, RuntimeError) as e:
                    self.transport.send(m["from"], {"type": "propose_resp", "from": self.node, "req": m["req"],
                                                    "error": str(e), "leader": getattr(e, "leader", None)})
                return
            if m.get("type") == "propose_resp":
                ev = self._pending.get(m["req"])
                if ev:
                    ev[1].append(m)
                    ev[0].set()
                return
            self.raft.step(m)

    def _ticker(self) -> None:
        nxt = time.monotonic()
        while not self._stop.is_set():
            nxt += self.tick_s
            with self._lock:
                self.raft.tick()
            time.sleep(max(0.0, nxt - time.monotonic()))

    def submit(self, cmd: dict, timeout: float = 5.0):
        """Replicate ``cmd`` and return the state machine's result (forwarded to the leader if needed)."""
        cmd = {**cmd, "now": time.time()}
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                leader = self.raft.leader
                if self.raft.role == LEADER:
                    idx = self.raft.propose(cmd)
                    term = self.raft.term
                else:
                    idx = None
            if idx is None:
                if leader is None or leader == self.node:
                    time.sleep(self.tick_s * 2)
                    continue
                req = os.urandom(8).hex()
                ev = (threading.Event(), [])
                self._pending[req] = ev
                self.transport.send(leader, {"type": "propose", "from": self.node, "req": req, "cmd": cmd})
                ev[0].wait(max(0.05, min(1.0, deadline - time.monotonic())))
                self._pending.pop(req, None)
                if not ev[1] or "index" not in ev[1][0]:
                    time.sleep(self.tick_s * 2)
                    continue
                idx, term = ev[1][0]["index"], None
            while time.monotonic() < deadline:
                with self._lock:
                    if self.raft.applied >= idx:
                        if term is not None and self.raft.term_at(idx) != term:
                            break                   # overwritten by a new leader: retry
                        return self.raft.results.get(idx)
                time.sleep(self.tick_s / 2)
        raise TimeoutError(f"raft: command {cmd.get('op')} not committed within {timeout}s (no quorum?)")

    # -- Cluster interface ---------------------------------------------------
    def start(self) -> None:
        for fn, name in ((self._ticker, "ulpf-raft-tick"), (self._loop, "ulpf-raft-cluster")):
            t = threading.Thread(target=fn, name=name, daemon=True)
            t.start()
            self._threads.append(t)

    def _loop(self) -> None:
        while not self._stop.wait(self.heartbeat_s):
            self.tick()

    def beat(self, stopped: bool = False) -> None:
        self.submit({"op": "heartbeat", "node": self.node, "info": {"epoch": self.epoch, "stopped": stopped,
                                                                    "running_inputs": list(self.running_inputs)}},
                    timeout=max(1.0, self.heartbeat_s))

    def alive_nodes(self) -> list[str]:
        with self._lock:
            nodes = dict(self.raft.machine.nodes)
            clock = self.raft.machine.clock
        live = [n for n, d in nodes.items() if not d.get("stopped") and clock - d.get("last", 0) <= self.failover_s]
        if self.node not in live:
            live.append(self.node)
        return sorted(live)

    def owns(self, key: str) -> bool:
        return not self.fenced and self._owner(key, self._alive) == self.node

    def tick(self) -> bool:
        changed = False
        try:
            self.beat()
            if self.fenced:
                self.fenced, changed = False, True
            for name in list(self._held):        # renew held leases
                res = self.submit({"op": "acquire", "name": name, "node": self.node, "epoch": self.epoch,
                                   "ttl": self.lease_ttl})
                if res and res.get("granted"):
                    self._renewed[name] = time.monotonic()
                else:
                    self._held.pop(name, None)
                    changed = True
            alive = self.alive_nodes()
            if alive != self._alive:
                self._alive, changed = alive, True
            if self.wanted:
                changed = True
        except TimeoutError as e:
            logger.warning(f"cluster (raft): {e}")
        # self-fence: a lease is ours only within TTL/2 of its last committed renewal
        now = time.monotonic()
        for name, at in list(self._renewed.items()):
            if now - at > self.lease_ttl / 2 and name in self._held:
                logger.error(f"cluster (raft): lease {name} not renewed in time; self-fencing")
                self._held.pop(name, None)
                changed = True
        if changed and self.on_change:
            self.on_change()
        return changed

    def acquire(self, name: str) -> int | None:
        if self.fenced:
            return None
        try:
            res = self.submit({"op": "acquire", "name": name, "node": self.node, "epoch": self.epoch,
                               "ttl": self.lease_ttl})
        except TimeoutError:
            return None
        if not res or not res.get("granted"):
            return None
        self._held[name] = int(res["token"])
        self._renewed[name] = time.monotonic()
        return self._held[name]

    def holds(self, name: str) -> bool:
        return name in self._held and time.monotonic() - self._renewed.get(name, 0) <= self.lease_ttl / 2

    def release(self, name: str) -> None:
        token = self._held.pop(name, None)
        self._renewed.pop(name, None)
        if token is not None:
            try:
                self.submit({"op": "release", "name": name, "node": self.node, "token": token})
            except TimeoutError:
                pass

    @property
    def held(self) -> dict[str, int]:
        return dict(self._held)

    def token_for_key(self, key: str) -> int | None:
        from ulpf.runtime.cluster import input_of_key
        name = input_of_key(key)
        return self._held.get(name) if name is not None else None

    def save_checkpoint(self, key: str, entry: dict, token: int | None = None) -> None:
        from ulpf.runtime.cluster import FencedError
        res = self.submit({"op": "checkpoint", "key": key, "entry": entry, "token": token, "node": self.node})
        if res and not res.get("stored"):
            raise FencedError(f"checkpoint {key}: lease token {token} is older than {res.get('fenced_by')}")

    def load_checkpoint(self, key: str) -> dict | None:
        with self._lock:
            d = self.raft.machine.checkpoints.get(key)
        return dict(d) if d else None

    def add_member(self, node_id: str) -> object:
        with self._lock:
            members = sorted(set(self.raft.members) | {node_id})
        return self.submit({"op": "config", "members": members}, timeout=10)

    def remove_member(self, node_id: str) -> object:
        with self._lock:
            members = sorted(set(self.raft.members) - {node_id})
        return self.submit({"op": "config", "members": members}, timeout=10)

    def status(self) -> dict:
        with self._lock:
            r = self.raft
            return {"node": self.node, "role": r.role, "term": r.term, "leader": r.leader, "commit": r.commit,
                    "applied": r.applied, "members": r.members, "leases": dict(r.machine.leases),
                    "held": dict(self._held), "transport_dropped": getattr(self.transport, "dropped", 0)}

    def stop(self) -> None:
        for name in list(self._held):
            self.release(name)
        try:
            self.beat(stopped=True)
        except TimeoutError:
            pass
        self._stop.set()
        self.transport.close()
        for t in self._threads:
            t.join(2)
        try:
            self.raft.storage.close()
        except AttributeError:
            pass
