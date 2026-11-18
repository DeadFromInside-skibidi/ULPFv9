"""v10 cluster: embedded Raft (Jepsen-style deterministic simulation), TCP transport, rendezvous mesh, fleet."""
from __future__ import annotations

import os
import random
import shutil
import tempfile
import time
import unittest

from ulpf.runtime.raft import LEADER, NotLeader, RaftNode


class SimNet:
    """Deterministic network: per-message random delay, loss, duplication and partitions."""

    def __init__(self, ids, seed, loss=0.05, dup=0.02, max_delay=4):
        self.rng = random.Random(seed)
        self.ids = list(ids)
        self.loss, self.dup, self.max_delay = loss, dup, max_delay
        self.queue = []                 # (deliver_at, seq, msg)
        self.now = 0
        self.seq = 0
        self.groups = None              # list of sets: messages only flow inside a group

    def connected(self, a, b):
        return self.groups is None or any(a in g and b in g for g in self.groups)

    def send(self, to, msg):
        if self.rng.random() < self.loss:
            return
        for _ in range(2 if self.rng.random() < self.dup else 1):
            self.seq += 1
            self.queue.append((self.now + self.rng.randint(1, self.max_delay), self.seq, msg))

    def deliver(self, nodes):
        due = sorted(m for m in self.queue if m[0] <= self.now)
        self.queue = [m for m in self.queue if m[0] > self.now]
        for _, _, msg in due:
            if self.connected(msg["from"], msg["to"]) and msg["to"] in nodes:
                nodes[msg["to"]].step(msg)


def make_cluster(n=5, seed=1, **net):
    ids = [f"n{i}" for i in range(n)]
    sim = SimNet(ids, seed, **net)
    nodes = {i: RaftNode(i, ids, send=sim.send, rng=random.Random(f"{seed}-{i}"), snapshot_every=200)
             for i in ids}
    return sim, nodes


def run(sim, nodes, ticks, check=None):
    for _ in range(ticks):
        sim.now += 1
        for nd in nodes.values():
            nd.tick()
        sim.deliver(nodes)
        if check:
            check()


def leader_of(nodes, sim=None):
    leaders = [n for n in nodes.values() if n.role == LEADER]
    return max(leaders, key=lambda n: n.term) if leaders else None


class RaftSafety(unittest.TestCase):
    def test_elects_single_leader_and_replicates(self):
        sim, nodes = make_cluster(5, seed=7, loss=0.0, dup=0.0)
        run(sim, nodes, 200)
        ld = leader_of(nodes)
        self.assertIsNotNone(ld)
        idx = ld.propose({"op": "acquire", "name": "in1", "node": "n3", "epoch": "e", "ttl": 10, "now": 100.0})
        run(sim, nodes, 50)
        for n in nodes.values():
            self.assertGreaterEqual(n.applied, idx)
            self.assertEqual(n.machine.leases["in1"]["holder"], "n3")
            self.assertEqual(n.machine.leases["in1"]["token"], idx)       # fencing token = log index

    def test_jepsen_partitions_preserve_invariants(self):
        """Random partitions, loss, duplication, reordering; Election Safety, Log Matching, State Machine
        Safety, lease mutual exclusion and monotonic fencing tokens must hold throughout."""
        for seed in (11, 23, 42):
            with self.subTest(seed=seed):
                self._chaos(seed)

    def _chaos(self, seed):
        sim, nodes = make_cluster(5, seed=seed, loss=0.08, dup=0.03, max_delay=5)
        rng = random.Random(seed)
        leaders_by_term: dict[int, str] = {}
        applied_log: dict[int, tuple] = {}         # index -> (term, cmd) first applied anywhere
        grants: list[tuple[float, str, int]] = []
        clock = [1000.0]

        def check():
            for n in nodes.values():
                if n.role == LEADER:
                    prev = leaders_by_term.setdefault(n.term, n.id)
                    self.assertEqual(prev, n.id, f"two leaders in term {n.term}")
                for i in range(n.snap_index + 1, n.applied + 1):
                    e = n.log[i - n.snap_index - 1]
                    key = (e["term"], repr(sorted(e["cmd"].items())))
                    seen = applied_log.setdefault(i, key)
                    self.assertEqual(seen, key, f"entry {i} differs between nodes (state machine safety)")

        for step in range(60):
            r = rng.random()
            if r < 0.3:
                ids = list(nodes)
                rng.shuffle(ids)
                cut = rng.randint(1, 4)
                sim.groups = [set(ids[:cut]), set(ids[cut:])]
            elif r < 0.5:
                sim.groups = None
            ld = leader_of(nodes)
            if ld is not None:
                clock[0] += rng.uniform(0.5, 3.0)
                try:
                    ld.propose({"op": "acquire", "name": "L", "node": rng.choice(list(nodes)),
                                "epoch": "e", "ttl": 2.0, "now": clock[0]})
                except NotLeader:
                    pass
            run(sim, nodes, 25, check)
        sim.groups = None
        run(sim, nodes, 400, check)
        # every node converges on the same committed state
        ld = leader_of(nodes)
        self.assertIsNotNone(ld, "no leader after the partitions healed")
        ld.propose({"op": "noop", "now": clock[0]})
        run(sim, nodes, 200, check)
        states = {repr(sorted(n.machine.leases.items())) for n in nodes.values()}
        self.assertEqual(len(states), 1, "replicas diverged")
        # lease history on the leader's applied log: grants never overlap, tokens strictly increase
        n = ld
        last_token, last_exp, last_holder = 0, -1.0, None
        m = __import__("ulpf.runtime.raft", fromlist=["LeaseMachine"]).LeaseMachine()
        for i in range(n.snap_index + 1, n.applied + 1):
            cmd = n.log[i - n.snap_index - 1]["cmd"]
            res = m.apply(i, cmd)
            if cmd.get("op") == "acquire" and res.get("granted") and not res.get("renewed"):
                self.assertGreater(res["token"], last_token)
                if last_holder is not None and last_holder != cmd["node"]:
                    self.assertGreaterEqual(m.clock, last_exp, "lease granted while another holder's was valid")
                last_token, last_holder = res["token"], cmd["node"]
            if cmd.get("op") == "acquire" and res.get("granted"):
                last_exp = m.leases["L"]["expires"]

    def test_minority_partition_cannot_commit_or_keep_leader(self):
        sim, nodes = make_cluster(5, seed=5, loss=0.0, dup=0.0)
        run(sim, nodes, 200)
        ld = leader_of(nodes)
        others = [i for i in nodes if i != ld.id]
        sim.groups = [{ld.id, others[0]}, set(others[1:])]
        idx = ld.propose({"op": "kv", "key": "x", "value": 1, "now": 1.0})
        run(sim, nodes, 120)
        self.assertLess(nodes[others[0]].commit, idx) if nodes[others[0]].last_index >= idx else None
        self.assertNotEqual(nodes[ld.id].role, LEADER, "check-quorum: minority leader must step down")
        majority_leader = leader_of({i: nodes[i] for i in others[1:]})
        self.assertIsNotNone(majority_leader)
        sim.groups = None
        run(sim, nodes, 200)
        self.assertNotIn("x", {k for n in nodes.values() for k in n.machine.kv})   # uncommitted entry discarded

    def test_membership_change_and_snapshot_catch_up(self):
        sim, nodes = make_cluster(3, seed=9, loss=0.0, dup=0.0)
        run(sim, nodes, 150)
        ld = leader_of(nodes)
        for i in range(450):
            ld.propose({"op": "kv", "key": f"k{i}", "value": i, "now": float(i)})
            if i % 50 == 0:
                run(sim, nodes, 5)
        run(sim, nodes, 100)
        self.assertGreater(ld.snap_index, 0)          # compacted
        new = RaftNode("n9", ["n9"], send=sim.send, rng=random.Random(3), snapshot_every=200)
        new.members = list(ld.members) + ["n9"]
        nodes["n9"] = new
        ld.propose({"op": "config", "members": sorted(ld.members + ["n9"])})
        run(sim, nodes, 300)
        self.assertEqual(new.machine.kv.get("k449"), 449)    # caught up through a snapshot
        self.assertIn("n9", leader_of(nodes).members)


class RaftOverTcp(unittest.TestCase):
    def test_three_node_cluster_leases_and_fencing(self):
        from ulpf.runtime.cluster import FencedError
        from ulpf.runtime.raft import RaftCluster
        d = tempfile.mkdtemp()
        import socket
        ports = []
        for _ in range(3):
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            ports.append(s.getsockname()[1])
            s.close()
        peers = {f"n{i}": f"127.0.0.1:{p}" for i, p in enumerate(ports)}
        nodes = []
        try:
            for nid in peers:
                cfg = {"cluster": {"heartbeat_seconds": 0.3, "failover_seconds": 3,
                                   "raft": {"peers": peers, "data_dir": d, "tick_ms": 20, "lease_ttl_seconds": 3}}}
                c = RaftCluster(cfg, nid)
                c.start()
                nodes.append(c)
            deadline = time.time() + 15
            while time.time() < deadline and not any(c.raft.role == LEADER for c in nodes):
                time.sleep(0.05)
            t1 = nodes[1].acquire("syslog-in")
            self.assertIsNotNone(t1)
            self.assertIsNone(nodes[2].acquire("syslog-in"))          # held by a live node
            nodes[1].save_checkpoint("syslog-in|pos", {"value": 10}, token=t1)
            nodes[1].release("syslog-in")
            t2 = nodes[2].acquire("syslog-in")
            self.assertGreater(t2, t1)                                 # fencing token increases
            nodes[2].save_checkpoint("syslog-in|pos", {"value": 20}, token=t2)
            with self.assertRaises(FencedError):                       # deposed holder's late write
                nodes[1].save_checkpoint("syslog-in|pos", {"value": 11}, token=t1)
            time.sleep(0.3)
            self.assertEqual(nodes[0].load_checkpoint("syslog-in|pos")["value"], 20)
        finally:
            for c in nodes:
                c._stop.set()
                c.transport.close()
                c.raft.storage.close()
            shutil.rmtree(d, ignore_errors=True)


class Mesh(unittest.TestCase):
    def test_rendezvous_minimal_movement_and_affinity(self):
        from ulpf.runtime.mesh import Mesh as M
        nodes = {"a": 1.0, "b": 1.0, "c": 1.0, "d": 2.0}
        m = M(nodes)
        keys = [f"netflow|10.0.{i // 256}.{i % 256}" for i in range(4000)]
        before = {k: m.route(k) for k in keys}
        share = sum(1 for v in before.values() if v == "d") / len(keys)
        self.assertAlmostEqual(share, 0.4, delta=0.05)                # weight 2 of 5
        plan = m.rebalance_plan({"a": 1.0, "b": 1.0, "d": 2.0}, keys)  # c failed
        moved = {k for k, (src, dst) in plan.items()}
        self.assertEqual(moved, {k for k, v in before.items() if v == "c"})   # only c's keys move
        self.assertEqual(m.route("tcp-syslog|10.1.1.1:5140"), m.route("tcp-syslog|10.1.1.1:5140"))


class Fleet(unittest.TestCase):
    def test_enroll_heartbeat_config_and_throttle(self):
        from ulpf.fleet.control import FleetControl, verify_bundle
        d = tempfile.mkdtemp()
        try:
            fc = FleetControl(d)
            tok = fc.create_enrollment_token("edge", ttl=60)
            agent = fc.enroll(tok, "fwd-001", {"os": "linux", "version": "10.0.0"})
            self.assertIn("BEGIN CERTIFICATE", agent["certificate"])
            with self.assertRaises(PermissionError):
                fc.enroll(tok, "fwd-002", {})                         # single-use token
            v = fc.publish_config("edge", {"inputs": [{"type": "file", "path": "/var/log/*.log"}]}, "admin")
            hb = fc.heartbeat("fwd-001", agent["agent_token"], {"eps": 500, "buffer_fill": 0.1, "config_version": 0})
            self.assertEqual(hb["config_version"], v["version"])
            bundle = fc.config_bundle("fwd-001", agent["agent_token"])
            self.assertTrue(verify_bundle(bundle, fc.public_key()))
            bundle["config"]["inputs"][0]["path"] = "/etc/shadow"
            self.assertFalse(verify_bundle(bundle, fc.public_key()))  # tampered config refused by agents
            fc.set_cluster_health(buffer_fill=0.95)
            hb = fc.heartbeat("fwd-001", agent["agent_token"], {"eps": 500, "buffer_fill": 0.1})
            self.assertLess(hb["throttle_eps"], 500)                  # backpressure when the SIEM is saturated
            with self.assertRaises(PermissionError):
                fc.heartbeat("fwd-001", "wrong-token", {})
            self.assertEqual(fc.summary()["agents"], 1)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
