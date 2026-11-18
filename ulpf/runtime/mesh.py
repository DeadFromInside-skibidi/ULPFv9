"""
Cluster-wide ingest mesh: weighted rendezvous hashing for stateful protocol affinity.

Stateful flows must keep landing on the same collector: NetFlow v9/IPFIX
templates (per exporter), TCP syslog sessions (per source ip:port), APG canary
parsers (per learned format). ``Mesh.route(key)`` picks the node with the
highest weighted rendezvous score (Schindelhauer & Schomaker), so

* every forwarder and node computes the same owner from the same membership,
  with no coordination on the data path;
* a node with weight 2 receives twice the keys of a node with weight 1;
* when a node fails or joins, only the keys it owned (or now owns) move:
  ``rebalance_plan`` lists exactly those moves.

Membership and weights come from the cluster (Raft ``nodes`` / ``alive_nodes``)
and are pushed to forwarders through the fleet control plane.
"""
from __future__ import annotations

import hashlib
import math


def _u(node: str, key: str) -> float:
    h = int.from_bytes(hashlib.blake2b(f"{node}\0{key}".encode(), digest_size=8).digest(), "big")
    return (h + 1) / (2**64 + 1)          # uniform in (0, 1)


def affinity_key(protocol: str, **kw) -> str:
    """Canonical affinity keys: netflow(exporter), syslog_tcp(src, port), apg(parser), default(source)."""
    if protocol in ("netflow", "ipfix", "sflow"):
        return f"netflow|{kw['exporter']}"
    if protocol in ("syslog_tcp", "tls"):
        return f"tcp-syslog|{kw['src']}:{kw.get('port', '')}"
    if protocol == "apg":
        return f"apg|{kw['parser']}"
    return f"{protocol}|{kw.get('source', '')}"


class Mesh:
    def __init__(self, nodes: dict[str, float] | list[str]):
        self.nodes = dict(nodes) if isinstance(nodes, dict) else {n: 1.0 for n in nodes}
        for n, w in self.nodes.items():
            if not w > 0:
                raise ValueError(f"node {n}: weight must be positive")

    def score(self, node: str, key: str) -> float:
        return -self.nodes[node] / math.log(_u(node, key))

    def route(self, key: str) -> str | None:
        if not self.nodes:
            return None
        return max(self.nodes, key=lambda n: (self.score(n, key), n))

    def ranked(self, key: str, n: int = 2) -> list[str]:
        """Owner first, then failover candidates (replicas) in order."""
        return sorted(self.nodes, key=lambda x: (self.score(x, key), x), reverse=True)[:n]

    def rebalance_plan(self, new_nodes: dict[str, float] | list[str], keys) -> dict[str, tuple[str, str]]:
        new = Mesh(new_nodes)
        plan = {}
        for k in keys:
            a, b = self.route(k), new.route(k)
            if a != b:
                plan[k] = (a, b)
        return plan

    def partition_map(self, partitions: int = 1024) -> dict[int, str]:
        """Owner of each virtual partition (``hash(key) % partitions``) for bulk hand-over."""
        return {p: self.route(f"partition|{p}") for p in range(partitions)}

    def load(self, keys) -> dict[str, int]:
        out = {n: 0 for n in self.nodes}
        for k in keys:
            out[self.route(k)] += 1
        return out
