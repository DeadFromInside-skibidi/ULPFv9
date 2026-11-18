# Multi-node deployment

A ULPF cluster is a set of independent ingest nodes. Each node runs `ulpf run` with its own journal, buffers and store. The nodes share one directory, which they use for coordination only: heartbeats and input checkpoints. No event data passes through the shared directory, so it does not limit throughput.

```
          senders / load balancer (syslog, HTTP, OTLP, NetFlow, SNMP)
            │                │                 │
      ┌─────▼─────┐    ┌─────▼─────┐     ┌─────▼─────┐
      │ ingest-1  │    │ ingest-2  │     │ ingest-3  │   each: journal → workers → outputs
      └─────┬─────┘    └─────┬─────┘     └─────┬─────┘
            └────── shared dir (NFS/SMB): nodes/*.json heartbeats, checkpoints/*.json ──────┘
```

## Configuration

Every node uses the same pipeline file except for `node.id`:

```yaml
node: {id: ingest-1}
cluster:
  enabled: true
  shared_dir: /mnt/ulpf-shared       # same mount on every node
  heartbeat_seconds: 2
  failover_seconds: 10               # a node is down after this long without a heartbeat
  nodes:
    - {id: ingest-1, address: "https://ingest-1.local:8000"}
    - {id: ingest-2, address: "https://ingest-2.local:8000"}
    - {id: ingest-3, address: "https://ingest-3.local:8000"}
```

## Which node runs an input

| `placement` | Behaviour | Default for |
|---|---|---|
| `all` | Runs on every node; senders or a load balancer choose the node | listeners: syslog, HTTP, OTLP, NetFlow, SNMP, and local sources such as journald and Windows event logs |
| `one` | Runs on exactly one live node, chosen by rendezvous hashing of the input name over the live node IDs | cloud pulls: CloudTrail, Pub/Sub, Okta, Entra ID, Event Hubs. Also set it for a `file` input on shared storage |

Rendezvous hashing moves only the inputs of a node that disappears. Inputs on the surviving nodes stay where they are (`tests/test_operations.py` checks this).

**Failover.** When a node stops heartbeating, or shuts down cleanly (it marks itself stopped at once), each input it owned starts on the node with the next highest hash score. That node resumes from the checkpoint the old owner mirrored to `checkpoints/`. A graceful hand-over loses and duplicates nothing; the two-node test checks this with a shared file. After a crash, records that the failed node pulled but had not yet checkpointed are pulled again: delivery is at least once, bounded by one checkpoint interval. For idempotent outputs (DuckDB, Elasticsearch `_id`), records the failed node had already delivered are not duplicated by its own replay when it comes back.

## Operating

- `ulpf cluster status --config pipeline.yaml` lists nodes, heartbeat age, liveness, the inputs each node runs, and the owner of every `placement: one` input.
- `GET /api/v1/cluster/status` returns the same data (read role).
- `GET /api/v1/cluster/events?limit=100&q=…` queries every live node's store and merges the results, newest event time first. Nodes that do not answer are listed in `node_errors`, and the query still returns the rest.
- `ulpf evidence verify` runs per node: each node seals its own journal.

## Sizing

Capacity is per node and adds up across nodes, because nodes share nothing on the data path. Measured on one 4-core laptop (Intel i5-8279U), with mixed TCP traffic into the local store, evidence seals and all analytics on (`benchmarks/results/live/runtime_tcp_*.json`):

| Workers per node | Persisted events/s | Loss |
|---|---|---|
| 3 | 17,034 | 0 |
| 6 | 26,952 | 0 |

At 6 workers, one such node handles about 2.3 billion events per day at full load. Plan nodes at about 60% of the measured rate to leave headroom for bursts and for the drain after a sink outage. `python -m benchmarks.multinode --nodes 2` measures an aggregate. On this single 4-core laptop, 2 nodes × 3 workers reached 20,934 events/s against 16,927 for one node; on one host that ratio is bounded by its cores. The store's ingest rate falls as the table grows, so measure sustained throughput with `benchmarks/soak.py` (docs/STATUS.md). A per-node figure for server hardware should be measured on that hardware with `python -m benchmarks.live.harness --target runtime --workers N`.

## Shared directory requirements

- It must support atomic rename (`os.replace`). NFSv4, SMB 3 and local volumes in a single-host test all do.
- Its clock skew must be small relative to `failover_seconds`. Heartbeats carry wall-clock times; keep NTP running on all nodes.
- Grant read and write access to the ULPF service account only. Checkpoints reveal source positions, and heartbeats reveal node addresses.
