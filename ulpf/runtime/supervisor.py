"""
The ULPF runtime: inputs → journal → workers → sink buffers → senders.

    rt = Runtime(load_pipeline_config("pipeline.yaml"))
    rt.start()          # replays anything uncommitted, then opens inputs
    ...
    rt.reload()         # apply an edited config without losing data
    rt.stop()           # inputs stop, workers drain, sinks drain, state persisted

Invariants
* A record is journaled (durable per ``journal.sync``) before anything else
  happens to it.
* The commit watermark is persisted only after the journal is flushed, and
  senders deliver only segments at or below the persisted watermark, so a
  delivered event is always recoverable from the journal and never resent.
* Inputs that raise are restarted with exponential backoff.

The *stage* (outputs, buffers, router, workers, senders) can be rebuilt on
reload; the journal, evidence sealer, checkpoints and audit log persist.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time

from ulpf.config.pipeline import PipelineConfig, describe

logger = logging.getLogger("ulpf.runtime")

_STAGE_KEYS = ("outputs", "routes", "default_output", "analytics", "learning", "workers", "dlq")


def learned_dir(data_dir: str) -> str:
    """Learned (APG) parsers of a node: ``<data dir>/learned_parsers``, shared by its workers."""
    return os.path.join(data_dir, "learned_parsers")


class Checkpoints:
    """Input positions (file offsets, cursors), persisted only once durable in the journal."""

    def __init__(self, path: str, cluster=None):
        self.path = path
        self.cluster = cluster        # mirror to the shared directory (failover resumes there)
        self._lock = threading.Lock()
        self._durable: dict[str, dict] = {}
        self._pending: dict[str, dict] = {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                self._durable = json.load(f)
        except (OSError, ValueError):
            self._durable = {}

    # A position taken over from another node: its journal sequence is not ours,
    # so nothing in the local journal counts as "journaled after" it.
    FOREIGN_SEQ = 2 ** 62

    def _with_shared(self, key: str, local: dict | None) -> dict | None:
        if self.cluster is None:
            return local
        shared = self.cluster.load_checkpoint(key)
        if shared is None or shared.get("node") == self.cluster.node:
            return local
        # another node owned the input more recently: continue from its position. Positions
        # written under leases are ordered by fencing token, not by (skewed) wall clocks.
        st, lt = shared.get("token"), (local or {}).get("token")
        newer = local is None or (st > lt if st is not None and lt is not None
                                  else shared.get("updated", 0) > local.get("updated", 0))
        if newer:
            return {"value": shared["value"], "seq": self.FOREIGN_SEQ, "updated": shared.get("updated", 0),
                    "token": st}
        return local

    def get(self, key: str) -> dict | None:
        with self._lock:
            local = self._pending.get(key)
            if local is not None:
                return local
            local = self._durable.get(key)
        return self._with_shared(key, local)

    def durable(self, key: str) -> dict | None:
        with self._lock:
            local = self._durable.get(key)
        return self._with_shared(key, local)

    def set(self, key: str, value, seq: int) -> None:
        token = self.cluster.token_for_key(key) if self.cluster is not None else None
        with self._lock:
            self._pending[key] = {"value": value, "seq": seq, "updated": time.time(), "token": token}

    def flush(self, durable_seq: int) -> None:
        with self._lock:
            ready = {k: v for k, v in self._pending.items() if v["seq"] <= durable_seq}
            if not ready:
                return
            for k in ready:
                if self._pending.get(k) is ready[k]:
                    del self._pending[k]
            self._durable.update(ready)
            snapshot = dict(self._durable)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(snapshot, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        if self.cluster is not None:
            from ulpf.runtime.cluster import FencedError
            for k, entry in ready.items():
                try:
                    self.cluster.save_checkpoint(k, {"value": entry["value"]}, token=entry.get("token"))
                except FencedError as e:
                    logger.warning(f"cluster: checkpoint not mirrored, lease lost: {e}")
                except OSError as e:
                    logger.warning(f"cluster: could not mirror checkpoint {k}: {e}")


class Runtime:
    def __init__(self, cfg: PipelineConfig, api: bool | None = None):
        from ulpf.platform.paths import get_data_dir
        self.cfg = cfg
        self.data_dir = cfg.get("node.data_dir") or str(get_data_dir())
        os.makedirs(self.data_dir, exist_ok=True)
        self.learned_dir = learned_dir(self.data_dir)
        self.want_api = cfg.get("api.enabled") if api is None else api
        self.stop_event = threading.Event()
        self._sink_stop = threading.Event()
        self._reload_lock = threading.RLock()
        self.inputs: dict[str, object] = {}
        self._input_threads: dict[str, threading.Thread] = {}
        self.runners: dict[str, object] = {}
        self.sinks: dict[str, object] = {}
        self.buffers: dict[str, object] = {}
        self.database = None
        self.started_at: float | None = None
        self.persisted_committed = 0
        self._rate_limiters: dict[str, object] = {}
        self._threads: list[threading.Thread] = []
        self.api_server = None
        self.soar = None             # v10: SOAR / case management (ulpf.soar)
        self.copilot = None          # v10: offline SecOps copilot (ulpf.copilot)
        self.memory_guard = None     # v10: hard memory ceiling (ulpf.runtime.limits_os)
        self.correlator = None
        self.tip = None
        self.sealer = None
        self.row_keys = None
        self._worker_cfg: dict | None = None
        self._apg_engine = None
        self._apg_lock = threading.Lock()
        self.journal = None
        self.dispatcher = None
        self.live = None                # live-tail bus (ulpf.query.live)
        self._query_engine = None
        self.audit = None
        self.report: dict = {}
        self.reloads = 0
        self.egress = None
        self.worker_egress: dict[int, dict] = {}
        self.cluster = None
        self.limits_state: dict = {}
        self._stopping = False

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def _workers(self, cfg: PipelineConfig) -> int:
        w = cfg.get("workers", "auto")
        if isinstance(w, int) and w > 0:
            return w
        return max(1, (os.cpu_count() or 2) - 1)

    def _open_journal(self):
        from ulpf.runtime.journal import Journal, load_or_create_key
        j = self.cfg["journal"]
        key = None
        if j["encrypt"]:
            key = load_or_create_key(j.get("key_file") or os.path.join(self.data_dir, "journal.key"))
        return Journal(os.path.join(self.data_dir, "journal"), segment_bytes=j["segment_mb"] * 2**20,
                       sync=j["sync"], sync_interval_ms=j["sync_interval_ms"], key=key,
                       retention_days=j["retention_days"])

    def start(self) -> "Runtime":
        from ulpf.runtime.audit import AuditLog
        from ulpf.runtime.dispatch import CommitTracker
        from ulpf.runtime.dlq import DeadLetterQueue
        from ulpf.runtime.ids import node_id

        cfg = self.cfg
        self.node = node_id(self.data_dir, cfg.get("node.id"))
        mem = (cfg.data.get("limits") or {}).get("duckdb_memory_mb")
        if mem:
            os.environ["ULPF_DUCKDB_MEMORY"] = f"{int(mem)}MB"   # read when the store opens
        if cfg.get("audit.enabled", True):
            self.audit = AuditLog(os.path.join(self.data_dir, "audit", "audit.log"))
        self.report = describe(cfg)
        if self.audit:
            self.audit.record("runtime.start", {"mode": cfg.mode, "node": self.node, **self.report})
        for w in self.report["waived_rules"]:
            logger.warning(f"mode rule waived by config: {w}")

        from ulpf.runtime import egress
        air = cfg["airgap"]
        self.egress = egress.install(air["allow"], bool(air["enforce"]),
                                     dns_refresh_s=air["dns_refresh_seconds"], dns_grace_s=air["dns_grace_seconds"])

        self.journal = self._open_journal()
        self.tracker = CommitTracker(self.journal.committed_seq)
        self.persisted_committed = self.journal.committed_seq
        self.journal.add_listener(lambda first, raws, *_: self.tracker.register(first, len(raws)))
        if cfg["cluster"]["enabled"]:
            from ulpf.runtime.cluster import Cluster
            if (cfg.data["cluster"].get("backend") or "shared_dir") == "raft":
                from ulpf.runtime.raft import RaftCluster
                self.cluster = RaftCluster(cfg.data, self.node, on_change=self._rebalance)
            else:
                self.cluster = Cluster(cfg.data, self.node, on_change=self._rebalance)
            self.cluster.start()
        self.checkpoints = Checkpoints(os.path.join(self.data_dir, "checkpoints.json"), self.cluster)
        dlq_cfg = cfg["dlq"]
        self.dlq = DeadLetterQueue(os.path.join(self.data_dir, "dlq"), int(dlq_cfg["max_mb"] * 2**20),
                                   dlq_cfg["retention_days"])

        self._build_correlator(cfg)
        if cfg["evidence"]["enabled"]:
            from ulpf.runtime.evidence import Sealer
            from ulpf.runtime.keys import RowKeyRatchet, passphrase_from_env
            ev = cfg["evidence"]
            ev_dir = os.path.join(self.data_dir, "evidence")
            if ev["row_mac"]:
                # Forward-secure row MAC keys: ratcheted as the commit watermark moves
                self.row_keys = RowKeyRatchet(ev_dir, ev.get("row_key_epoch_records") or ev["seal_every_events"],
                                              escrow_pub=ev.get("row_key_escrow"))
                self.row_keys.advance_to_seq(self.journal.committed_seq + 1)
            from ulpf.runtime.keys import configure_provider
            configure_provider("pkcs11", ev.get("pkcs11"))
            configure_provider("tpm", ev.get("tpm"))
            self.sealer = Sealer(os.path.join(ev_dir, "seals"), self.node,
                                 ev["seal_every_events"], ev["seal_every_seconds"],
                                 emit=self.emit_derived, row_mac=bool(ev["row_mac"]), row_keys=self.row_keys,
                                 passphrase=passphrase_from_env(ev.get("key_passphrase_env")),
                                 key_provider=ev.get("key_provider") or "file")
            recovered = self.sealer.recover(self.journal)
            if recovered:
                logger.info(f"evidence: {recovered} journaled record(s) awaiting a seal from before restart")
            self.journal.add_listener(self.sealer.on_append)

        self._start_intel(cfg)
        self._build_stage(cfg)
        self._spawn(self._commit_loop, "ulpf-commit")
        self._spawn(self._housekeeping_loop, "ulpf-housekeeping")
        self._replay()

        self._start_inputs(cfg)
        self._start_v10_services()
        if self.want_api:
            self._start_api()
        self.started_at = time.time()
        logger.info(f"ULPF runtime started: node={self.node} mode={cfg.mode} "
                    f"workers={self.dispatcher.n} inputs={list(self.inputs)} outputs={list(self.sinks)}")
        return self

    def _build_correlator(self, cfg: PipelineConfig) -> None:
        an = cfg["analytics"]
        if an["correlation"]["enabled"]:
            from ulpf.runtime.analytics import StreamCorrelator
            c = an["correlation"]
            from ulpf.intelligence.sigma import engine_from_config
            yl, rk = an.get("yaral") or {}, an.get("risk") or {}
            yaral = risk = None
            if yl.get("enabled", True) and yl.get("rules"):
                from ulpf.intelligence.yaral import YaraLCorrelator, load_rules
                rules, errors = load_rules(yl["rules"])
                for e in errors:
                    logger.warning(f"yara-l: {e}")
                yaral = YaraLCorrelator(rules)
            if rk.get("enabled", True):
                from ulpf.intelligence.risk import RiskEngine
                risk = RiskEngine(rk.get("half_life_days", 7), rk.get("thresholds"), rk.get("dynamic", True),
                                  rk.get("dynamic_sigma", 3), tactic_threshold=rk.get("tactic_threshold", 3),
                                  suppress_hours=rk.get("suppress_hours", 24), level_scores=rk.get("level_scores"))
            ub = an.get("ueba") or {}
            ueba = None
            if ub.get("enabled", True):
                from ulpf.ueba.engine import UebaEngine
                ueba = UebaEngine(self.data_dir, ub)
            self.correlator = StreamCorrelator(self.node, c["window_seconds"], emit=self.emit_derived,
                                               max_groups=c["max_groups"], max_group_events=c["max_group_events"],
                                               sigma=engine_from_config(cfg.data), yaral=yaral, risk=risk,
                                               risk_path=os.path.join(self.data_dir, "risk", "state.json"), ueba=ueba)
        else:
            self.correlator = None

    def _build_stage(self, cfg: PipelineConfig) -> None:
        """Outputs, buffers, router, worker processes and senders for ``cfg``."""
        from ulpf.runtime.buffer import DiskBuffer
        from ulpf.runtime.dispatch import Dispatcher
        from ulpf.runtime.router import Router
        from ulpf.runtime.sinks import build_sink
        from ulpf.runtime.sinks.runner import SinkRunner

        buffer_root = os.path.join(self.data_dir, "buffers")
        sinks, buffers, runners = {}, {}, {}
        for o in cfg.outputs():
            ctx = {"mode": cfg.mode, "data_dir": self.data_dir}
            if o["type"] == "duckdb" and self.database is not None and \
                    (o.get("path") or None) == getattr(self, "_store_path", None):
                ctx["database"] = self.database          # keep the open store across reloads
            sink = build_sink(o, ctx)
            sinks[o["name"]] = sink
            buf = DiskBuffer(os.path.join(buffer_root, o["name"]), int(o["buffer"]["max_mb"] * 2**20),
                             o["buffer"]["when_full"], sink.ext)
            buf.clean_tmp()
            buffers[o["name"]] = buf
        self.router = Router(cfg["routes"], cfg.get("default_output"))
        self.sinks, self.buffers = sinks, buffers

        worker_cfg = dict(cfg.data)
        worker_cfg["_buffer_root"] = buffer_root
        worker_cfg["_data_dir"] = self.data_dir
        worker_cfg["_learned_dir"] = self.learned_dir
        # Stored rows are MAC'd with the ratchet's current epoch key, so verify can detect edits
        # to any column; workers never receive keys of epochs that are already committed
        worker_cfg["_row_ratchet"] = self.row_keys.snapshot() if self.row_keys is not None else None
        self._worker_cfg = worker_cfg
        self.dispatcher = Dispatcher(worker_cfg, self.node, self._workers(cfg), self.tracker,
                                     on_result=self._on_result)
        self.dispatcher.start()
        if self.live is None:
            from ulpf.query.live import LiveBus
            lc = (cfg.get("query") or {}).get("live") or {}
            self.live = LiveBus(lambda specs, lease: self.dispatcher.broadcast("live", (specs, lease)),
                                lc.get("max_tails", 32), lc.get("per_user", 4), lc.get("queue_rows", 10_000),
                                lc.get("idle_seconds", 120))

        self._sink_stop = threading.Event()
        for name, sink in sinks.items():
            o = next(x for x in cfg.outputs() if x["name"] == name)
            runners[name] = SinkRunner(sink, buffers[name], self.dlq, lambda: self.persisted_committed,
                                       o["retry"], self._sink_stop)
        # The first DuckDB output is "the store" the API, CLI queries and GUI read
        duck = [(s, o) for o in cfg.outputs() for s in [sinks[o["name"]]] if o["type"] == "duckdb"]
        if duck:
            duck[0][0].open()
            self.database = duck[0][0].db
            self._store_path = duck[0][1].get("path") or None
        self.runners = runners
        for r in runners.values():
            r.start()

    def _stop_stage(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        drained = self.dispatcher.drain(max(0.1, deadline - time.monotonic()))
        self.dispatcher.stop(max(1.0, deadline - time.monotonic()))
        self._commit()
        for r in self.runners.values():
            r.drain_deadline = time.monotonic() + max(1.0, deadline - time.monotonic())
        self._sink_stop.set()
        for r in self.runners.values():
            r.join(max(1.0, deadline - time.monotonic()) + 1)
        return drained

    def _spawn(self, fn, name: str) -> None:
        t = threading.Thread(target=fn, name=name, daemon=True)
        t.start()
        self._threads.append(t)

    # ------------------------------------------------------------------
    # Ingest path (called by inputs)
    # ------------------------------------------------------------------

    def rate_limiter(self, input_name: str):
        rl = self._rate_limiters.get(input_name)
        if rl is None:
            from ulpf.runtime.inputs.base import RateLimiter
            opts = next((i for i in self.cfg.inputs() if i["name"] == input_name), {})
            rl = self._rate_limiters[input_name] = RateLimiter(opts.get("rate_limit_eps", 0))
        return rl

    def ingest(self, input_name: str, source: str, raws: list[bytes], recv_ts: float | None = None) -> int:
        """Journal raw records and dispatch them. Returns the first sequence number."""
        if not raws:
            return self.journal.next_seq
        ts = recv_ts or time.time()
        with self._reload_lock:     # a reload swaps the dispatcher; never journal into the gap
            first, digests = self.journal.append(source, input_name, raws, ts)
            inp = self.inputs.get(input_name)
            affinity = inp.opts.get("affinity", "none") if inp is not None else "source"
            self.dispatcher.submit(input_name, source, affinity, first, raws, digests, ts)
        return first

    def saturated(self) -> bool:
        """True when the worker queues are nearly full (HTTP inputs answer 429)."""
        d = self.dispatcher
        return d is not None and d.stats()["in_flight_batches"] >= int(d.n * d.queue_batches * 0.9)

    def journaled_after(self, input_name: str, source: str, seq: int) -> list:
        """Records of (input, source) journaled after ``seq`` (to reconcile checkpoints)."""
        out = []
        for block in self.journal.iter_from(seq + 1):
            out.extend(r for r in block if r.input == input_name and r.source == source)
        return out

    def _replay(self) -> None:
        start = self.journal.committed_seq + 1
        if start >= self.journal.next_seq:
            return
        n = 0
        for block in self.journal.iter_from(start):
            if not block:
                continue
            first = block[0].seq
            self.tracker.register(first, len(block))
            inp_opts = next((i for i in self.cfg.inputs() if i["name"] == block[0].input), {})
            self.dispatcher.submit(block[0].input, block[0].source, inp_opts.get("affinity", "source"),
                                   first, [r.raw for r in block], [r.sha256 for r in block], block[0].recv_ts)
            n += len(block)
        logger.warning(f"replayed {n} journaled records that were not committed before the last stop")
        if self.audit:
            self.audit.record("runtime.replay", {"records": n, "from_seq": start})

    # ------------------------------------------------------------------
    # Results and derived events
    # ------------------------------------------------------------------

    def _on_result(self, msg: dict) -> None:
        if msg.get("live") and self.live is not None:
            self.live.publish(msg["live"])
        if msg.get("yaral") and self.correlator is not None:
            self.correlator.submit_yaral(msg["yaral"])
        if msg["t"] == "done":
            if self.correlator is not None and msg.get("proj"):
                self.correlator.submit(msg["proj"])
            if msg.get("egress"):
                self.worker_egress[msg["worker"]] = msg["egress"]
            return
        # The pipeline failed for a whole batch: keep the raw records in the DLQ
        recs = []
        for seq in range(msg["first"], msg["last"] + 1):
            r = self.journal.read(seq)
            if r is not None:
                recs.append({"raw_hash": r.sha256_hex, "event_id": None,
                             "record": r.raw.decode("utf-8", "replace"), "journal_seq": seq})
        lines = (msg.get("error") or "pipeline error").strip().splitlines()
        self.dlq.write("pipeline", lines[-1] if lines else "pipeline error", recs)

    def emit_derived(self, events: list[dict]) -> None:
        """Route host-generated events (correlations, seals) into sink buffers."""
        for sink_name, batch in self.router.split(events).items():
            sink = self.sinks.get(sink_name)
            if sink is None:
                continue
            self.buffers[sink_name].write_derived(sink.encode(batch), len(batch))

    # ------------------------------------------------------------------
    # Background loops
    # ------------------------------------------------------------------

    def _commit_loop(self) -> None:
        while not self.stop_event.wait(0.1):
            try:
                self._commit()
            except Exception:
                logger.exception("commit failed")

    def _commit(self) -> None:
        j = self.journal
        durable = j.next_seq - 1
        j.flush()
        committed = min(self.tracker.committed, durable)
        if committed > j.committed_seq:
            j.set_committed(committed)
        self.persisted_committed = j.committed_seq
        if self.row_keys is not None and self.row_keys.advance_to_seq(j.committed_seq + 1)                 and self._worker_cfg is not None:
            # A worker respawned later starts from the new base, not from an erased key
            self._worker_cfg["_row_ratchet"] = self.row_keys.snapshot()
        self.checkpoints.flush(durable)

    def _housekeeping_loop(self) -> None:
        last_sweep = 0.0
        last_store_upkeep = time.time()
        last_limits = 0.0
        while not self.stop_event.wait(1.0):
            if self.correlator is not None:
                try:
                    self.correlator.step(time.time())
                except Exception:
                    logger.exception("correlation step failed")
            if self.sealer is not None:
                try:
                    self.sealer.tick()
                except Exception:
                    logger.exception("evidence seal failed")
            if time.time() - last_limits > 30:
                last_limits = time.time()
                try:
                    self._enforce_limits()
                except Exception:
                    logger.exception("limits check failed")
            if self.database is not None and time.time() - last_store_upkeep > 60:
                last_store_upkeep = time.time()
                try:
                    # partition rotation, whole-file retention, checkpoint of the active partition
                    self.database.maintain()
                except Exception:
                    logger.exception("event store maintenance failed")
            if time.time() - last_sweep > 3600:
                last_sweep = time.time()
                try:
                    removed = self.journal.sweep()
                    if removed:
                        logger.info(f"journal retention removed {removed} segment(s)")
                    self.dlq.enforce_limits()
                except Exception:
                    logger.exception("retention sweep failed")
            self._supervise_inputs()
            if self.cluster is not None:
                try:
                    self._rebalance()
                except Exception:
                    logger.exception("cluster rebalance failed")

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    def _start_input(self, opts: dict) -> None:
        from ulpf.runtime.inputs import build_input
        inp = build_input(opts, self)
        self.inputs[opts["name"]] = inp
        stop = threading.Event()
        inp._stop = stop
        inp._backoff = 1.0
        inp._failed_at = None

        def run():
            try:
                inp.run(stop)
            except Exception as e:
                inp.stats.errors += 1
                inp.stats.last_error = f"{type(e).__name__}: {e}"
                logger.error(f"input {inp.name} failed: {inp.stats.last_error}")
                inp._failed_at = time.time()

        t = threading.Thread(target=run, name=f"ulpf-in-{opts['name']}", daemon=True)
        t.start()
        self._input_threads[opts["name"]] = t

    def _stop_input(self, name: str, timeout: float = 10.0) -> None:
        inp = self.inputs.pop(name, None)
        t = self._input_threads.pop(name, None)
        if inp is not None:
            inp._stop.set()
        if t is not None:
            t.join(timeout)
        self._rate_limiters.pop(name, None)

    def _wants(self, opts: dict) -> bool:
        """Should this node run the input? (cluster placement: preferred owner *and* lease holder)"""
        if self.cluster is None:
            return True
        from ulpf.runtime.cluster import placement
        if placement(opts) == "all":
            return True
        name = opts["name"]
        if not self.cluster.owns(name):
            self.cluster.wanted.discard(name)
            return False
        try:
            ok = name in self.cluster.held or self.cluster.acquire(name) is not None
        except OSError as e:
            logger.warning(f"cluster: lease {name}: {e}")
            ok = False
        if ok:
            self.cluster.wanted.discard(name)
        else:
            self.cluster.wanted.add(name)
        return ok

    def _start_inputs(self, cfg: PipelineConfig) -> None:
        for i in cfg.inputs():
            if self._wants(i):
                self._start_input(i)
        if self.cluster is not None:
            self.cluster.running_inputs = sorted(self.inputs)

    def _rebalance(self) -> None:
        """Start inputs this node now owns; stop those that moved to another node."""
        if self.cluster is None or self.stop_event.is_set() or self._stopping:
            return
        from ulpf.runtime.cluster import placement
        stopping = [i for i in self.cfg.inputs() if i["name"] in self.inputs and not self._wants(i)]
        to_stop = [i["name"] for i in stopping]
        for name in to_stop:
            logger.info(f"cluster: input {name} moved to another node")
            self._stop_input(name)
        if stopping:
            try:
                self._commit()                 # its last positions reach the shared checkpoints first
            except Exception:
                logger.exception("commit before lease release failed")
            for i in stopping:
                if placement(i) == "one":
                    try:
                        self.cluster.release(i["name"])
                    except OSError as e:
                        logger.warning(f"cluster: could not release lease {i['name']}: {e}")
        with self._reload_lock:
            for i in self.cfg.inputs():
                if i["name"] not in self.inputs and self._wants(i):
                    logger.info(f"cluster: taking over input {i['name']}")
                    self._start_input(i)
            self.cluster.running_inputs = sorted(self.inputs)
        if to_stop and self.audit:
            self.audit.record("cluster.rebalance", {"stopped": to_stop, "running": sorted(self.inputs)})

    def _supervise_inputs(self) -> None:
        if self.stop_event.is_set() or self._stopping:
            return
        with self._reload_lock:
            for name, t in list(self._input_threads.items()):
                if t.is_alive():
                    continue
                inp = self.inputs[name]
                failed_at = inp._failed_at
                if failed_at is None:
                    continue  # finished on its own (e.g. a one-shot read)
                if time.time() - failed_at < inp._backoff:
                    continue
                restarts = inp.stats.restarts + 1
                backoff = min(inp._backoff * 2, 60.0)
                logger.warning(f"restarting input {name} (attempt {restarts})")
                stats = inp.stats
                self._start_input(inp.opts)
                new = self.inputs[name]
                new.stats = stats
                new.stats.restarts = restarts
                new._backoff = backoff

    # ------------------------------------------------------------------
    # Reload
    # ------------------------------------------------------------------

    def reload(self, timeout: float = 60.0) -> dict:
        """Re-read the config file and apply it. An invalid config changes nothing."""
        from ulpf.config import ConfigError, load_pipeline_config
        if not self.cfg.path:
            return {"reloaded": False, "error": "the runtime was not started from a config file"}
        try:
            new = load_pipeline_config(self.cfg.path)
        except (ConfigError, OSError) as e:
            errors = [str(i) for i in getattr(e, "issues", [])] or [str(e)]
            if self.audit:
                self.audit.record("config.reload_rejected", {"errors": errors[:20]})
            return {"reloaded": False, "errors": errors}
        if self.cfg.get("node.data_dir") and not new.get("node.data_dir"):
            new.data["node"]["data_dir"] = self.cfg.get("node.data_dir")
        for key in ("mode", "journal", "evidence", "node", "api", "cluster"):
            if new.data.get(key) != self.cfg.data.get(key):
                return {"reloaded": False, "error": f"changing '{key}' needs a restart"}
        old = self.cfg
        stage_changed = [k for k in _STAGE_KEYS if new.data.get(k) != old.data.get(k)]
        old_in = {i["name"]: i for i in old.inputs()}
        new_in = {i["name"]: i for i in new.inputs()}
        changed_inputs = sorted(n for n in set(old_in) | set(new_in) if old_in.get(n) != new_in.get(n))
        # Stop inputs first, without the lock: an input may be inside ingest()
        # waiting for it, and its in-flight batch must land in the old stage.
        to_stop = list(self.inputs) if stage_changed else [n for n in changed_inputs if n in self.inputs]
        for name in to_stop:
            self._stop_input(name)
        with self._reload_lock:
            if stage_changed:
                self._stop_stage(timeout)
                self.cfg = new
                if "analytics" in stage_changed:
                    self._build_correlator(new)
                self._build_stage(new)
                self._start_inputs(new)
            else:
                self.cfg = new
                for name in changed_inputs:
                    if name in new_in and self._wants(new_in[name]):
                        self._start_input(new_in[name])
            self.report = describe(new)
            self.reloads += 1
        result = {"reloaded": True, "stage_rebuilt": bool(stage_changed), "changed": stage_changed,
                  "inputs_restarted": changed_inputs}
        if self.audit:
            self.audit.record("config.reload", result)
        logger.info(f"configuration reloaded: {result}")
        return result

    # ------------------------------------------------------------------
    # API
    # ------------------------------------------------------------------

    def _start_v10_services(self) -> None:
        d = self.cfg.data
        lim = d.get("limits") or {}
        if lim.get("hard_memory_mb"):
            from ulpf.runtime.limits_os import apply_memory_ceiling
            self.memory_guard = apply_memory_ceiling(int(lim["hard_memory_mb"]), lim.get("memory_high_mb"),
                                                     include_children=True)
            if self.audit:
                self.audit.record("limits.hard_memory", self.memory_guard)
        if (d.get("soar") or {}).get("enabled"):
            from ulpf.soar.service import SoarService
            self.soar = SoarService(self.data_dir, d["soar"])
            self.soar.attach_runtime(self)
        if (d.get("copilot") or {}).get("enabled"):
            from ulpf.copilot.service import Copilot
            self.copilot = Copilot(d["copilot"], runtime=self)

    def _start_api(self) -> None:
        from ulpf.runtime.api_server import ApiServer
        self.api_server = ApiServer(self)
        self.api_server.start()

    def _enforce_limits(self) -> dict:
        """``limits``: RSS of host + workers (warn, audit) and data-directory size (retire old partitions)."""
        lim = self.cfg.data.get("limits") or {}
        out = {}
        if lim.get("max_rss_mb"):
            import psutil
            me = psutil.Process()
            rss = me.memory_info().rss
            for child in me.children(recursive=True):
                try:
                    rss += child.memory_info().rss
                except psutil.Error:
                    pass
            out["rss_mb"] = round(rss / 2**20, 1)
            self.limits_state["rss_mb"] = out["rss_mb"]
            if out["rss_mb"] > lim["max_rss_mb"]:
                self.limits_state["rss_exceeded"] = self.limits_state.get("rss_exceeded", 0) + 1
                logger.warning(f"limits: {out['rss_mb']} MB resident, above max_rss_mb={lim['max_rss_mb']}")
                if self.audit:
                    self.audit.record("limits.rss", {"rss_mb": out["rss_mb"], "max_rss_mb": lim["max_rss_mb"]})
        if lim.get("max_disk_mb"):
            def size() -> float:
                total = 0
                for dirpath, _d, files in os.walk(self.data_dir):
                    for f in files:
                        try:
                            total += os.path.getsize(os.path.join(dirpath, f))
                        except OSError:
                            pass
                return total / 2**20
            mb = size()
            retired = 0
            while mb > lim["max_disk_mb"] and self.database is not None and self.database.retire_oldest():
                retired += 1
                mb = size()
            out.update(disk_mb=round(mb, 1), partitions_retired=retired)
            self.limits_state["disk_mb"] = out["disk_mb"]
            if retired and self.audit:
                self.audit.record("limits.disk", {"disk_mb": out["disk_mb"], "partitions_retired": retired})
            if mb > lim["max_disk_mb"]:
                logger.warning(f"limits: data directory {mb:.0f} MB, above max_disk_mb={lim['max_disk_mb']} "
                               "(journal and evidence are never deleted early)")
        return out

    @property
    def query_engine(self):
        """KQL / SPL2 / HQL over the event store and the lakehouse outputs (``ulpf.query``)."""
        if self._query_engine is None:
            from ulpf.lake import service as lake_service
            from ulpf.query.engine import Governor, QueryEngine
            q = self.cfg.get("query") or {}
            gov = Governor(q.get("max_concurrent", 4), q.get("per_user", 2), q.get("memory_mb", 1024),
                           q.get("query_memory_mb", 256), q.get("max_queue", 64), q.get("timeout_seconds", 30))
            self._query_engine = QueryEngine(self.database, lake_service.get,
                                             os.path.join(self.data_dir, "lookups"), gov)
        return self._query_engine

    @property
    def apg_engine(self):
        """The control plane's view of the learned parsers: one engine per runtime, built once.

        Spec files changed by the workers (new canaries, promotions) are picked up
        by an mtime check on each access instead of re-reading and re-compiling
        every spec per request. No learning thread runs here.
        """
        with self._apg_lock:
            if self._apg_engine is None:
                from ulpf.intelligence.auto_parser.engine import AutoParserEngine
                eng = AutoParserEngine(learned_dir=self.learned_dir)
                if self.cfg["learning"]["approval_required"]:
                    eng.approval_required = True
                    eng.registry.require_signatures()
                self._apg_engine = eng
            else:
                self._apg_engine.registry.reload_if_changed()
            return self._apg_engine

    def decide_parser(self, parser_id: str, decision: str, operator: str):
        """Approve or reject a learned parser and tell every worker to load the decision now."""
        eng = self.apg_engine
        with self._apg_lock:
            spec = eng.approve(parser_id, operator) if decision == "approve" else eng.reject(parser_id, operator)
        if self.dispatcher is not None:
            self.dispatcher.broadcast("reload_parsers")
        return spec

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def _start_intel(self, cfg) -> None:
        """Threat-intelligence platform: file feeds and the snapshot before the workers start (they load
        it), network feeds in the background."""
        intel = cfg.get("intel") or {}
        if not intel.get("enabled", True):
            return
        from ulpf.intelligence.tip.service import TipService

        def reload(_path):
            if self.dispatcher is not None:
                self.dispatcher.broadcast("reload_intel")

        self.tip = TipService(self.data_dir, intel, mode=cfg.mode, airgap_allow=cfg["airgap"]["allow"],
                              on_snapshot=reload)
        for f in self.tip.feeds:
            if f["type"] in ("stix_file", "misp_file", "otx_file"):
                self.tip.sync(f["name"])
        self.tip.build()
        self.tip.start(float(intel.get("poll_seconds", 30)))

    def stop(self, timeout: float = 30.0) -> dict:
        self._stopping = True          # no input restarts or cluster take-overs from here on
        deadline = time.monotonic() + timeout
        for name in list(self.inputs):
            self._stop_input(name, max(0.1, min(10, deadline - time.monotonic())))
        if self.api_server is not None:
            self.api_server.stop()
        if self.soar is not None:
            self.soar.close()
        if self.live is not None:
            self.live.stop()
        if self.tip is not None:
            self.tip.stop()
        drained = self.dispatcher.drain(max(0.1, deadline - time.monotonic()))
        self.dispatcher.stop(max(1.0, deadline - time.monotonic()))
        self._commit()
        if self.correlator is not None:
            self.correlator.step(time.time() + 10**9)   # flush open groups
        if self.sealer is not None:
            while self.sealer.seal_now("shutdown"):
                pass
            self.sealer.close()
        for r in self.runners.values():
            r.drain_deadline = time.monotonic() + max(1.0, deadline - time.monotonic())
        self._sink_stop.set()
        self.stop_event.set()
        for r in self.runners.values():
            r.join(max(1.0, deadline - time.monotonic()) + 1)
        self._commit()
        self.journal.close()
        if self.database is not None:
            self.database.close()
        summary = {"drained": drained, **self.stats()}
        if self.cluster is not None:
            self.cluster.running_inputs = []
            self.cluster.stop()
        from ulpf.runtime import egress
        if egress.current() is self.egress:
            egress.uninstall()
        if self.audit:
            self.audit.record("runtime.stop", {"drained": drained,
                                               "egress": summary["egress"],
                                               "journal": summary["journal"],
                                               "undelivered_segments": {k: v["buffer"]["segments"]
                                                                        for k, v in summary["outputs"].items()}})
        return summary

    def run_forever(self) -> None:
        import signal
        stop = threading.Event()

        def _sig(*_):
            stop.set()

        for s in (signal.SIGINT, getattr(signal, "SIGTERM", None), getattr(signal, "SIGBREAK", None)):
            if s is not None:
                try:
                    signal.signal(s, _sig)
                except (ValueError, OSError):
                    pass
        if hasattr(signal, "SIGHUP"):
            try:
                signal.signal(signal.SIGHUP, lambda *_: threading.Thread(target=self.reload, daemon=True).start())
            except (ValueError, OSError):
                pass
        try:
            while not stop.wait(0.5):
                pass
        finally:
            self.stop()

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        return {
            "node": getattr(self, "node", None), "mode": self.cfg.mode,
            "uptime_seconds": round(time.time() - self.started_at, 1) if self.started_at else 0,
            "reloads": self.reloads,
            "limits": dict(self.limits_state),
            "journal": self.journal.stats() if self.journal else {},
            "committed_seq": self.persisted_committed,
            "pipeline": self.dispatcher.stats() if self.dispatcher else {},
            "inputs": {n: i.describe() for n, i in self.inputs.items()},
            "outputs": {n: r.stats() for n, r in self.runners.items()},
            "dlq": self.dlq.stats() if hasattr(self, "dlq") else {},
            "correlation": {"events_seen": self.correlator.events_seen,
                            "groups_emitted": self.correlator.groups_emitted,
                            "groups_open": len(self.correlator.correlator._groups),
                            "groups_closed": self.correlator.evicted} if self.correlator else None,
            "evidence": self.sealer.stats() if self.sealer else None,
            "egress": self.egress_report(),
            "cluster": {"node": self.node, "alive": self.cluster._alive,
                        "running_inputs": sorted(self.inputs)} if self.cluster else None,
        }

    def egress_report(self) -> dict:
        """Outbound destinations actually contacted by the host and the workers (U4)."""
        if self.egress is None:
            return {"mode": "off", "destinations": {}, "blocked": {}}
        snap = self.egress.snapshot()
        for w in list(self.worker_egress.values()):
            for kind in ("destinations", "blocked"):
                for dest, n in (w.get(kind) or {}).items():
                    snap[kind][dest] = snap[kind].get(dest, 0) + n
        return snap
