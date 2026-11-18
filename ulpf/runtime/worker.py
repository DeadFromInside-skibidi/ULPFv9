"""
Worker process: journal records in, sink buffer segments out.

For every batch (one journal block) the worker

1. decodes each record and runs the pipeline (detect → parse → learned
   parser → raw fallback → normalise → enrich), with the event ID derived
   from (node, sequence) and the SHA-256 computed by the journal;
2. stamps evidence (journal sequence, node) and provenance (input, source);
3. runs per-worker analytics (anomaly detection, Log DNA drift per source)
   and turns findings into derived events of the same batch;
4. routes every event, encodes per sink, and writes one segment per sink
   named by the batch's journal range (exactly-once into the buffer);
5. reports counters and a slim projection of each event (for cross-source
   correlation in the host).
"""
from __future__ import annotations

import logging
import os
import time
import traceback

logger = logging.getLogger("ulpf.runtime.worker")

_PROJ_KEYS = ("event_id", "timestamp", "category", "action", "severity", "message",
              "event_type", "raw_format")


# Same groups, keys and order as the compiled core's write_projection (engine.rs)
_PROJ_GROUPS = (("source", ("ip", "hostname", "mac", "port")), ("destination", ("ip", "hostname", "port")),
                ("device", ("hostname", "ip", "product", "vendor")), ("user", ("name", "domain", "id", "email", "source")),
                ("network", ("session_id", "bytes_in", "bytes_out", "protocol")),
                ("threat", ("ioc_value", "category", "signature")), ("rule", ("name",)),
                ("geo", ("src_country_code", "src_city", "src_latitude", "src_longitude")))


def project(e: dict) -> dict:
    """The fields host analytics read: cross-source correlation, kill-chain mapping and UEBA
    (identities, asset bindings, geography, egress)."""
    p = {k: e.get(k) for k in _PROJ_KEYS}
    for group, keys in _PROJ_GROUPS:
        g = e.get(group) or {}
        p[group] = {k: g.get(k) for k in keys}
    return p


def _looks_like_ip(s: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


class WorkerState:
    """Everything a worker builds once (also usable in-process for tests)."""

    def __init__(self, cfg: dict, node: str, worker_id: int):
        from ulpf.engine.pipeline import Pipeline
        from ulpf.runtime.buffer import DiskBuffer
        from ulpf.runtime.router import Router
        from ulpf.runtime.sinks import build_sink

        self.cfg = cfg
        self.node = node
        self.worker_id = worker_id
        from ulpf.parsers.plugins import policy_from_config
        self.pipeline = Pipeline(enable_auto_parser=True, learned_parsers_dir=cfg.get("_learned_dir"),
                                 plugin_policy=policy_from_config(cfg),
                                 apg_engine=(cfg.get("learning") or {}).get("engine") or "classic")
        self._configure_learning()
        from ulpf.query.live import LiveFilters
        self.live = LiveFilters()            # live-tail filters (lease from the host)
        yl = (cfg.get("analytics") or {}).get("yaral") or {}
        self.yaral = None
        if yl.get("enabled", True) and yl.get("rules") and ((cfg.get("analytics") or {}).get("correlation") or {}) \
                .get("enabled", True):
            from ulpf.intelligence.yaral import YaraLEngine
            self.yaral = YaraLEngine.load(yl["rules"])     # same files, same order as the host
            self._yaral_inputs = set(yl.get("inputs") or [])
        self.router = Router(cfg["routes"], cfg.get("default_output"))
        # The host's cross-source correlation reads a projection of every log event
        self._correlate = bool(((cfg.get("analytics") or {}).get("correlation") or {}).get("enabled", True))
        # Sigma rules run here, on full events; the host only sees projections (+ these hits)
        from ulpf.intelligence.sigma import engine_from_config
        self.sigma = engine_from_config(cfg)
        dp = ((cfg.get("compliance") or {}).get("dpdp") or {})
        self.dpdp = None
        if dp.get("enabled"):
            from ulpf.compliance.dpdp import DPDPStage
            self.dpdp = DPDPStage(dp, cfg["_data_dir"])
        from ulpf.intelligence.tip import runtime as tip_runtime
        intel = cfg.get("intel") or {}
        tip_runtime.configure(os.path.join(cfg["_data_dir"], "intel", "matcher.snap")
                              if intel.get("enabled", True) else None)
        self.native = None
        if not self.pipeline.registry.plugins:          # plugins take precedence over built-in parsers
            from ulpf.engine.native_lane import NativeLane
            self.native = NativeLane.create()
        self.sinks = {}
        self.buffers = {}
        # Row MACs: the host's forward-secure key ratchet, from its current base epoch
        from ulpf.runtime.keys import RowKeyChain
        snap = cfg.get("_row_ratchet")
        self.row_keys = RowKeyChain.from_snapshot(snap) if snap else None
        for o in cfg["outputs"]:
            if not o.get("enabled", True):
                continue
            sink = build_sink(o, {"mode": cfg["mode"], "worker": True, "row_key": self.row_keys})
            self.sinks[o["name"]] = sink
            self.buffers[o["name"]] = DiskBuffer(
                os.path.join(cfg["_buffer_root"], o["name"]),
                int(o["buffer"]["max_mb"] * 2**20), o["buffer"]["when_full"], sink.ext)
        analytics = cfg.get("analytics") or {}
        self.anomaly = None
        an = analytics.get("anomaly") or {}
        if an.get("enabled", True):
            from ulpf.intelligence.anomaly import AnomalyDetector, NativeAnomalyDetector
            # Live streams: first-seen alerts only for public IPs, after a baseline,
            # and only once the IP population has stabilised (< 1 % novelty)
            opts = dict(new_ip_warmup=an.get("new_ip_warmup_events", 10_000), new_ip_external_only=True,
                        new_ip_max_novelty=0.01)
            state_cls = getattr(self.native.engine_module, "AnomalyState", None) if self.native else None
            # with the compiled core, its per-event state serves every batch (native or not)
            self.anomaly = NativeAnomalyDetector(state_cls, **opts) if state_cls else AnomalyDetector(**opts)
        self.drift = None
        if (analytics.get("drift") or {}).get("enabled", True):
            from ulpf.runtime.analytics import DriftMonitor, NativeDriftMonitor
            dopts = dict(sample_lines=analytics["drift"].get("sample_lines", 500),
                         min_interval_seconds=analytics["drift"].get("min_interval_seconds", 5),
                         data_dir=cfg["_data_dir"])
            dstate = getattr(self.native.engine_module, "DriftState", None) if self.native else None
            self.drift = NativeDriftMonitor(dstate, **dopts) if dstate else DriftMonitor(**dopts)
        self.input_tags = {i["name"]: list(i.get("tags") or []) for i in cfg["inputs"]}
        from ulpf.runtime.decoders import build_decoders
        self.decoders = build_decoders(cfg["inputs"], cfg["_data_dir"])
        self.native_analytics = self._native_analytics()

    def _native_analytics(self):
        """Sigma rules and routes compiled for the core (``ulpf_core.Analytics``), or None when
        a rule or route needs Python — the batch then goes through event dicts."""
        if self.native is None or self.dpdp is not None:
            return None
        import orjson
        sigma_ir = None
        if self.sigma is not None and self._correlate:
            ir = self.sigma.ir()
            if ir is None:
                logger.info("a Sigma rule needs the Python evaluator; native lane builds event dicts")
                return None
            sigma_ir = orjson.dumps(ir).decode()
        try:
            route_ir, self._route_names = self.router.ir()
            return self.native.engine_module.Analytics(sigma_ir, orjson.dumps(route_ir).decode())
        except (ValueError, TypeError) as e:
            logger.info(f"native analytics unavailable ({e}); native lane builds event dicts")
            return None

    def _configure_learning(self) -> None:
        eng = self.pipeline.auto_engine
        if eng is None:
            return
        learning = self.cfg.get("learning") or {}
        eng.approval_required = bool(learning.get("approval_required"))
        if eng.approval_required:
            eng.registry.require_signatures()
        eng.max_parsers_per_source = int(learning.get("max_parsers_per_source") or 0) or None
        if not learning.get("autonomous", True):
            eng.profile.auto_discovery = False

    def close(self) -> None:
        self.pipeline.close()

    def _project(self, e: dict) -> dict:
        p = project(e)
        if self.sigma is not None:
            p["sigma"] = self.sigma.match(e)
        return p

    def _python_event(self, input_name: str, source: str, source_ip: str, learn_key: str, tags: list,
                      decoder, seq: int, raw: bytes, digest: bytes, counts: dict) -> dict | None:
        """One record through the Python pipeline plus the worker's fields (None: skipped)."""
        from ulpf.runtime.ids import event_id
        node = self.node
        container = None
        if decoder is not None:
            text, container = decoder.decode(raw, source)
        else:
            text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
        # source_ip keys the learning plane's per-source limits; non-IP sources use input/source
        r = self.pipeline.process_line(text, event_id=event_id(node, seq), source_ip=learn_key,
                                       raw_hash=digest.hex())
        if not r.get("success"):
            if r.get("skipped"):
                counts["skipped"] += 1
                return None
            counts["failed"] += 1
            from ulpf.engine.normalizer import build_raw_fallback_event
            ev = build_raw_fallback_event(text, raw_hash=digest.hex(), event_id=event_id(node, seq))
            ev.setdefault("tags", []).append("pipeline_error")
        else:
            ev = r["event"]
            if r.get("raw_fallback"):
                counts["raw_fallback"] += 1
            elif r.get("auto_parsed"):
                counts["auto_parsed"] += 1
        evid = ev.setdefault("evidence", {})
        evid["journal_seq"] = seq
        evid["node_id"] = node
        ev["event_kind"] = "log"
        meta = ev["metadata"]
        meta["input"] = input_name
        meta["ingestion_source"] = source
        if source_ip:
            meta["ingestion_source_ip"] = source_ip
            dev = ev.get("device")
            if dev is not None and not dev.get("ip"):
                dev["ip"] = source_ip
        if tags:
            ev["tags"] = list(ev.get("tags") or []) + tags
        if container:
            if "journald" in container:
                j = container["journald"]
                ev.setdefault("extensions", {})["journald"] = j
                if j.get("_HOSTNAME") and not (ev.get("device") or {}).get("hostname"):
                    ev["device"]["hostname"] = j["_HOSTNAME"]
            else:
                ev.setdefault("extensions", {})["container"] = container
                if container.get("name") and not (ev.get("device") or {}).get("hostname"):
                    ev["device"]["hostname"] = container.get("pod") or container["name"]
        return ev

    def _native_batch(self, res, py: dict, input_name: str, source: str, first_seq: int, n: int,
                      counts: dict, t0: float, stop) -> dict:
        """Finish a native-lane batch without event dicts for its native records: Sigma hits and
        routes come from the core, anomalies from its per-event state, drift from its structure
        signatures. Only Python-path records, Sigma-undecided events and events routed to
        non-DuckDB outputs exist as dicts. The segments, projections and derived events are
        the ones the dict path builds (``tests/test_native_lane.py``)."""
        from ulpf.runtime.sinks.duckdb_sink import DuckDBSink, encode_mixed
        node = self.node
        batch = res.batch
        native = res.native
        py_items = sorted(py.items())
        total = len(native) + len(py)
        derived: list[dict] = []
        if self.anomaly is not None and total:
            from ulpf.runtime.analytics import anomaly_event
            for k, a in enumerate(self.anomaly.analyse_native(batch, py_items)):
                derived.append(anomaly_event(a, node, first_seq, k, input_name, source))
        if self.drift is not None and total:
            if hasattr(self.drift, "observe_native"):
                derived += self.drift.observe_native(input_name, source, batch, py_items)
            else:
                from ulpf.runtime.analytics import structure_signature
                merged = [(i, (fmt, sig, raw, {"event_id": eid, "evidence": {"journal_seq": seq, "node_id": nid}}))
                          for i, (fmt, sig, raw, eid, seq, nid) in zip(native, batch.drift_items())]
                merged += [(i, (e.get("raw_format"), None if (e.get("raw_format") or "unknown") == "ulpf_derived"
                                else structure_signature(e), e.get("raw_event"), e)) for i, e in py_items]
                merged.sort(key=lambda x: x[0])
                derived += self.drift.observe_items(input_name, source, (x for _, x in merged))
        counts["events"] = total
        counts["derived"] = len(derived)

        # routes: the core's targets for native events, the router for the others
        names = self._route_names
        per_sink: dict[str, list] = {}       # sink -> [(order, "n", position) | (order, "p", event)]
        self.router.unrouted += res.unrouted
        if res.targets_uniform is not None:
            # every native event goes to the same outputs: one list per output, merged with the others
            for t in (names[j] for j in res.targets_uniform):
                per_sink[t] = [(i, "n", k) for k, i in enumerate(native)]
            for i, e in py_items:
                for t in self.router.targets(e):
                    per_sink.setdefault(t, []).append((i, "p", e))
            for items in per_sink.values():
                if any(items[k][0] > items[k + 1][0] for k in range(len(items) - 1)):
                    items.sort(key=lambda x: x[0])
        else:
            tagged = [(i, "n", k) for k, i in enumerate(native)] + [(i, "p", e) for i, e in py_items]
            tagged.sort(key=lambda x: x[0])
            for i, kind, x in tagged:
                for t in ([names[j] for j in res.targets[x]] if kind == "n" else self.router.targets(x)):
                    per_sink.setdefault(t, []).append((i, kind, x))
        for k, d in enumerate(derived):
            for t in self.router.targets(d):
                per_sink.setdefault(t, []).append((n + k, "p", d))

        written: dict[str, int] = {}
        dropped: dict[str, int] = {}
        last_seq = first_seq + n - 1
        dicts: dict[int, dict] = {}          # native position -> event dict, built on demand
        for sink_name, items in per_sink.items():
            sink = self.sinks.get(sink_name)
            if sink is None:
                continue
            buf = self.buffers[sink_name]
            name = buf.log_name(first_seq, last_seq, len(items))
            if buf.exists(name):
                written[sink_name] = len(items)   # replay of an already-buffered batch
                continue
            if isinstance(sink, DuckDBSink):
                pos = [x for _, kind, x in items if kind == "n"]
                table = res.table if len(pos) == len(native) else res.table.take(pos)
                payload = encode_mixed(table, [native[p] for p in pos],
                                       [(i, x) for i, kind, x in items if kind == "p"], self.row_keys)
            else:
                need = [x for _, kind, x in items if kind == "n" and x not in dicts]
                if need:
                    import orjson
                    dicts.update(zip(need, orjson.loads(batch.events_json(need))))
                payload = sink.encode([dicts[x] if kind == "n" else x for _, kind, x in items])
            dropped[sink_name] = buf.write(name, payload, stop=stop)
            written[sink_name] = len(items)

        proj_list: list = []
        if self._correlate:
            proj = dict(zip(native, res.projections))
            if res.sigma_undecided:
                import orjson
                for p, e in zip(res.sigma_undecided, orjson.loads(batch.events_json(res.sigma_undecided))):
                    proj[native[p]]["sigma"] = self.sigma.match(e)
            if self.sigma is not None:
                self.sigma.matches += res.sigma_matches
            proj.update({i: self._project(e) for i, e in py_items})
            proj_list = [proj[i] for i in sorted(proj)]
        out = {"t": "done", "worker": self.worker_id, "first": first_seq, "last": last_seq,
               "counts": counts, "written": written, "dropped": dropped, "proj": proj_list,
               "derived_summary": [(d["event_kind"], d.get("message")) for d in derived][:20],
               "elapsed": time.perf_counter() - t0}
        live = self._live_matches(res.table, [e for _, e in py_items])
        if live:
            out["live"] = live
        if self.yaral is not None and self.yaral.rules and (not self._yaral_inputs or input_name in self._yaral_inputs):
            import orjson
            evs = orjson.loads(batch.events_json(list(range(len(native))))) if native else []
            cands = self.yaral.extract(evs + [e for _, e in py_items])
            if cands:
                out["yaral"] = cands
        return out

    def _live_matches(self, native_table=None, events=()) -> dict | None:
        """Matches of the open live tails in this batch (store-format rows), or None."""
        if not self.live.active():
            return None
        import pyarrow as pa
        from ulpf.storage.database import event_to_row, rows_to_arrow
        parts = [native_table] if native_table is not None and native_table.num_rows else []
        logs = [e for e in events if e.get("event_kind", "log") == "log"]
        if logs:
            parts.append(rows_to_arrow([event_to_row(e) for e in logs]))
        if not parts:
            return None
        try:
            out = self.live.run(parts[0] if len(parts) == 1 else pa.concat_tables(parts))
        except Exception:
            logging.getLogger(__name__).warning("live tail filters failed", exc_info=True)
            return None
        return out or None

    def reload_parsers(self) -> int:
        """Pick up learned-parser decisions now (operator approve/reject via the API)."""
        eng = self.pipeline.auto_engine
        return eng.registry.reload_if_changed() if eng is not None else 0

    def forget_keys_before(self, committed: int) -> None:
        """Erase row keys of epochs no record after ``committed`` can need."""
        if self.row_keys is not None:
            self.row_keys.advance_to_seq(committed + 1)

    # ------------------------------------------------------------------

    def process(self, input_name: str, source: str, first_seq: int, raws: list[bytes],
                digests: list[bytes], recv_ts: float, stop=None) -> dict:
        t0 = time.perf_counter()
        node = self.node
        source_ip = source if _looks_like_ip(source) else ""
        learn_key = source_ip or f"{input_name}:{source}"
        tags = self.input_tags.get(input_name) or []
        decoder = self.decoders.get(input_name)
        events: list[dict] = []
        counts = {"records": len(raws), "events": 0, "skipped": 0, "failed": 0,
                  "raw_fallback": 0, "auto_parsed": 0}
        lane = self.native if decoder is None else None
        if lane is not None:
            # Compiled core for whole batches; the records it cannot reproduce exactly
            # (and the stateful formats) run through the Python pipeline below, in order.
            # With the analytics compiled for the core, native records never become dicts.
            nat = self.native_analytics
            res = lane.run(raws, digests, first_seq, node, input_name, source, source_ip, tags, self.row_keys,
                           want_events=nat is None, want_projections=nat is not None and self._correlate,
                           analytics=nat)
            py: dict[int, dict] = {}
            for i in res.delegated:
                ev = self._python_event(input_name, source, source_ip, learn_key, tags, None, first_seq + i,
                                        raws[i], digests[i], counts)
                if ev is not None:
                    py[i] = ev
            counts["native"] = len(res.native)
            if nat is not None:
                return self._native_batch(res, py, input_name, source, first_seq, len(raws), counts, t0, stop)
            by_index = dict(zip(res.native, res.events))
            by_index.update(py)
            events = [by_index[i] for i in sorted(by_index)]
        else:
            for i, raw in enumerate(raws):
                ev = self._python_event(input_name, source, source_ip, learn_key, tags, decoder, first_seq + i,
                                        raw, digests[i], counts)
                if ev is not None:
                    events.append(ev)

        if self.dpdp is not None:
            for e in events:
                self.dpdp.apply(e)

        derived: list[dict] = []
        if self.anomaly is not None and events:
            from ulpf.runtime.analytics import anomaly_event
            for k, a in enumerate(self.anomaly.analyse_batch(events)):
                derived.append(anomaly_event(a, node, first_seq, k, input_name, source))
        if self.drift is not None and events:
            for k, d in enumerate(self.drift.observe(input_name, source, events)):
                derived.append(d)
        counts["events"] = len(events)
        counts["derived"] = len(derived)

        written: dict[str, int] = {}
        dropped: dict[str, int] = {}
        last_seq = first_seq + len(raws) - 1
        for sink_name, batch in self.router.split(events + derived).items():
            sink = self.sinks.get(sink_name)
            if sink is None:
                continue
            buf = self.buffers[sink_name]
            name = buf.log_name(first_seq, last_seq, len(batch))
            if buf.exists(name):
                written[sink_name] = len(batch)   # replay of an already-buffered batch
                continue
            payload = sink.encode(batch)
            dropped[sink_name] = buf.write(name, payload, stop=stop)
            written[sink_name] = len(batch)
        out = {"t": "done", "worker": self.worker_id, "first": first_seq, "last": last_seq,
               "counts": counts, "written": written, "dropped": dropped,
               "proj": [self._project(e) for e in events if e.get("event_kind") == "log"] if self._correlate else [],
               "derived_summary": [(d["event_kind"], d.get("message")) for d in derived][:20],
               "elapsed": time.perf_counter() - t0}
        live = self._live_matches(None, events)
        if live:
            out["live"] = live
        if self.yaral is not None and self.yaral.rules and (not self._yaral_inputs or input_name in self._yaral_inputs):
            cands = self.yaral.extract(events)
            if cands:
                out["yaral"] = cands
        return out


def worker_main(worker_id: int, cfg: dict, node: str, in_q, out_q, stop) -> None:
    """Entry point of a worker process."""
    logging.basicConfig(level=os.environ.get("ULPF_LOG_LEVEL", "WARNING"),
                        format="%(asctime)s [%(processName)s] %(levelname)s %(name)s: %(message)s")
    from ulpf.engine.perf import tune_gc
    from ulpf.runtime import egress
    from ulpf.runtime.buffer import BufferFull
    air = cfg.get("airgap") or {}
    guard = egress.install(air.get("allow") or [], bool(air.get("enforce")),
                           dns_refresh_s=air.get("dns_refresh_seconds", 60),
                           dns_grace_s=air.get("dns_grace_seconds", 300))
    try:
        state = WorkerState(cfg, node, worker_id)
    except Exception:
        out_q.put({"t": "fatal", "worker": worker_id, "error": traceback.format_exc()})
        return
    tune_gc()
    out_q.put({"t": "ready", "worker": worker_id, "pid": os.getpid()})
    try:
        while True:
            msg = in_q.get()
            if msg is None:
                break
            if msg[0] == "live":                       # live-tail lease: (specs, seconds)
                state.live.set(*msg[1])
                continue
            if msg[0] == "reload_intel":              # the host rebuilt the indicator snapshot
                from ulpf.intelligence.tip import runtime as tip_runtime
                tip_runtime.reload()
                continue
            if msg[0] == "reload_parsers":
                try:
                    state.reload_parsers()
                except Exception:
                    logging.getLogger(__name__).warning("learned-parser reload failed", exc_info=True)
                continue
            _kind, input_name, source, first_seq, raws, digests, recv_ts, *extra = msg
            if extra:
                state.forget_keys_before(extra[0])
            try:
                result = state.process(input_name, source, first_seq, raws, digests, recv_ts, stop=stop)
            except BufferFull:
                # stopping while a sink buffer is full: leave the batch to journal replay
                kind = "aborted" if stop.is_set() else "error"
                result = {"t": kind, "worker": worker_id, "first": first_seq,
                          "last": first_seq + len(raws) - 1, "error": traceback.format_exc(),
                          "input": input_name, "source": source}
            except Exception:
                result = {"t": "error", "worker": worker_id, "first": first_seq,
                          "last": first_seq + len(raws) - 1, "error": traceback.format_exc(),
                          "input": input_name, "source": source}
            if guard.destinations or guard.blocked:
                result["egress"] = guard.snapshot()
            out_q.put(result)
    finally:
        state.close()
        out_q.put({"t": "exit", "worker": worker_id})
