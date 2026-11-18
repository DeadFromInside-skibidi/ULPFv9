"""
ULPF — Universal Log Pre-processing Framework
================================================
Command-line entry point.

    python -m ulpf.main --help
    python -m ulpf.main process --files demo_data/*.log
    python -m ulpf.main learn --file custom_app.log
    python -m ulpf.main listen --port 5514 --protocol both
    python -m ulpf.main serve --port 8000
    python -m ulpf.main forensic --limit 500 --description "Incident 42"
    python -m ulpf.main forensic --verify evidence_xxx.json
    python -m ulpf.main purge --older-than-days 90
    python -m ulpf.main desktop

All commands share one event store: ``--db PATH`` > ``ULPF_DB_PATH`` >
``<data dir>/ulpf.duckdb`` (data dir: ``ULPF_DATA_DIR`` or the platform default).
"""
from __future__ import annotations

import argparse
import glob
import json
import logging
import os
import sys
import time
from collections import Counter

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def _siem_forward(events: list, host_port: str, proto: str = "udp") -> int:
    """Forward normalized events to a remote SIEM as RFC 5424 syslog. Returns count sent."""
    from ulpf.ingestion.forwarder import SiemForwarder
    fwd = SiemForwarder.from_target(host_port, proto)
    try:
        return fwd.send(events)
    finally:
        fwd.close()


def _open_plugin(args, **overrides):
    """Initialise the plugin, turning a locked store into a clear CLI error."""
    from ulpf.plugin.interface import ULPFPlugin
    from ulpf.storage.database import DatabaseLockedError
    plugin = ULPFPlugin()
    plugin.initialize({"storage_backend": "duckdb", **overrides})
    plugin.start()
    if getattr(plugin.storage, "read_only", False) and getattr(args, "_needs_write", False):
        plugin.shutdown()
        raise DatabaseLockedError(
            f"The event store {plugin.config.storage_path} is locked by another ULPF process "
            "(desktop app or API server). Close it, or pass --db to use a different store.")
    return plugin


def _expand(patterns: list[str]) -> list[str]:
    files: list[str] = []
    for p in patterns:
        matches = glob.glob(p)
        files.extend(sorted(matches) if matches else [p])
    return files


# ---------------------------------------------------------------------------
# process
# ---------------------------------------------------------------------------

def cmd_process(args):
    """Parse, normalise, enrich and store log files."""
    from ulpf.engine.perf import tune_gc
    args._needs_write = True
    plugin = _open_plugin(args)
    tune_gc()
    pipeline, db, detector = plugin.pipeline, plugin.storage, plugin.anomaly_detector
    correlator = plugin.correlator if args.correlate else None

    fmt_ctr: Counter = Counter()
    cat_ctr: Counter = Counter()
    sev_ctr: Counter = Counter()
    src_ctr: Counter = Counter()
    threat_by_ip: dict[str, str] = {}
    geo_by_ip: dict[str, str] = {}
    ioc_samples: list[dict] = []
    totals = Counter()
    forwarder = None
    if args.siem_forward:
        from ulpf.ingestion.forwarder import SiemForwarder
        forwarder = SiemForwarder.from_target(args.siem_forward, args.siem_proto)

    out = None
    if args.output:
        out = open(args.output, "w", encoding="utf-8")
        out.write("[\n")
    first_out = True
    t_start = time.perf_counter()
    files = _expand(args.files)

    try:
        for filepath in files:
            if not os.path.isfile(filepath):
                print(f"  [!] File not found: {filepath}")
                continue
            print(f"\n{'=' * 60}\n  Processing: {filepath}\n{'=' * 60}")
            f_tot = Counter()
            f_fmt: Counter = Counter()
            f_anoms: list[dict] = []
            failed_samples: list[str] = []
            t0 = time.perf_counter()
            for results in pipeline.iter_file(filepath, batch_size=5000):
                events = []
                for r in results:
                    if r.get("success"):
                        events.append(r["event"])
                    elif r.get("skipped"):
                        f_tot["skipped"] += 1
                    else:
                        f_tot["failed"] += 1
                        if len(failed_samples) < 5:
                            failed_samples.append(r.get("error", "unknown"))
                f_tot["lines"] += len(results)
                f_tot["ok"] += len(events)
                if not events:
                    continue
                if correlator:
                    for e in events:
                        correlator.add_and_correlate(e)
                f_tot["stored"] += db.store_events_bulk(events)
                if detector:
                    anomalies = detector.analyse_batch(events)
                    if anomalies:
                        db.store_anomalies_bulk(anomalies)
                        f_anoms.extend(anomalies)
                if forwarder:
                    f_tot["forwarded"] += forwarder.send(events)
                for e in events:
                    f_fmt[e["raw_format"]] += 1
                    cat_ctr[e["category"]] += 1
                    sev_ctr[e["severity_label"]] += 1
                    ip = e["source"]["ip"]
                    if ip:
                        src_ctr[ip] += 1
                        if e["threat"]["category"]:
                            threat_by_ip.setdefault(ip, e["threat"]["category"])
                        cc = e["geo"]["src_country_code"]
                        if cc and cc not in ("XX", "??"):
                            geo_by_ip.setdefault(ip, cc)
                    if e["threat"]["ioc_value"] and len(ioc_samples) < 5:
                        ioc_samples.append(e)
                if out:
                    for e in events:
                        out.write(("" if first_out else ",\n") + json.dumps(e, default=str))
                        first_out = False
            elapsed = time.perf_counter() - t0
            fmt_ctr.update(f_fmt)
            totals.update(f_tot)
            totals["anomalies"] += len(f_anoms)

            print(f"  Lines processed : {f_tot['lines']}")
            print(f"  Events          : {f_tot['ok']}  (headers skipped: {f_tot['skipped']}, failed: {f_tot['failed']})")
            print(f"  Stored to DB    : {f_tot['stored']}")
            print(f"  Anomalies found : {len(f_anoms)}")
            print(f"  Throughput      : {f_tot['ok'] / elapsed:,.0f} events/s" if elapsed > 0 else "")
            if forwarder:
                print(f"  SIEM forwarded  : {f_tot['forwarded']} -> {args.siem_forward} ({args.siem_proto.upper()})")
            if f_fmt:
                print("\n  Format distribution:")
                for fmt, cnt in f_fmt.most_common():
                    print(f"    {fmt:15s} : {cnt}")
            if failed_samples and args.verbose:
                print("\n  Failed lines (first 5):")
                for err in failed_samples:
                    print(f"    Error: {err}")
            if f_anoms:
                print("\n  [!] Anomalies detected:")
                for a in f_anoms[:5]:
                    print(f"    [{a.get('risk', '?').upper()}] {a.get('description', '')[:100]}")
    finally:
        if out:
            out.write("\n]\n")
            out.close()
        if forwarder:
            forwarder.close()

    total_elapsed = time.perf_counter() - t_start
    print(f"\n{'=' * 60}\n  UNIFIED VISIBILITY SUMMARY  ({len(files)} source(s))\n{'=' * 60}")
    print(f"  Total lines     : {totals['lines']}")
    print(f"  Normalised      : {totals['ok']}  ({totals['ok'] * 100 // max(totals['lines'], 1)}%)")
    print(f"  Stored          : {totals['stored']}")
    print(f"  Anomalies       : {totals['anomalies']}")
    print(f"  Wall time       : {total_elapsed:.2f}s  ({totals['ok'] / max(total_elapsed, 1e-9):,.0f} events/s)")
    if fmt_ctr:
        print("\n  -- Format Distribution")
        peak = max(fmt_ctr.values())
        for fmt, cnt in fmt_ctr.most_common():
            print(f"    {fmt:16s} {'|' * max(1, cnt * 20 // peak):20s} {cnt}")
        print("\n  -- Severity Distribution")
        for lbl in ("unknown", "info", "low", "medium", "high", "critical"):
            if sev_ctr.get(lbl):
                print(f"    {lbl:9s} {sev_ctr[lbl]}")
        print("\n  -- Top Source IPs")
        for ip, cnt in src_ctr.most_common(5):
            geo = f" ({geo_by_ip[ip]})" if ip in geo_by_ip else ""
            threat = f" [{threat_by_ip[ip]}]" if ip in threat_by_ip else ""
            print(f"    {ip:18s} {cnt:5d} events{geo}{threat}")
        print("\n  -- Event Categories")
        for cat, cnt in cat_ctr.most_common():
            print(f"    {cat:15s} : {cnt}")
        if ioc_samples:
            print("\n  -- Threat Intel Matches (sample)")
            for e in ioc_samples:
                print(f"    {e['threat']['ioc_value']:18s}  {e['threat']['category']}  "
                      f"confidence={e['threat']['confidence']:.0%}")
    if correlator:
        groups = correlator.get_results()
        print(f"\n  -- Correlation Groups: {len(groups)}")
        for g in groups[:5]:
            print(f"    {g['correlation_id']}  events={g['event_count']}  risk={g['risk_score']:.1f}  "
                  f"stages={','.join(g['kill_chain_stages']) or '-'}")
    if args.output:
        print(f"\n  Output written to: {args.output}")
    print(f"\n  Database  : {db.db_path}")
    plugin.shutdown()


# ---------------------------------------------------------------------------
# listen
# ---------------------------------------------------------------------------

def cmd_listen(args):
    """Real-time syslog listener feeding a multiprocess worker pool."""
    from multiprocessing import Queue as MPQueue
    from ulpf.ingestion.listener import NetworkListener
    from ulpf.ingestion.workers import WorkerPool
    from ulpf.storage import create_storage

    db = create_storage(path=os.environ.get("ULPF_DB_PATH"))
    if db.read_only:
        print(f"Error: event store {db.db_path} is locked by another ULPF process.")
        return 1
    print(f"\n{'=' * 60}\n  ULPF Real-Time Network Listener\n{'=' * 60}")
    print(f"  Bind     : {args.host}:{args.port} ({args.protocol})")
    print(f"  Workers  : {args.workers or 'auto'}")
    print(f"  Store    : {db.db_path}\n{'=' * 60}\n")

    shared_queue = MPQueue(maxsize=2_000)
    pool = WorkerPool(num_workers=args.workers, input_queue=shared_queue, batch_size=2000,
                      anomaly_detection=True)
    siem_host = siem_port = None
    if args.siem_forward:
        siem_host, _, port = args.siem_forward.rpartition(":")
        siem_host, siem_port = (siem_host, int(port)) if siem_host else (args.siem_forward, 514)
    pool.start(db=db, is_network=True, siem_host=siem_host, siem_port=siem_port)

    def _store_anomalies(msg):
        if msg.get("anomalies"):
            db.store_anomalies_bulk(msg["anomalies"])
    pool._on_batch = _store_anomalies

    listener = NetworkListener(shared_queue, host=args.host, port=args.port)
    try:
        listener.run_forever(protocol=args.protocol)
    except KeyboardInterrupt:
        pass
    finally:
        metrics = pool.stop()
        db.close()
        print(f"\n  Worker pool metrics: {json.dumps(metrics, indent=2)}")
    return 0


# ---------------------------------------------------------------------------
# correlate / forensic / export-ml
# ---------------------------------------------------------------------------

def cmd_correlate(args):
    from ulpf.intelligence.correlation import EventCorrelator
    plugin = _open_plugin(args)
    db = plugin.storage
    events = db.query(limit=args.limit)
    print(f"Correlating {len(events)} events (window: {args.window}s)...")
    correlator = EventCorrelator(args.window)
    correlator.add_events(events)
    groups = correlator.correlate()
    if not db.read_only:
        for g in groups:
            db.set_correlation([e["event_id"] for e in g.events], g.correlation_id)
    results = correlator.get_results()
    print(f"\nFound {len(results)} correlation groups:\n")
    for d in results:
        print(f"  Group {d['correlation_id']}: {d['event_count']} events, risk={d['risk_score']:.1f}/10")
        if d["kill_chain_stages"]:
            print(f"    Kill-chain: {', '.join(d['kill_chain_stages'])}")
        print(f"    Summary: {d['summary'][:160]}\n")
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"Results written to: {args.output}")
    plugin.shutdown()


def cmd_forensic(args):
    from ulpf.intelligence.forensic import verify_package
    if args.verify:
        result = verify_package(args.verify)
        print(f"  Package : {args.verify}")
        print(f"  Chain   : {result['chain_id']}  ({result['items']} items)")
        print(f"  Merkle  : {result['merkle_root']}")
        print(f"  Verdict : {'[VALID]' if result['valid'] else '[TAMPERED]'}")
        for p in result["problems"]:
            print(f"    - {p}")
        return 0 if result["valid"] else 2

    plugin = _open_plugin(args)
    builder = plugin.forensic_builder
    if args.list:
        for c in builder.list_chains():
            print(f"  {c['chain_id']}  items={c['item_count']:<6} created={c['created_at']}  {c['description']}")
        plugin.shutdown()
        return 0

    events = plugin.storage.query(limit=args.limit)
    if not events:
        print("No events in the store. Run 'process' first.")
        plugin.shutdown()
        return 1
    print(f"Building evidence chain from {len(events)} events...")
    chain = builder.build_from_events(events, description=args.description or "CLI-generated evidence chain",
                                      tags=args.tags.split(",") if args.tags else [])
    integrity = chain.verify_integrity()
    print(f"  Chain ID   : {chain.chain_id}")
    print(f"  Items      : {len(chain.items)}")
    print(f"  Chain Hash : {chain.chain_hash}")
    print(f"  Merkle Root: {chain.merkle_root}")
    print(f"  Integrity  : {'[VALID]' if integrity['valid'] else '[INVALID] ' + integrity['message']}")
    print(f"  Exported to: {builder.export_package(chain.chain_id)}")
    plugin.shutdown()
    return 0


def cmd_purge(args):
    """Retention: delete old events (and anomalies), or unclassified raw_fallback events."""
    from ulpf.storage import create_storage
    db = create_storage(path=os.environ.get("ULPF_DB_PATH"))
    try:
        if args.raw_fallback:
            print(f"Deleted {db.purge_raw_fallback():,} raw_fallback events from {db.db_path}")
        if args.older_than_days is not None:
            n = db.purge_older_than(args.older_than_days, by=args.by)
            print(f"Deleted {n:,} events older than {args.older_than_days} day(s) (by {args.by}) from {db.db_path}")
        if not args.raw_fallback and args.older_than_days is None:
            print("Nothing to do: pass --older-than-days N and/or --raw-fallback")
    finally:
        db.close()
    return 0


_ACTION_CODE = {"allowed": 0, "connected": 0, "success": 0, "blocked": 1, "dropped": 1, "denied": 1,
                "reset": 1, "detected": 2, "alerted": 2, "logged": 2, "failed": 3, "disconnected": 3,
                "other": 4}
_FORMATS = ("cef", "leef", "syslog", "json", "xml", "csv", "kv", "w3c", "auto_detected", "raw_fallback")

# (column, arrow type, kind, description) - kind is numeric | categorical | flag | timestamp | identifier | text
ML_COLUMNS: tuple[tuple[str, str, str, str], ...] = (
    ("event_id", "string", "identifier", "Unified event ID (join key back to the store and raw journal)"),
    ("timestamp", "timestamp", "timestamp", "Event time, UTC"),
    ("hour_of_day", "int8", "numeric", "UTC hour 0-23"),
    ("day_of_week", "int8", "numeric", "0 = Monday"),
    ("severity", "int8", "numeric", "Normalised severity 0-10"),
    ("source_port", "int32", "numeric", "0 when absent"),
    ("dest_port", "int32", "numeric", "0 when absent"),
    ("protocol_number", "int16", "numeric", "IANA protocol number, 0 when absent"),
    ("bytes_in", "int64", "numeric", "0 when absent"),
    ("bytes_out", "int64", "numeric", "0 when absent"),
    ("bytes_total", "int64", "numeric", "bytes_in + bytes_out when not reported"),
    ("action_code", "int8", "categorical", "0 allowed, 1 blocked, 2 detected, 3 failed, 4 other"),
    ("category_code", "int8", "categorical", "Index into the unified category list"),
    ("format_code", "int8", "categorical", "Index into: " + ", ".join(_FORMATS)),
    ("is_threat", "int8", "flag", "An IOC matched"),
    ("is_cross_border", "int8", "flag", "Source and destination countries differ"),
    ("is_blocked", "int8", "flag", "Action is blocked, dropped or denied"),
    ("is_high_severity", "int8", "flag", "Severity >= 7"),
    ("is_learned_format", "int8", "flag", "Parsed by a learned (APG) parser"),
    ("action", "string", "categorical", "Normalised action"),
    ("category", "string", "categorical", "Unified category"),
    ("raw_format", "string", "categorical", "Detected format"),
    ("source_ip", "string", "categorical", "High cardinality: hash or embed before training"),
    ("dest_ip", "string", "categorical", "High cardinality: hash or embed before training"),
    ("src_country_code", "string", "categorical", "ISO code; XX private, ZZ reserved, ?? unknown"),
    ("dst_country_code", "string", "categorical", "ISO code; XX private, ZZ reserved, ?? unknown"),
    ("threat_category", "string", "categorical", "IOC category, empty when none"),
    ("message", "string", "text", "First 200 characters of the message"),
)


def ml_feature_rows(events: list[dict]) -> list[dict]:
    from datetime import datetime
    from ulpf.engine.schema import CATEGORIES
    category_code = {c: i for i, c in enumerate(CATEGORIES)}
    format_code = {f: i for i, f in enumerate(_FORMATS)}
    rows = []
    for e in events:
        net, src, dst = e.get("network") or {}, e.get("source") or {}, e.get("destination") or {}
        geo, threat, tags = e.get("geo") or {}, e.get("threat") or {}, e.get("tags") or []
        bin_, bout = int(net.get("bytes_in") or 0), int(net.get("bytes_out") or 0)
        action, cat, fmt = e.get("action") or "other", e.get("category") or "other", e.get("raw_format")
        try:
            ts = datetime.fromisoformat(str(e.get("timestamp")).replace("Z", "+00:00"))
        except ValueError:
            ts = None
        sev = int(e.get("severity") or 0)
        rows.append({
            "event_id": e.get("event_id"), "timestamp": ts,
            "hour_of_day": ts.hour if ts else 0, "day_of_week": ts.weekday() if ts else 0,
            "severity": sev, "source_port": int(src.get("port") or 0), "dest_port": int(dst.get("port") or 0),
            "protocol_number": int(net.get("protocol_number") or 0),
            "bytes_in": bin_, "bytes_out": bout, "bytes_total": int(net.get("bytes_total") or (bin_ + bout)),
            "action_code": _ACTION_CODE.get(action, 4), "category_code": category_code.get(cat, len(CATEGORIES)),
            "format_code": format_code.get(fmt, len(format_code)),
            "is_threat": int(bool(threat.get("ioc_value"))), "is_cross_border": int("cross_border" in tags),
            "is_blocked": int(action in ("blocked", "dropped", "denied")), "is_high_severity": int(sev >= 7),
            "is_learned_format": int(fmt == "auto_detected"),
            "action": action, "category": cat, "raw_format": fmt or "",
            "source_ip": src.get("ip") or "", "dest_ip": dst.get("ip") or "",
            "src_country_code": geo.get("src_country_code") or "",
            "dst_country_code": geo.get("dst_country_code") or "",
            "threat_category": threat.get("category") or "", "message": (e.get("message") or "")[:200],
        })
    return rows


def write_ml_dataset(rows: list[dict], output_path: str, fmt: str) -> str:
    """Write rows as CSV or Parquet plus ``<output>.columns.json`` describing every column."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    names = [c[0] for c in ML_COLUMNS]
    if fmt == "parquet":
        import pyarrow as pa
        import pyarrow.parquet as pq
        types = {"string": pa.string(), "int8": pa.int8(), "int16": pa.int16(), "int32": pa.int32(),
                 # a fixed offset, not "UTC": readers then need no time-zone database (Windows has none)
                 "int64": pa.int64(), "timestamp": pa.timestamp("ms", tz="+00:00")}
        schema = pa.schema([pa.field(n, types[t], metadata={"kind": k, "description": d})
                            for n, t, k, d in ML_COLUMNS])
        table = pa.Table.from_pylist(rows, schema=schema)
        pq.write_table(table, output_path, compression="zstd")
    else:
        import csv
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=names)
            w.writeheader()
            for r in rows:
                w.writerow({**r, "timestamp": r["timestamp"].isoformat() if r["timestamp"] else ""})
    card = output_path + ".columns.json"
    with open(card, "w", encoding="utf-8") as f:
        from ulpf.engine.schema import SCHEMA_VERSION
        json.dump({"format": fmt, "rows": len(rows), "schema_version": SCHEMA_VERSION,
                   "columns": [{"name": n, "type": t, "kind": k, "description": d} for n, t, k, d in ML_COLUMNS]},
                  f, indent=2)
    return card


def cmd_export_ml(args):
    """Export events as an ML-ready feature matrix (CSV or Parquet) with a column card."""
    plugin = _open_plugin(args)
    events = plugin.storage.query(limit=args.limit)
    if not events:
        print("No events in the store. Run 'process' first.")
        plugin.shutdown()
        return 1
    output_path = args.output
    fmt = args.format or ("parquet" if output_path.lower().endswith(".parquet") else "csv")
    rows = ml_feature_rows(events)
    card = write_ml_dataset(rows, output_path, fmt)
    print(f"\n{'=' * 60}\n  ML FEATURE EXPORT\n{'=' * 60}")
    print(f"  Events exported : {len(rows)}")
    print(f"  Feature columns : {len(ML_COLUMNS)}")
    print(f"  Output file     : {output_path} ({fmt})")
    print(f"  Column card     : {card}")
    plugin.shutdown()
    return 0


# ---------------------------------------------------------------------------
# learn / fingerprint
# ---------------------------------------------------------------------------

def cmd_learn(args):
    """Learn, validate and save parsers for the unknown formats in a log file."""
    from ulpf.engine.pipeline import Pipeline

    if not os.path.isfile(args.file):
        print(f"File not found: {args.file}")
        return 1
    with open(args.file, "r", encoding="utf-8", errors="replace") as f:
        lines = [l.rstrip("\n") for l in f]

    pipeline = Pipeline()
    engine = pipeline.auto_engine

    def is_known(line: str) -> bool:
        if args.all_lines:
            return False
        parser = pipeline.registry.get_parser_for_format(pipeline._detect(line)["format_name"])
        return parser is not None and parser.parse(line) is not None

    report = engine.learn(lines, is_known=is_known, save=not args.dry_run, min_group=args.min_samples)
    pipeline.close()

    print(f"\n  Lines analysed  : {report['total_lines']}")
    print(f"  Known formats   : {report['known_lines']} (handled by built-in parsers)")
    print(f"  Unknown lines   : {report['unknown_lines']}")
    if report.get("error"):
        print(f"\n  {report['error']}")
        return 1
    print(f"  Covered by new  : {report['covered_lines']} ({report.get('coverage_pct', 0)}%)")
    for a in report["accepted"]:
        spec = a["spec"]
        print(f"\n  [ACCEPTED] {a['parser_id']}  family={a['family']}  accuracy={a['accuracy']:.1%}  "
              f"parse={a['parse_time_ms']:.3f}ms  samples={a['lines']}")
        print(f"    Template : {a['template'][:160]}")
        print(f"    Saved to : {a['saved_to'] or '(dry run, not saved)'}")
        for fld in spec.fields:
            print(f"      {fld.name:28s} type={fld.field_type:10s} position={fld.position}")
    for r in report["rejected"]:
        print(f"\n  [REJECTED] fingerprint={r['fingerprint']} lines={r['lines']}: {r['reason']}")
    return 0 if report["accepted"] else 1


def cmd_fingerprint(args):
    from ulpf.intelligence.log_dna import LogDNA
    if not os.path.isfile(args.file):
        print(f"File not found: {args.file}")
        return 1
    with open(args.file, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    dna = LogDNA()
    label = args.label or os.path.basename(args.file)
    # Earlier fingerprints of the same source, oldest first
    previous = [fid for fid, stored in dna.database.items() if stored.get("source_label") == label]
    fp = dna.fingerprint(lines, source_label=label)
    drift = None
    if previous and fp.fingerprint_id not in previous:
        drift = dna.detect_drift(previous[-1], lines)
    fid = dna.register(fp)
    d = fp.to_dict()
    print("  Log DNA Fingerprint Generated!")
    print(f"  Fingerprint ID : {fid}")
    print(f"  Field count    : {d['field_count']}")
    print(f"  Type signature : {d['field_type_signature']}")
    print(f"  Delimiter      : {d['delimiter']}")
    print(f"  Entropy        : {d['entropy']}")
    print(f"  Avg line length: {d['avg_line_length']}")
    print(f"  Source label   : {d['source_label']}")
    if drift is not None and "error" not in drift:
        status = "DETECTED" if drift["drift_detected"] else "none"
        print(f"  Format drift   : {status} vs {drift['original_fingerprint']} "
              f"(similarity {drift['similarity_score']})")
        for change in drift["changes"]:
            print(f"    {change['field']}: {change['old']} -> {change['new']}")
    elif previous:
        print("  Format drift   : none (same structure as the stored fingerprint)")
    print(f"  Stored in      : {dna.db_path}")
    return 0


# ---------------------------------------------------------------------------
# serve / tui / gui / desktop / benchmark
# ---------------------------------------------------------------------------

def cmd_serve(args):
    try:
        import uvicorn
    except ImportError:
        print("FastAPI/Uvicorn not installed. Install with: pip install fastapi uvicorn[standard] python-multipart")
        return 1
    from ulpf.api.app import create_app
    auth = "API key required (ULPF_API_KEY)" if os.environ.get("ULPF_API_KEY") else "no authentication"
    print(f"Starting ULPF API server on http://{args.host}:{args.port}  (docs: /docs, {auth})")
    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="info")
    return 0


def cmd_tui(args):
    from ulpf.tui.tui_app import launch_tui
    launch_tui(mode=getattr(args, "mode", "auto"))


def cmd_desktop(args):
    try:
        from ulpf.gui.qt_app import main
    except ImportError as e:
        print(f"PySide6 not available ({e}). Install with: pip install PySide6")
        return 1
    main()
    return 0


def cmd_benchmark(args):
    try:
        from benchmarks.suite import BenchmarkRunner
    except ImportError:
        # benchmarks/ is not part of the installed package
        print("The benchmark suite ships with the source tree, not the installed package: "
              "run `python -m ulpf.main benchmark` from a ULPF checkout.", file=sys.stderr)
        return 2
    runner = BenchmarkRunner(num_events=args.events, seed=args.seed)
    print(f"\n{'=' * 60}\n  ULPF PERFORMANCE BENCHMARK\n{'=' * 60}")
    hw = runner.get_hardware_info()
    print(f"  Platform : {hw['platform']}")
    print(f"  CPU      : {hw['processor']}")
    print(f"  Cores    : {hw.get('cpu_count_logical', os.cpu_count())}")
    print(f"  Python   : {hw.get('python_version', 'Unknown')}")
    print(f"  Events   : {args.events:,}")
    all_results = {"hardware": hw, "pipeline": runner.run_pipeline_benchmark(num_workers=args.workers)}
    if args.db_bench:
        all_results["database"] = runner.run_database_benchmark()
    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(all_results, f, indent=2, default=str)
        print(f"\n  Results exported to: {args.output}")
    print(f"\n{'=' * 60}\n  BENCHMARK COMPLETE\n{'=' * 60}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ulpf", description="ULPF — Universal Log Pre-processing Framework")
    parser.add_argument("--db", metavar="PATH", help="Event store path (overrides ULPF_DB_PATH)")
    parser.add_argument("--log-level", default=os.environ.get("ULPF_LOG_LEVEL", "WARNING"),
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("process", help="Process log files (globs allowed)")
    p.add_argument("--files", "-f", nargs="+", required=True, help="Log file paths or globs")
    p.add_argument("--output", "-o", help="Also write normalised events to this JSON file")
    p.add_argument("--correlate", action="store_true", help="Run streaming correlation and report groups")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--siem-forward", metavar="HOST:PORT", help="Forward events to a SIEM as RFC 5424 syslog")
    p.add_argument("--siem-proto", choices=["udp", "tcp"], default="udp")

    p = sub.add_parser("listen", help="Real-time syslog listener (multiprocess)")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", "-p", type=int, default=5514)
    p.add_argument("--protocol", choices=["udp", "tcp", "both"], default="both")
    p.add_argument("--workers", "-w", type=int, default=None, help="Worker processes (default: CPU count - 1)")
    p.add_argument("--siem-forward", metavar="HOST:PORT")

    p = sub.add_parser("correlate", help="Correlate stored events")
    p.add_argument("--limit", type=int, default=1000)
    p.add_argument("--window", type=float, default=60.0, help="Time window in seconds")
    p.add_argument("--output", "-o")

    p = sub.add_parser("forensic", help="Build, list or verify forensic evidence chains")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--description", "-d")
    p.add_argument("--tags", "-t", help="Comma-separated tags")
    p.add_argument("--verify", metavar="PACKAGE_JSON", help="Verify an exported evidence package")
    p.add_argument("--list", action="store_true", help="List stored chains")

    p = sub.add_parser("learn", help="Auto-learn parsers for unknown formats in a file")
    p.add_argument("--file", "-f", required=True)
    p.add_argument("--min-samples", type=int, default=2, help="Minimum lines per structure (default 2)")
    p.add_argument("--all-lines", action="store_true", help="Also learn lines built-in parsers already handle")
    p.add_argument("--dry-run", action="store_true", help="Validate and report without saving")

    p = sub.add_parser("fingerprint", help="Generate a Log DNA fingerprint")
    p.add_argument("--file", "-f", required=True)
    p.add_argument("--label", "-l")

    p = sub.add_parser("serve", help="Start the REST API server")
    p.add_argument("--host", default=os.environ.get("ULPF_API_HOST", "127.0.0.1"))
    p.add_argument("--port", "-p", type=int, default=8000)

    p = sub.add_parser("tui", help="Terminal dashboard (headless-safe)")
    p.add_argument("--mode", choices=["auto", "rich", "textual"], default="auto")
    sub.add_parser("desktop", help="Native PySide6 desktop application")

    p = sub.add_parser("purge", help="Data retention: delete old or unclassified events")
    p.add_argument("--older-than-days", type=float, help="Delete events older than N days")
    p.add_argument("--by", choices=["ingested_at", "timestamp"], default="ingested_at",
                   help="Age by arrival time (default) or by normalised event time")
    p.add_argument("--raw-fallback", action="store_true", help="Delete events no parser recognised")

    p = sub.add_parser("export-ml", help="Export an ML-ready feature matrix (CSV or Parquet)")
    p.add_argument("--output", "-o", default="output/ml_features.csv")
    p.add_argument("--format", choices=["csv", "parquet"], help="Default: from the output extension")
    p.add_argument("--limit", "-n", type=int, default=10000)

    p = sub.add_parser("benchmark", help="Run performance benchmarks")
    p.add_argument("--events", "-n", type=int, default=10000)
    p.add_argument("--workers", "-w", type=int, default=None)
    p.add_argument("--db-bench", action="store_true")
    p.add_argument("--output", "-o")
    p.add_argument("--seed", type=int, default=42)

    from ulpf.cli_runtime import register
    COMMANDS.update(register(sub))
    from ulpf.cli_v10 import register as register_v10
    COMMANDS.update(register_v10(sub))
    return parser


COMMANDS = {
    "process": cmd_process, "listen": cmd_listen, "correlate": cmd_correlate,
    "forensic": cmd_forensic, "learn": cmd_learn, "fingerprint": cmd_fingerprint,
    "serve": cmd_serve, "tui": cmd_tui, "desktop": cmd_desktop,
    "benchmark": cmd_benchmark, "export-ml": cmd_export_ml, "purge": cmd_purge,
}


def main(argv: list[str] | None = None) -> int:
    import multiprocessing
    multiprocessing.freeze_support()

    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level),
                        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s", datefmt="%H:%M:%S")
    if args.db:
        os.environ["ULPF_DB_PATH"] = os.path.abspath(args.db)
    if args.command not in COMMANDS:
        parser.print_help()
        return 0

    from ulpf.storage.database import DatabaseLockedError
    try:
        return COMMANDS[args.command](args) or 0
    except DatabaseLockedError as e:
        print(f"Error: {e}")
        return 3
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
