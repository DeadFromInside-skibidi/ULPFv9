"""
CLI commands for the v9 runtime:

    ulpf run [--config pipeline.yaml]          run the live pipeline (inputs → outputs)
    ulpf config check|show|example [FILE]      validate a config and show what it opens
    ulpf raw get (--seq N | --event-id ID)     original bytes of a journaled record
    ulpf evidence verify|list|prove|pubkey     check seals against the journal (and store)
    ulpf airgap os-policy|os-check             kernel-level egress policy (Linux)
    ulpf sigma list|check|test                 Sigma rules and ATT&CK detections
    ulpf compliance dpdp|cbam ...              DPDP erasure / breach packs, CBAM data packs
    ulpf parsers list|approve|reject           learned parsers and defence-mode approval
    ulpf audit verify                          check the hash-chained audit log
    ulpf dlq list [--sink NAME]                dead-lettered events
    ulpf source onboard --name N --sample F    learn a new source from a sample, add it to the config
    ulpf plugins list                          installed parser plugins and their package hashes
    ulpf schema diff|export|versions           unified schema registry and compatibility check
"""
from __future__ import annotations

import json
import os
import time
import sys


def _data_dir(args) -> str:
    from ulpf.platform.paths import get_data_dir
    return getattr(args, "data_dir", None) or str(get_data_dir())


def _load_cfg(path: str | None, mode: str | None = None):
    from ulpf.config import ConfigError, default_config, format_issues, load_pipeline_config
    try:
        if path:
            cfg = load_pipeline_config(path)
        else:
            cfg = load_pipeline_config(data=default_config(mode or "industry"))
    except ConfigError as e:
        print(format_issues(e, path), file=sys.stderr)
        return None
    except FileNotFoundError:
        print(f"config file not found: {path}", file=sys.stderr)
        return None
    return cfg


def _print_report(report: dict) -> None:
    print(f"  mode       : {report['mode']}")
    print(f"  inputs     : {', '.join(report['inputs']) or '-'}")
    print(f"  outputs    : {', '.join(report['outputs']) or '-'}")
    print("  listening  :" + ("" if report["listeners"] else " nothing"))
    for l in report["listeners"]:
        print(f"    - {l}")
    print("  connects to:" + ("" if report["remote_destinations"] else " nothing (no outbound traffic)"))
    for r in report["remote_destinations"]:
        print(f"    - {r}")
    for w in report["waived_rules"]:
        print(f"  WAIVED     : {w}")
    for w in report["warnings"]:
        print(f"  WARNING    : {w}")


# ---------------------------------------------------------------------------

def cmd_run(args) -> int:
    from ulpf.config import describe
    from ulpf.runtime.supervisor import Runtime
    cfg = _load_cfg(args.config, args.mode)
    if cfg is None:
        return 2
    if args.data_dir:
        cfg.data["node"]["data_dir"] = os.path.abspath(args.data_dir)
    print(f"\n{'=' * 64}\n  ULPF runtime\n{'=' * 64}")
    _print_report(describe(cfg))
    rt = Runtime(cfg, api=False if args.no_api else None)
    rt.start()
    print(f"  node       : {rt.node}\n  data dir   : {rt.data_dir}\n  workers    : {rt.dispatcher.n}")
    print("  egress     : " + ("ENFORCED - only loopback and airgap.allow can be reached"
                               if rt.egress and rt.egress.enforce else
                               "recorded - every outbound destination is listed in /api/v1/runtime/status"))
    if rt.api_server is not None:
        print(f"  api        : {rt.api_server.url}")
    print(f"{'=' * 64}\n  Running. Press Ctrl+C to stop (queued data is drained first).\n")
    rt.run_forever()
    return 0


def cmd_config(args) -> int:
    from ulpf.config import describe
    if args.action == "example":
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "config", "pipeline.example.yaml")
        with open(path, "r", encoding="utf-8") as f:
            print(f.read())
        return 0
    cfg = _load_cfg(args.file)
    if cfg is None:
        return 2
    if args.action == "show":
        print(json.dumps(cfg.data, indent=2, default=str))
        return 0
    print(f"{args.file or '(built-in default)'}: OK")
    _print_report(describe(cfg))
    return 0


def _open_journal_ro(data_dir: str):
    from ulpf.runtime.journal import Journal
    key_path = os.path.join(data_dir, "journal.key")
    key = None
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            key = f.read()
    return Journal(os.path.join(data_dir, "journal"), key=key, read_only=True)


def _seq_for_event(event_id: str, data_dir: str) -> int | None:
    from ulpf.storage.database import Database
    from ulpf.platform.paths import get_db_path
    db = Database(str(get_db_path()), read_only=True)
    try:
        row = db.conn.execute("SELECT normalised_json FROM events WHERE event_id = ?", [event_id]).fetchone()
    finally:
        db.close()
    if not row:
        return None
    return (json.loads(row[0]).get("evidence") or {}).get("journal_seq")


def cmd_raw(args) -> int:
    data_dir = _data_dir(args)
    seq = args.seq
    if seq is None:
        try:
            seq = _seq_for_event(args.event_id, data_dir)
        except Exception as e:
            print(f"could not read the event store ({e}); if `ulpf run` is active use "
                  f"GET /api/v1/events/{args.event_id}/raw", file=sys.stderr)
            return 3
        if seq is None:
            print(f"event {args.event_id} not found, or it predates the journal", file=sys.stderr)
            return 1
    j = _open_journal_ro(data_dir)
    rec = j.read(int(seq))
    if rec is None:
        print(f"record {seq} is not in the journal (never written, or removed by retention)", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps({"seq": rec.seq, "received_at": rec.recv_ts, "source": rec.source,
                          "input": rec.input, "sha256": rec.sha256_hex,
                          "raw": rec.raw.decode("utf-8", "replace")}, indent=2))
    else:
        sys.stdout.buffer.write(rec.raw + b"\n")
    return 0


def cmd_evidence(args) -> int:
    from ulpf.runtime.evidence import identity_pub_path, load_seals, verify_seals, inclusion_proof, leaf
    from ulpf.runtime import keys
    if args.action == "escrow-keygen":
        out = args.out or "."
        priv, pub = keys.generate_escrow_keypair(out, passphrase=keys.passphrase_from_env())
        print(f"escrow private key: {priv}   (keep with the auditor, off this host)")
        print(f"escrow public key : {pub}   (set evidence.row_key_escrow to this file before the first run)")
        return 0
    data_dir = _data_dir(args)
    ev_dir = os.path.join(data_dir, "evidence")
    seal_dir = os.path.join(ev_dir, "seals")
    if args.action == "pubkey":
        path = identity_pub_path(ev_dir)
        if not os.path.exists(path):
            print("no evidence identity key yet (run `ulpf run` with evidence enabled)", file=sys.stderr)
            return 1
        with open(path, "rb") as f:
            pem = f.read()
        print(f"# Ed25519 evidence identity, fingerprint {keys.fingerprint(keys.load_public_key(pem))}")
        sys.stdout.write(pem.decode())
        return 0
    if not os.path.isdir(seal_dir):
        print("no evidence seals yet (run `ulpf run` with evidence enabled)")
        return 1
    if args.action == "list":
        for s in load_seals(seal_dir)[-args.limit:]:
            print(f"{s['first_seq']:>12}..{s['last_seq']:<12} {s['count']:>7} records  root {s['merkle_root'][:20]}  "
                  f"seal {s['seal_hash'][:16]}")
        return 0
    # Pre-9.1 seals were HMAC'd with evidence.key; current seals need only public keys
    legacy_path = os.path.join(ev_dir, "evidence.key")
    key = None
    if os.path.exists(legacy_path):
        with open(legacy_path, "rb") as f:
            key = f.read()
    j = _open_journal_ro(data_dir)
    if args.action == "prove":
        seal = next((s for s in load_seals(seal_dir) if s["first_seq"] <= args.seq <= s["last_seq"]), None)
        if seal is None:
            print(f"record {args.seq} is not sealed yet", file=sys.stderr)
            return 1
        leaves = []
        for seq in range(seal["first_seq"], seal["last_seq"] + 1):
            r = j.read(seq)
            leaves.append(leaf(seq, r.sha256))
        idx = args.seq - seal["first_seq"]
        print(json.dumps({"seq": args.seq, "leaf": leaves[idx].hex(), "seal_hash": seal["seal_hash"],
                          "merkle_root": seal["merkle_root"], "proof": inclusion_proof(leaves, idx)}, indent=2))
        return 0
    db = None
    if args.check_store:
        try:
            from ulpf.storage.database import Database
            from ulpf.platform.paths import get_db_path
            db = Database(str(get_db_path()), read_only=True)
        except Exception as e:
            print(f"store not checked ({e})")
    row_key = None
    if args.row_key:
        try:
            row_key = keys.load_row_key(args.row_key, args.escrow_key)
        except (OSError, ValueError) as e:
            print(f"row key: {e}", file=sys.stderr)
            return 2
    try:
        result = verify_seals(seal_dir, j, key, database=db, from_seq=args.from_seq, to_seq=args.to_seq,
                              pubkey=args.pubkey, row_key=row_key)
    except (OSError, ValueError) as e:
        print(f"public key: {e}", file=sys.stderr)
        return 2
    if db is not None:
        db.close()
    print(f"seals: {result['seals']}  signatures checked: {result['signatures_checked']}  "
          f"records checked: {result['records_checked']}  stored events checked: {result['events_checked']}")
    if not result["anchor_pinned"]:
        print("WARNING: no identity public key (evidence.pub / --pubkey): signing chains checked against "
              "the keys they carry")
    if result["row_macs_unchecked"]:
        print(f"note: {result['row_macs_unchecked']} row MAC(s) not checked: their epoch keys were erased "
              "on this host; pass --row-key (K_0) to check them")
    for n in result["notes"][:20]:
        print(f"note: {n}")
    if result["valid"]:
        print("VALID: every seal matches the journal" + (" and the store" if db is not None else ""))
        return 0
    print(f"INVALID ({len(result['problems'])} problem(s)):")
    for p in result["problems"][:50]:
        print(f"  - {p}")
    return 1


def cmd_parsers(args) -> int:
    from ulpf.intelligence.auto_parser.engine import AutoParserEngine
    from ulpf.runtime.supervisor import learned_dir
    eng = AutoParserEngine(learned_dir=learned_dir(_data_dir(args)))
    try:
        if args.action == "list":
            specs = sorted(eng.registry.list_parsers(), key=lambda s: (s.state, s.parser_id))
            if not specs:
                print("no learned parsers")
            for s in specs:
                acc = s.metadata.get("validation_accuracy")
                print(f"{s.parser_id:22s} {s.state:17s} {s.source_family:22s} "
                      f"acc={acc if acc is not None else '-'}  {s.template[:70]}")
            return 0
        fn = eng.approve if args.action == "approve" else eng.reject
        spec = fn(args.parser_id, operator=os.environ.get("USERNAME") or os.environ.get("USER") or "operator")
        _audit(args, f"parser.{args.action}", {"parser_id": spec.parser_id, "state": spec.state})
        print(f"{spec.parser_id}: {spec.state}")
        return 0
    except (KeyError, ValueError) as e:
        print(str(e), file=sys.stderr)
        return 1
    finally:
        eng.stop()


def _audit(args, action: str, details: dict) -> None:
    from ulpf.runtime.audit import AuditLog
    actor = os.environ.get("USERNAME") or os.environ.get("USER") or "operator"
    AuditLog(os.path.join(_data_dir(args), "audit", "audit.log")).record(action, details, actor=f"cli:{actor}")


def cmd_lake(args) -> int:
    """Lakehouse outputs: status, federated query, compaction, commit-chain verification."""
    import datetime as _dt
    cfg = _load_cfg(args.config)
    if cfg is None:
        return 2
    outs = [o for o in cfg.outputs() if o["type"] == "lakehouse" and (not args.output or o["name"] == args.output)]
    if len(outs) != 1:
        print("name one lakehouse output with --output" if outs else "no lakehouse output in the config",
              file=sys.stderr)
        return 2
    from ulpf.lake.service import LakeService
    svc = LakeService(outs[0]["name"], outs[0], cfg.data.get("node", {}).get("data_dir") or _data_dir(args))
    if args.action == "status":
        print(json.dumps(svc.status(), indent=1))
    elif args.action == "verify":
        r = svc.table.verify()
        print(f"VALID: {r['commits']} commits, head MAC {r['head_mac'][:16]}")
    elif args.action == "compact":
        print(f"replaced {svc.compact_once(force=args.force)} files")
    else:
        ts = (lambda s: _dt.datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None)
        eq = dict(x.split("=", 1) for x in args.eq or [])
        table, stats = svc.query.run(args.sql, args.tenant, ts(args.start), ts(args.end), eq, args.max_rows)
        for row in table.to_pylist():
            print(json.dumps(row, default=str))
        print(json.dumps(stats), file=sys.stderr)
    return 0


def cmd_audit(args) -> int:
    from ulpf.runtime.audit import verify_audit_log
    path = os.path.join(_data_dir(args), "audit", "audit.log")
    if not os.path.exists(path):
        print("no audit log yet")
        return 1
    r = verify_audit_log(path)
    if r["valid"]:
        print(f"VALID: {r['entries']} entries, head {r['head'][:16]}")
        return 0
    print(f"INVALID: chain broken at line {r['broken_at_line']} (after {r['entries']} valid entries)")
    return 1


def cmd_dlq(args) -> int:
    from ulpf.runtime.dlq import DeadLetterQueue
    d = os.path.join(_data_dir(args), "dlq")
    if not os.path.isdir(d):
        print("dead-letter queue is empty")
        return 0
    for r in DeadLetterQueue(d).read(args.sink, args.limit):
        print(json.dumps(r, default=str))
    return 0


def cmd_plugins(args) -> int:
    from ulpf.parsers.plugins import discover, policy_from_config
    policy = {"enabled": True, "allow": None}
    if args.config:
        cfg = _load_cfg(args.config)
        if cfg is None:
            return 2
        policy = policy_from_config(cfg.data)
    infos = discover(policy)
    if args.json:
        print(json.dumps([i.to_dict() for i in infos], indent=2))
        return 0
    if not infos:
        print("no parser plugins installed (entry-point group 'ulpf.parsers')")
        return 0
    for i in infos:
        status = "loaded" if i.loaded else f"not loaded: {i.error}"
        print(f"{i.name:20s} {i.distribution or '?'} {i.version or ''}\n  target : {i.target}\n"
              f"  sha256 : {i.sha256}\n  status : {status}")
    return 0


def cmd_schema(args) -> int:
    from ulpf.engine import schema_registry as reg
    if args.action == "export":
        doc = reg.export(args.old)
        if not args.old:
            print(json.dumps(doc, indent=2))
        else:
            print(f"schema {doc['version']} ({len(doc['fields'])} fields) written to {args.old}")
        return 0
    if args.action == "versions":
        for v in reg.versions():
            print(v)
        return 0
    try:
        old, new = reg.load(args.old or reg.versions()[-1]), reg.load(args.new or "current")
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return 2
    d = reg.diff(old, new)
    if args.json:
        print(json.dumps(d, indent=2))
    else:
        print(f"schema {d['old']} -> {d['new']}: {len(d['added'])} added, {len(d['removed'])} removed, "
              f"{len(d['type_changed'])} retyped")
        for f in d["added"]:
            print(f"  + {f}")
        for f in d["removed"]:
            print(f"  - {f}   (breaking)")
        for c in d["type_changed"]:
            print(f"  ~ {c['field']}: {c['old']} -> {c['new']}   (breaking)")
        for p in d["problems"]:
            print(f"  INCOMPATIBLE: {p}")
        if d["compatible"]:
            print("  compatible")
    return 0 if d["compatible"] else 1


def onboard_source(name: str, lines: list[str], mode: str, learned: str) -> dict:
    """Measure built-in coverage of a sample, learn parsers for the rest, re-measure."""
    import time as _time
    from ulpf.engine.pipeline import Pipeline
    from ulpf.intelligence.auto_parser.engine import AutoParserEngine
    t0 = _time.perf_counter()
    clean = [l.rstrip("\r\n") for l in lines if l.strip()]
    pipe = Pipeline(enable_auto_parser=False)
    formats: dict[str, int] = {}
    known = set()
    for i, l in enumerate(clean):
        r = pipe.process_line(l)
        fmt = r["event"]["raw_format"] if r.get("success") else "error"
        formats[fmt] = formats.get(fmt, 0) + 1
        if fmt not in ("raw_fallback", "error"):
            known.add(l)
    eng = AutoParserEngine(learned_dir=learned)
    try:
        state = "pending_approval" if mode == "defence" else "active"
        report = eng.learn(clean, is_known=lambda l: l in known, save=True, state=state, source=name)
    finally:
        eng.stop()
    covered = report.get("covered_lines", 0)
    total = len(clean)
    return {"source": name, "mode": mode, "lines": total, "builtin_formats": formats,
            "builtin_coverage_pct": round(len(known) / total * 100, 1) if total else 0.0,
            "learned": [{"parser_id": a["parser_id"], "template": a["template"], "accuracy": a["accuracy"],
                         "lines": a["lines"], "state": state, "fields": [f.name for f in a["spec"].fields]}
                        for a in report.get("accepted", [])],
            "rejected": report.get("rejected", []),
            "total_coverage_pct": round((len(known) + covered) / total * 100, 1) if total else 0.0,
            "elapsed_seconds": round(_time.perf_counter() - t0, 3)}


def _input_entry(args) -> dict:
    entry = {"type": args.input_type, "name": args.name}
    if args.input_type == "file":
        entry.update(paths=[args.path or "<path to the live log>"], start_from="end")
    elif args.input_type == "syslog":
        entry.update(protocol=args.protocol, host=args.host, port=args.port)
    entry["tags"] = [f"source:{args.name}"]
    return entry


def _yaml_item(entry: dict, indent: str = "  ") -> str:
    import yaml
    body = yaml.safe_dump([entry], sort_keys=False, default_flow_style=False).rstrip("\n").splitlines()
    return "\n".join(indent + l for l in body) + "\n"


def add_input_to_config(path: str, entry: dict) -> None:
    """Insert an input under ``inputs:`` keeping the rest of the file (and its comments) unchanged."""
    import re
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    m = re.search(r"^inputs:[ \t]*(\[\s*\])?[ \t]*(#.*)?$", text, re.M)
    if m and m.group(1) is None:
        pos = m.end() + 1
        text = text[:pos] + _yaml_item(entry) + text[pos:]
    elif m:      # inputs: []
        text = text[:m.start()] + "inputs:\n" + _yaml_item(entry) + text[m.end() + 1:]
    else:
        text = text.rstrip("\n") + "\n\ninputs:\n" + _yaml_item(entry)
    from ulpf.config import load_pipeline_config
    load_pipeline_config(text=text)          # never write a config that does not validate
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    os.replace(tmp, path)


def cmd_source(args) -> int:
    from ulpf.runtime.supervisor import learned_dir
    from ulpf.config import ConfigError, format_issues
    if not os.path.isfile(args.sample):
        print(f"sample not found: {args.sample}", file=sys.stderr)
        return 2
    mode = args.mode
    if args.config and not mode:
        cfg = _load_cfg(args.config)
        if cfg is None:
            return 2
        mode = cfg.mode
    mode = mode or "industry"
    with open(args.sample, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    rep = onboard_source(args.name, lines, mode, learned_dir(_data_dir(args)))
    if args.json:
        print(json.dumps(rep, indent=2, default=str))
    else:
        print(f"\n  source            : {rep['source']} ({rep['mode']} mode)")
        print(f"  sample lines      : {rep['lines']}")
        print(f"  built-in formats  : {', '.join(f'{k}={v}' for k, v in rep['builtin_formats'].items())}")
        print(f"  built-in coverage : {rep['builtin_coverage_pct']}%")
        for p in rep["learned"]:
            print(f"  learned parser    : {p['parser_id']} ({p['state']}, accuracy {p['accuracy']:.1%}, "
                  f"{p['lines']} lines)\n    template : {p['template'][:150]}\n"
                  f"    fields   : {', '.join(p['fields'])}")
        for r in rep["rejected"][:5]:
            print(f"  not learned       : {r['lines']} line(s): {r['reason']}")
        print(f"  total coverage    : {rep['total_coverage_pct']}%")
        print(f"  elapsed           : {rep['elapsed_seconds']} s")
        if mode == "defence" and rep["learned"]:
            print("  approval needed   : " + "; ".join(f"ulpf parsers approve {p['parser_id']}" for p in rep["learned"]))
    entry = _input_entry(args)
    if args.config and args.write_config:
        try:
            add_input_to_config(args.config, entry)
        except ConfigError as e:
            print(format_issues(e, args.config), file=sys.stderr)
            return 2
        print(f"  config            : input {args.name!r} added to {args.config}")
    elif not args.json:
        print("\n  input entry (add under inputs:, or rerun with --config FILE --write-config):\n")
        print(_yaml_item(entry))
    _audit(args, "source.onboard", {"source": args.name, "mode": mode, "coverage_pct": rep["total_coverage_pct"],
                                     "parsers": [p["parser_id"] for p in rep["learned"]]})
    return 0 if rep["total_coverage_pct"] > 0 else 1


def cmd_cluster(args) -> int:
    from ulpf.runtime.cluster import status
    cfg = _load_cfg(args.config)
    if cfg is None:
        return 2
    if not cfg["cluster"]["enabled"]:
        print("cluster mode is not enabled in this config", file=sys.stderr)
        return 2
    st = status(cfg.data)
    if args.json:
        print(json.dumps(st, indent=2))
        return 0
    print(f"shared dir : {st['shared_dir']}")
    for n in st["nodes"]:
        age = "never" if n["last_heartbeat_age_s"] is None else f"{n['last_heartbeat_age_s']}s ago"
        print(f"  {n['node']:20s} {'ALIVE' if n['alive'] else 'down ':5s} heartbeat {age:12s} "
              f"{n['address'] or '-'}  inputs: {', '.join(n['running_inputs']) or '-'}")
    print("assignments (placement: one):")
    for name, node in sorted(st["assignments"].items()):
        print(f"  {name:20s} -> {node or 'NO LIVE NODE'}")
    return 0 if st["alive"] else 1


def cmd_apikey(args) -> int:
    from ulpf.api.auth import new_key
    path = args.keys_file or os.environ.get("ULPF_API_KEYS_FILE")
    if not path and args.config:
        cfg = _load_cfg(args.config)
        if cfg is None:
            return 2
        path = cfg.get("api.keys_file")
    if not path:
        print("no keys file: pass --keys-file, set api.keys_file in --config, or ULPF_API_KEYS_FILE",
              file=sys.stderr)
        return 2
    key = new_key(path, args.name, args.role)
    _audit(args, "apikey.new", {"name": args.name, "role": args.role, "keys_file": path})
    print(f"{args.role} key for {args.name!r} (shown once; only its SHA-256 is stored in {path}):\n{key}")
    return 0


def cmd_reload(args) -> int:
    import urllib.error
    import urllib.request
    key = os.environ.get(args.key_env) if args.key_env else None
    req = urllib.request.Request(args.url.rstrip("/") + "/api/v1/runtime/reload", method="POST", data=b"",
                                 headers={"X-API-Key": key} if key else {})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            res = json.loads(r.read())
    except urllib.error.HTTPError as e:
        print(f"reload failed: HTTP {e.code}: {e.read().decode(errors='replace')}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"cannot reach the runtime API at {args.url}: {e}", file=sys.stderr)
        return 1
    print(json.dumps(res, indent=2))
    return 0 if res.get("reloaded") else 1


def cmd_intel(args) -> int:
    """Threat-intelligence platform: import feeds, sync, rebuild the match set, look up indicators."""
    from ulpf.intelligence.tip.service import TipService, import_file
    cfg = _load_cfg(args.config) if args.config else None
    if args.config and cfg is None:
        return 2
    data_dir = args.data_dir or (cfg.get("node.data_dir") if cfg else None) or _data_dir(args)
    intel = dict((cfg.get("intel") if cfg else None) or {})
    try:
        svc = TipService(data_dir, intel, mode=cfg.mode if cfg else "industry",
                         airgap_allow=cfg["airgap"]["allow"] if cfg else [])
    except (ValueError, PermissionError) as e:
        print(f"intel: {e}", file=sys.stderr)
        return 2
    try:
        act = args.action
        if act.startswith("import-"):
            if not args.file:
                print("--file is required", file=sys.stderr)
                return 2
            typ = {"import-stix": "stix_file", "import-misp": "misp_file", "import-otx": "otx_file"}[act]
            res = import_file(svc.store, typ, args.file, args.name)
            res["snapshot"] = svc.build()
            print(json.dumps(res, indent=2, default=str))
            return 0
        if act == "sync":
            res = svc.sync(args.name, force=True)
            res["snapshot"] = svc.build()
            print(json.dumps(res, indent=2, default=str))
            return 1 if any(isinstance(v, dict) and v.get("error") for v in res.values()) else 0
        if act == "build":
            print(json.dumps(svc.build(), indent=2))
            return 0
        if act == "sight":
            if not args.value:
                print("give an indicator value", file=sys.stderr)
                return 2
            print(json.dumps({"updated": svc.store.sight(args.kind, args.value)}))
            return 0
        if act == "lookup":
            if not args.value:
                print("give an indicator value", file=sys.stderr)
                return 2
            rows = svc.store.lookup(args.value)
            print(json.dumps(rows, indent=2, default=str))
            return 0 if rows else 1
        print(json.dumps(svc.stats(), indent=2, default=str))
        return 0
    except (OSError, ValueError) as e:
        print(f"intel {args.action}: {e}", file=sys.stderr)
        return 1
    finally:
        svc.stop()


def cmd_sigma(args) -> int:
    from ulpf.intelligence.sigma import SigmaEngine, engine_from_config, load_rules
    if args.action == "check":
        if not args.files:
            print("give rule files or directories to check", file=sys.stderr)
            return 2
        rules, errors = load_rules(args.files, builtin=False)
        for r in rules:
            print(f"ok     {r.id:40s} {r.level:8s} {','.join(r.techniques) or '-':20s} {r.title}")
        for e in errors:
            print(f"ERROR  {e}")
        print(f"{len(rules)} rule(s) compiled, {len(errors)} error(s)")
        return 1 if errors else 0
    if args.config:
        from ulpf.config import load_pipeline_config
        eng = engine_from_config(load_pipeline_config(args.config).data)
        if eng is None:
            print("analytics.sigma is disabled in this config", file=sys.stderr)
            return 1
    else:
        eng = SigmaEngine.load(args.files, builtin=not args.no_builtin)
    if args.action == "list":
        if args.json:
            print(json.dumps([r.to_dict() for r in eng.rules], indent=2))
        else:
            for r in eng.rules:
                agg = " (aggregation)" if r.aggregation else ""
                print(f"{r.id:40s} {r.level:8s} {','.join(r.techniques) or '-':22s} {r.title}{agg}")
        for e in eng.errors:
            print(f"ERROR  {e}", file=sys.stderr)
        return 0
    # test: run a log file through the pipeline and the rules
    from ulpf.engine.pipeline import Pipeline
    from ulpf.intelligence.correlation import EventCorrelator
    if not args.log:
        print("sigma test needs --log FILE", file=sys.stderr)
        return 2
    pipeline = Pipeline(enable_auto_parser=False)
    corr = EventCorrelator(args.window, sigma=eng)
    n = 0
    for batch in pipeline.iter_file(args.log):
        for res in batch:
            if res.get("success"):
                corr.correlate_event(res["event"])
                n += 1
    dets = [d.to_dict() for d in corr.detections]
    groups = [g for g in corr.get_results() if g["event_count"] > 1]
    if args.json:
        print(json.dumps({"events": n, "detections": dets, "groups": groups}, indent=2, default=str))
        return 0
    print(f"{n} events, {len(dets)} detection(s), {len(groups)} correlated group(s)")
    for d in dets:
        print(f"  {d['timestamp']}  {d['level']:8s} {','.join(d['techniques']) or '-':18s} {d['title']}"
              f"  key={d['key'] or '-'} count={d['count']}")
    for g in groups[:20]:
        tech = ", ".join(t["id"] for t in g["mitre"]["techniques"]) or "-"
        print(f"  group {g['correlation_id']}: {g['event_count']} events, risk {g['risk_score']}, "
              f"stages {','.join(g['kill_chain_stages']) or '-'}, ATT&CK {tech}")
    return 0


def _store_path(args) -> str:
    from ulpf.platform.paths import get_db_path
    return args.store or str(get_db_path())


def _open_writable(args):
    """(data dir, node id, store, journal) for offline compliance work; None if ULPF is running."""
    from ulpf.runtime.ids import node_id
    from ulpf.runtime.journal import Journal
    from ulpf.storage.database import Database
    data_dir = _data_dir(args)
    db = Database(_store_path(args))
    if db.read_only:
        db.close()
        print("the event store is in use (ulpf run is active): use the API "
              "(POST /api/v1/compliance/dpdp/erase) or stop the runtime", file=sys.stderr)
        return None
    key = None
    kp = os.path.join(data_dir, "journal.key")
    if os.path.exists(kp):
        with open(kp, "rb") as f:
            key = f.read()
    jdir = os.path.join(data_dir, "journal")
    journal = Journal(jdir, key=key, sync="always") if os.path.isdir(jdir) else None
    return data_dir, node_id(data_dir), db, journal


def cmd_compliance(args) -> int:
    if args.module == "dpdp":
        return _cmd_dpdp(args)
    return _cmd_cbam(args)


def _cmd_dpdp(args) -> int:
    from ulpf.compliance import dpdp
    a = args.action
    if a == "scan":
        from ulpf.compliance.pii import PIIScanner
        scanner = PIIScanner(args.types or None)
        text = sys.stdin.read() if not args.file else open(args.file, "r", encoding="utf-8", errors="replace").read()
        counts: dict[str, int] = {}
        lines_with = 0
        for line in text.splitlines():
            found = scanner.scan(line)
            if found:
                lines_with += 1
            for m in found:
                counts[m.type] = counts.get(m.type, 0) + 1
        out = {"lines": len(text.splitlines()), "lines_with_personal_data": lines_with, "by_type": counts}
        if args.redact_to:
            with open(args.redact_to, "w", encoding="utf-8") as f:
                f.write("\n".join(scanner.redact(l) for l in text.splitlines()) + "\n")
            out["redacted_copy"] = args.redact_to
        print(json.dumps(out, indent=2))
        return 0
    if a == "verify-certificate":
        from ulpf.runtime.keys import load_public_key
        with open(args.target, "r", encoding="utf-8") as f:
            cert = json.load(f)
        pub = load_public_key(args.pubkey) if args.pubkey else None
        ok = dpdp.verify_certificate(cert, pub)
        print(("VALID" if ok else "INVALID") + f": certificate {cert.get('certificate_id')} "
              f"({cert.get('summary', {}).get('records')} records)")
        if pub is None:
            print("note: checked against the key in the certificate; pass --pubkey to pin the publisher")
        return 0 if ok else 1
    opened = _open_writable(args)
    if opened is None:
        return 2
    data_dir, node, db, journal = opened
    try:
        if a == "erase":
            if not args.subject_id:
                print("--subject-id is required (repeat it for several identifiers)", file=sys.stderr)
                return 2
            res = dpdp.erase_subject(data_dir, args.subject_id, db=db, journal=journal, node=node,
                                     reason=args.reason or "", requested_by=args.requested_by or "",
                                     outputs=args.output or [], scan_whole_journal=args.scan_journal,
                                     out_dir=args.out)
            print(json.dumps(res, indent=2))
            print("give the receipt (salts) to the Data Principal and delete your copy of it", file=sys.stderr)
            return 0
        if a == "breach-pack":
            out = args.out or os.path.join(os.getcwd(), f"dpdp_breach_pack_{time.strftime('%Y%m%dT%H%M%S')}.zip")
            if not out.lower().endswith(".zip"):
                out = os.path.join(out, f"dpdp_breach_pack_{time.strftime('%Y%m%dT%H%M%S')}.zip")
            rep = dpdp.breach_pack(data_dir, out, db=db, journal=journal, since=args.since, until=args.until,
                                   min_risk=args.min_risk, organisation=args.org or "", contact=args.contact or "",
                                   node=node)
            print(json.dumps({"pack": out, **rep["summary"], "deadlines": rep["deadlines"]}, indent=2))
            return 0
        print(f"unknown dpdp action {a}", file=sys.stderr)
        return 2
    finally:
        db.close()
        if journal is not None:
            journal.close()


def _cmd_cbam(args) -> int:
    from ulpf.compliance import cbam
    a = args.action
    if a == "templates":
        for p in cbam.write_templates(args.out or "cbam_templates"):
            print(p)
        return 0
    if a == "csv2jsonl":
        if not args.files or not args.out:
            print("csv2jsonl needs CSV files and --out FILE.jsonl", file=sys.stderr)
            return 2
        n = sum(cbam.csv_to_jsonl(f, args.out, args.record_type) for f in args.files)
        print(f"{n} records appended to {args.out}")
        return 0
    if a == "verify-pack":
        from ulpf.compliance.packs import verify
        from ulpf.runtime.keys import load_public_key
        res = verify(args.target, load_public_key(args.pubkey) if args.pubkey else None)
        print(json.dumps(res, indent=2))
        return 0 if res["valid"] else 1
    if not args.installation or not args.period:
        print("--installation and --period are required", file=sys.stderr)
        return 2
    if a == "calculate":
        recs = cbam.records_from_files(args.files) if args.files else []
        if not recs:
            from ulpf.storage.database import Database
            db = Database(_store_path(args), read_only=True)
            try:
                recs = cbam.records_from_store(db, args.installation, args.period)
            finally:
                db.close()
        print(json.dumps(cbam.calculate(recs, args.installation, args.period, cbam.load_defaults(args.defaults),
                                        args.price), indent=2))
        return 0
    if a == "export-pack":
        from ulpf.storage.database import Database
        data_dir = _data_dir(args)
        db = None
        journal = None
        if not args.files_only:
            db = Database(_store_path(args), read_only=True)
            journal = _open_journal_ro(data_dir) if os.path.isdir(os.path.join(data_dir, "journal")) else None
        try:
            res = cbam.export_pack(args.out or os.getcwd(), args.installation, args.period, data_dir=data_dir,
                                   db=db, journal=journal, files=args.files, defaults_path=args.defaults,
                                   price_eur=args.price)
        finally:
            if db is not None:
                db.close()
        print(json.dumps({"pack": res["path"], "records": res["records"],
                          "goods": len(res["calculation"]["goods"]), "issues": res["calculation"]["issues"]}, indent=2))
        return 0
    print(f"unknown cbam action {a}", file=sys.stderr)
    return 2


def cmd_bundle(args) -> int:
    from ulpf.compliance.bundle import write_bundle
    from ulpf.storage.database import Database
    data_dir = _data_dir(args)
    db = Database(_store_path(args), read_only=True) if os.path.exists(_store_path(args)) else None
    out = args.out or os.path.join(os.getcwd(), f"ulpf_forensic_bundle_{time.strftime('%Y%m%dT%H%M%S')}.zip")
    try:
        res = write_bundle(data_dir, out, db=db, since=args.since, until=args.until,
                           include_journal=args.include_journal, config_path=args.config)
    finally:
        if db is not None:
            db.close()
    print(json.dumps(res, indent=2))
    return 0


def cmd_airgap(args) -> int:
    from ulpf.runtime import egress_os
    if args.action == "os-check":
        host, _, port = args.target.rpartition(":")
        res = egress_os.os_check((host, int(port)))
        print(json.dumps(res, indent=2))
        return 0 if res.get("blocked") else 1
    allow: list[str] = []
    if args.config:
        from ulpf.config import load_pipeline_config
        allow = load_pipeline_config(args.config)["airgap"]["allow"]
    if args.format == "nftables":
        sys.stdout.write(egress_os.render_nftables(allow, user=args.user, allow_dns=args.allow_dns))
    elif args.format == "ebpf":
        sys.stdout.write(egress_os.render_ebpf(allow, cgroup=args.cgroup, allow_dns=args.allow_dns))
    elif args.format == "wfp":
        sys.stdout.write(egress_os.render_wfp(allow, program=args.program, service=args.service,
                                              allow_dns=args.allow_dns))
    else:
        sys.stdout.write(egress_os.render_systemd(allow, ingress_from=args.ingress_from, allow_dns=args.allow_dns))
    return 0


def register(sub) -> dict:
    p = sub.add_parser("run", help="Run the live pipeline (inputs → journal → workers → outputs)")
    p.add_argument("--config", "-c", help="Pipeline YAML (default: syslog TCP 127.0.0.1:5514 → local store)")
    p.add_argument("--mode", choices=["defence", "industry"], help="Mode for the built-in default config")
    p.add_argument("--data-dir", help="Override the data directory")
    p.add_argument("--no-api", action="store_true", help="Do not start the REST API")

    p = sub.add_parser("config", help="Validate or show a pipeline config")
    p.add_argument("action", choices=["check", "show", "example"])
    p.add_argument("file", nargs="?")

    p = sub.add_parser("raw", help="Original bytes of a journaled record")
    p.add_argument("action", choices=["get"])
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--seq", type=int)
    g.add_argument("--event-id")
    p.add_argument("--json", action="store_true")
    p.add_argument("--data-dir")

    p = sub.add_parser("evidence", help="Evidence seals: verify, list, inclusion proofs, keys")
    p.add_argument("action", choices=["verify", "list", "prove", "pubkey", "escrow-keygen"])
    p.add_argument("--pubkey", help="verify: identity public key (PEM) the seals must be anchored by "
                                    "(default <data dir>/evidence/evidence.pub)")
    p.add_argument("--row-key", help="verify: row-MAC K_0 (row_key.k0, or row_key.k0.sealed with --escrow-key)")
    p.add_argument("--escrow-key", help="verify: X25519 private key that opens row_key.k0.sealed")
    p.add_argument("--out", help="escrow-keygen: directory for the new key pair")
    p.add_argument("--seq", type=int, help="Record to prove (prove)")
    p.add_argument("--from-seq", type=int)
    p.add_argument("--to-seq", type=int)
    p.add_argument("--check-store", action="store_true", help="Also compare stored events with the journal")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--data-dir")

    p = sub.add_parser("intel", help="Threat intelligence: import STIX / MISP / OTX, sync feeds, look up indicators")
    p.add_argument("action", choices=["import-stix", "import-misp", "import-otx", "sync", "build", "stats", "lookup",
                                      "sight"])
    p.add_argument("value", nargs="?", help="lookup / sight: indicator value")
    p.add_argument("--file", help="import-*: feed file (STIX 2.1 bundle, MISP event export, OTX pulses)")
    p.add_argument("--name", help="import-*: feed name (default: from the file name); sync: only this feed")
    p.add_argument("--kind", default="auto", help="sight: indicator kind (default: guessed)")
    p.add_argument("--config", "-c", help="Use the intel section (feeds, decay) and mode of this pipeline config")
    p.add_argument("--data-dir")

    p = sub.add_parser("sigma", help="Sigma rules: list, check files, test against a log file")
    p.add_argument("action", choices=["list", "check", "test"])
    p.add_argument("files", nargs="*", help="Rule files or directories (check; list/test: in addition to the "
                                            "bundled pack)")
    p.add_argument("--config", "-c", help="Use analytics.sigma from this pipeline config")
    p.add_argument("--no-builtin", action="store_true", help="Leave out the bundled rule pack")
    p.add_argument("--log", help="test: log file to run through the pipeline")
    p.add_argument("--window", type=float, default=300.0, help="test: correlation window in seconds")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("compliance", help="DPDP (India) erasure and breach packs; EU CBAM data packs")
    p.add_argument("module", choices=["dpdp", "cbam"])
    p.add_argument("action", help="dpdp: scan | erase | verify-certificate | breach-pack;  "
                                  "cbam: templates | csv2jsonl | calculate | export-pack | verify-pack")
    p.add_argument("target", nargs="?", help="verify-certificate: certificate JSON; verify-pack: pack ZIP")
    p.add_argument("--data-dir")
    p.add_argument("--store", help="Event store (default: the data directory's store)")
    p.add_argument("--out", help="Output directory or file")
    p.add_argument("--pubkey", help="Publisher's Ed25519 public key (PEM) to pin when verifying")
    # dpdp
    p.add_argument("--subject-id", action="append", default=[], help="erase: an identifier of the Data "
                   "Principal (e-mail, phone, Aadhaar, PAN, user name, ...); repeat for several")
    p.add_argument("--reason")
    p.add_argument("--requested-by")
    p.add_argument("--output", action="append", default=[], help="erase: outputs the data was delivered to")
    p.add_argument("--scan-journal", action="store_true", help="erase: also search every journal record")
    p.add_argument("--file", help="scan: log file (default: stdin)")
    p.add_argument("--types", nargs="*", help="scan: PII types to look for")
    p.add_argument("--redact-to", help="scan: write a redacted copy here")
    p.add_argument("--since", help="breach-pack: ISO time (default: 7 days before --until)")
    p.add_argument("--until", help="breach-pack: ISO time (default: now)")
    p.add_argument("--min-risk", type=float, default=6.0, help="breach-pack: correlation risk threshold")
    p.add_argument("--org")
    p.add_argument("--contact")
    # cbam
    p.add_argument("--installation")
    p.add_argument("--period", help="Reporting year (YYYY)")
    p.add_argument("--defaults", help="Default values CSV: cn_code, see_direct, see_indirect")
    p.add_argument("--price", type=float, help="CBAM certificate price, EUR per tCO2e (cost estimate)")
    p.add_argument("--files", nargs="*", help="CSV/JSONL record files (csv2jsonl, calculate, export-pack)")
    p.add_argument("--files-only", action="store_true", help="export-pack: records from --files only")
    p.add_argument("--record-type", choices=["production", "electricity", "precursor", "shipment"])

    p = sub.add_parser("bundle", help="Offline forensic bundle: seals, events, audit log, erasures (signed)")
    p.add_argument("--out", help="Bundle ZIP path")
    p.add_argument("--since")
    p.add_argument("--until")
    p.add_argument("--include-journal", action="store_true", help="Also the raw journal segments")
    p.add_argument("--config", "-c", help="Include this pipeline config")
    p.add_argument("--data-dir")
    p.add_argument("--store")

    p = sub.add_parser("airgap", help="OS-level egress policy for native code (nftables, systemd, eBPF, WFP)")
    p.add_argument("action", choices=["os-policy", "os-check"])
    p.add_argument("--config", "-c", help="os-policy: take airgap.allow from this config")
    p.add_argument("--format", choices=["nftables", "systemd", "ebpf", "wfp"], default="nftables",
                   help="ebpf: cgroup-BPF connect/sendmsg programs (Linux); wfp: Windows Filtering Platform rules")
    p.add_argument("--cgroup", default="/sys/fs/cgroup/system.slice/ulpf.service", help="ebpf: service cgroup")
    p.add_argument("--program", help="wfp: executable to restrict (default: this Python)")
    p.add_argument("--service", help="wfp: restrict a Windows service by name instead of an executable")
    p.add_argument("--user", default="ulpf", help="nftables: the service user whose packets are filtered")
    p.add_argument("--ingress-from", action="append", default=[],
                   help="systemd: networks that send logs here (the unit filter is two-way)")
    p.add_argument("--allow-dns", action="store_true", help="also allow the nameservers in /etc/resolv.conf")
    p.add_argument("--target", default="192.0.2.1:9", help="os-check: a destination that must be refused")

    p = sub.add_parser("parsers", help="Learned parsers; approve or reject (defence mode)")
    p.add_argument("action", choices=["list", "approve", "reject"])
    p.add_argument("parser_id", nargs="?")
    p.add_argument("--data-dir")

    p = sub.add_parser("lake", help="Lakehouse outputs: status, query (hot + cold), compact, verify")
    p.add_argument("action", choices=["status", "query", "compact", "verify"])
    p.add_argument("--config", required=True)
    p.add_argument("--output", help="Lakehouse output name (when there are several)")
    p.add_argument("--data-dir")
    p.add_argument("--sql", default="SELECT count(*) AS events FROM events")
    p.add_argument("--tenant")
    p.add_argument("--start", help="ISO-8601 time (UTC)")
    p.add_argument("--end", help="ISO-8601 time (UTC)")
    p.add_argument("--eq", action="append", help="column=value (bloom-pruned on source_ip, destination_ip, "
                                                 "user_name, hash_sha256)")
    p.add_argument("--max-rows", type=int, default=1000)
    p.add_argument("--force", action="store_true", help="compact: also recent partitions")

    p = sub.add_parser("audit", help="Verify the hash-chained audit log")
    p.add_argument("action", choices=["verify"])
    p.add_argument("--data-dir")

    p = sub.add_parser("dlq", help="Show dead-lettered events")
    p.add_argument("action", choices=["list"])
    p.add_argument("--sink")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--data-dir")

    p = sub.add_parser("plugins", help="Installed parser plugins and their package hashes")
    p.add_argument("action", choices=["list"])
    p.add_argument("--config", "-c", help="Apply this config's plugin policy (defence allow-list)")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("schema", help="Unified schema versions: diff, export")
    p.add_argument("action", choices=["diff", "export", "versions"])
    p.add_argument("old", nargs="?", help="diff: old version or file (default: latest registered); "
                                          "export: output file")
    p.add_argument("new", nargs="?", help="diff: new version or file (default: current)")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("source", help="Onboard a new log source from a sample file")
    p.add_argument("action", choices=["onboard"])
    p.add_argument("--name", required=True, help="Source name (also the input name)")
    p.add_argument("--sample", required=True, help="Sample log file (a few hundred lines)")
    p.add_argument("--mode", choices=["defence", "industry"], help="Default: the config's mode, else industry")
    p.add_argument("--config", "-c", help="Pipeline YAML to add the input to")
    p.add_argument("--write-config", action="store_true", help="Insert the input into --config")
    p.add_argument("--input-type", choices=["file", "syslog"], default="file")
    p.add_argument("--path", help="file input: path or glob of the live log")
    p.add_argument("--protocol", choices=["udp", "tcp", "tls"], default="tcp")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=5514)
    p.add_argument("--json", action="store_true")
    p.add_argument("--data-dir")

    p = sub.add_parser("cluster", help="Multi-node status: nodes, heartbeats, input assignments")
    p.add_argument("action", choices=["status"])
    p.add_argument("--config", "-c", required=True)
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("apikey", help="Create an API key with a role (read, write, admin)")
    p.add_argument("action", choices=["new"])
    p.add_argument("--name", required=True)
    p.add_argument("--role", choices=["read", "write", "admin"], required=True)
    p.add_argument("--keys-file")
    p.add_argument("--config", "-c", help="Take api.keys_file from this config")
    p.add_argument("--data-dir")

    p = sub.add_parser("reload", help="Ask a running `ulpf run` to re-read its config (validated first)")
    p.add_argument("--url", default="http://127.0.0.1:8000")
    p.add_argument("--key-env", default="ULPF_API_KEY", help="Environment variable holding an admin key")

    return {"run": cmd_run, "config": cmd_config, "raw": cmd_raw, "evidence": cmd_evidence,
            "parsers": cmd_parsers, "audit": cmd_audit, "dlq": cmd_dlq, "plugins": cmd_plugins,
            "schema": cmd_schema, "source": cmd_source, "cluster": cmd_cluster, "apikey": cmd_apikey,
            "reload": cmd_reload, "airgap": cmd_airgap, "sigma": cmd_sigma, "intel": cmd_intel, "compliance": cmd_compliance,
            "bundle": cmd_bundle, "lake": cmd_lake}
