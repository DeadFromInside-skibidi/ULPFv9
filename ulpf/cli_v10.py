"""
v10 command line:

    ulpf soar cases|create|playbooks|validate|run|approvals|approve|reject|rollback|audit-verify
    ulpf copilot ask "question" [--lang kql|spl|hql] | triage --case ID | explain T1110 ...
    ulpf matrix run|export [--frameworks cert_in,rbi_csf,...] [-c pipeline.yaml]
    ulpf certin report --case ID | ntp-check [--server HOST] | retention [-c pipeline.yaml]
    ulpf fleet token --group G | agent --server URL --id ID [--enroll-token T] | agents | publish --group G FILE
    ulpf raft status --peers n1=host:port,... (one-shot view of a Raft cluster member's state on disk)
    ulpf forensic-kit OUT_DIR       copy the standalone verifiers (Python + compiled) for an air-gapped workstation
    ulpf console [--port 8000]      serve the web console with the standalone API
"""
from __future__ import annotations

import json
import os
import shutil
import sys


def _data_dir(args) -> str:
    from ulpf.platform.paths import get_data_dir
    return getattr(args, "data_dir", None) or str(get_data_dir())


def _cfg(args) -> dict:
    if getattr(args, "config", None):
        from ulpf.config import load_pipeline_config
        c = load_pipeline_config(args.config)
        return c.data if hasattr(c, "data") else c
    return {}


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def cmd_soar(args) -> int:
    from ulpf.soar.service import SoarService
    svc = SoarService(_data_dir(args), _cfg(args).get("soar") or {})
    t, who = args.tenant, os.environ.get("USERNAME") or os.environ.get("USER") or "cli"
    try:
        a = args.action
        if a == "cases":
            for c in svc.cases.list(t, state=args.state):
                print(f"{c['id']}  {c['severity']:8s} {c['state']:14s} {c['title']}"
                      f"{'  SLA:' + ','.join(c['sla']['breached']) if c['sla']['breached'] else ''}")
        elif a == "create":
            _print(svc.cases.create(t, args.title, args.severity, actor=who))
        elif a == "playbooks":
            for p in svc.engine.playbooks.values():
                print(f"{p['id']:36s} v{p['version']}  {len(p['order'])} steps  {p['name']}")
            for e in svc.playbook_errors:
                print(f"error: {e}", file=sys.stderr)
        elif a == "validate":
            from ulpf.soar.playbook import load_spec, validate
            pb = validate(load_spec(args.file), svc.connectors, set(svc.engine.builtins))
            print(f"valid: {pb['id']} ({len(pb['order'])} steps)")
        elif a == "run":
            run = svc.engine.start(args.playbook, t, json.loads(args.inputs or "{}"), who, args.case,
                                   dry_run=args.dry_run, wait=True)
            _print({"run": run["id"], "status": run["status"],
                    "steps": {k: v["status"] for k, v in run["state"]["steps"].items()}})
        elif a == "approvals":
            for x in svc.engine.approvals(t):
                print(f"{x['id']}  run {x['run_id']}  step {x['step_id']}  {x['summary']}")
        elif a in ("approve", "reject"):
            _print(svc.engine.decide(t, args.id, who, a == "approve", args.reason or "", {"admin"}))
        elif a == "rollback":
            _print(svc.engine.rollback(t, args.id, who, dry_run=args.dry_run))
        elif a == "audit-verify":
            from ulpf.runtime.audit import verify_audit_log
            res = verify_audit_log(svc.audit.path)
            _print(res)
            return 0 if res["valid"] else 1
        return 0
    finally:
        svc.close()


def cmd_copilot(args) -> int:
    from ulpf.copilot.service import Copilot
    cp = Copilot(_cfg(args).get("copilot") or {})
    if args.action == "status":
        _print(cp.status())
    elif args.action == "ask":
        r = cp.nl2query(" ".join(args.text), args.lang)
        print(r["query"])
        print(f"# {r['explanation']} [{r['origin']}, {'valid' if r['valid'] else 'NOT VALID'}]", file=sys.stderr)
        return 0 if r["valid"] else 1
    elif args.action == "explain":
        _print(cp.explain(args.text))
    elif args.action == "triage":
        from ulpf.soar.service import SoarService
        from ulpf.storage.database import Database
        svc = SoarService(_data_dir(args), {})
        db = None
        try:
            db = Database(read_only=True)
        except Exception:
            db = None
        try:
            _print(cp.triage_case(args.tenant, args.case, svc, db))
        finally:
            svc.close()
            if db is not None:
                db.close()
    return 0


def cmd_matrix(args) -> int:
    from ulpf.compliance.matrix import FRAMEWORKS, Collector, export_bundle
    from ulpf.storage.database import Database
    cfg = _cfg(args)
    fws = args.frameworks.split(",") if args.frameworks else list(FRAMEWORKS)
    bad = [f for f in fws if f not in FRAMEWORKS]
    if bad:
        print(f"unknown framework(s) {bad}; known: {', '.join(FRAMEWORKS)}", file=sys.stderr)
        return 2
    db = Database(read_only=True)
    try:
        col = Collector(_data_dir(args), cfg, db, since=args.since, until=args.until,
                        ntp_result={"compliant": None, "note": "skipped (--no-ntp)"} if args.no_ntp else None)
        if args.action == "run":
            m = col.run(fws)
            for fid, fw in m["frameworks"].items():
                print(f"\n{fw['name']}: pass {fw['summary']['pass']}, fail {fw['summary']['fail']}, "
                      f"review {fw['summary']['review']}")
                for c in fw["controls"]:
                    print(f"  [{c['status'].upper():6s}] {c['id']:12s} {c['title']}")
            if args.json:
                _print(m)
        else:
            _print(export_bundle(col, args.out, fws, args.org or ""))
    finally:
        db.close()
    return 0


def cmd_certin(args) -> int:
    from ulpf.compliance import certin
    if args.action == "ntp-check":
        res = certin.ntp_check(args.server or certin.NTP_SERVERS)
        _print(res)
        return 0 if res["compliant"] else 1
    if args.action == "retention":
        _print(certin.retention_audit(_data_dir(args), _cfg(args)))
        return 0
    from ulpf.soar.service import SoarService
    svc = SoarService(_data_dir(args), {})
    try:
        case = svc.cases.get(args.tenant, args.case)
        case["timeline"] = svc.cases.timeline(args.tenant, args.case)
        org = (_cfg(args).get("compliance") or {}).get("organisation") or {"name": args.org}
        _print(certin.incident_report(case, org))
    finally:
        svc.close()
    return 0


def cmd_fleet(args) -> int:
    if args.action == "agent":
        import logging
        import threading
        from ulpf.fleet.agent import FleetAgent
        state = args.state_dir or os.path.join(_data_dir(args), "fleet-agent")

        def on_config(cfg):
            import yaml
            p = os.path.join(state, "pipeline.yaml")
            with open(p + ".tmp", "w", encoding="utf-8") as f:
                yaml.safe_dump(cfg, f)
            os.replace(p + ".tmp", p)
            logging.getLogger("ulpf.fleet").info(f"new configuration written to {p}")
        agent = FleetAgent(args.server, state, args.id, args.enroll_token, on_config=on_config,
                           insecure_bootstrap_ca=args.ca)
        stop = threading.Event()
        try:
            agent.run_forever(stop)
        except KeyboardInterrupt:
            stop.set()
        return 0
    from ulpf.fleet.control import FleetControl
    fc = FleetControl(_data_dir(args))
    if args.action == "token":
        print(fc.create_enrollment_token(args.group, args.ttl))
    elif args.action == "agents":
        for a in fc.agents(args.group):
            print(f"{a['id']:24s} {a['group']:12s} {'online' if a['online'] else 'offline':8s} "
                  f"eps={a['stats'].get('eps', 0)} cfg=v{a['stats'].get('config_version', 0)}")
    elif args.action == "publish":
        import yaml
        with open(args.file, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        _print(fc.publish_config(args.group, cfg, os.environ.get("USERNAME") or "cli"))
    elif args.action == "ca":
        print(fc.ca_pem())
    return 0


def cmd_raft(args) -> int:
    from ulpf.runtime.raft import FileStorage
    d = os.path.join(args.raft_dir or os.path.join(_data_dir(args), "raft"), args.node)
    st = FileStorage(d)
    try:
        _print({"node": args.node, "term": st.term, "voted_for": st.vote, "log_entries": len(st.entries),
                "snapshot_index": (st.snapshot or {}).get("index"), "members": (st.snapshot or {}).get("members")})
    finally:
        st.close()
    return 0


def cmd_forensic_kit(args) -> int:
    import ulpf.compliance.verify_pack as vp
    import ulpf.forensic_verify as fv
    os.makedirs(args.out, exist_ok=True)
    shutil.copy2(fv.__file__, os.path.join(args.out, "ulpf_forensic_verify.py"))
    shutil.copy2(vp.__file__, os.path.join(args.out, "verify_pack.py"))
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    copied = ["ulpf_forensic_verify.py", "verify_pack.py"]
    for exe in ("ulpf-forensic-verify.exe", "ulpf-forensic-verify"):
        p = os.path.join(root, "native", "ulpf_forensic", "target", "release", exe)
        if os.path.exists(p):
            shutil.copy2(p, os.path.join(args.out, exe))
            copied.append(exe)
    with open(os.path.join(args.out, "README.txt"), "w", encoding="utf-8") as f:
        f.write("ULPF air-gapped forensic verification kit\n\n"
                "  python ulpf_forensic_verify.py journal --journal JOURNAL_DIR --seals SEALS_DIR --pubkey evidence.pub\n"
                "  ulpf-forensic-verify journal --journal JOURNAL_DIR --seals SEALS_DIR --pubkey evidence.pub\n"
                "  python verify_pack.py PACK.zip --pubkey signer.pub\n\n"
                "Obtain evidence.pub / signer.pub out of band (never from the evidence medium itself).\n"
                "Exit status 0 = verified; findings name the segment file, byte offset, bit and sequence number.\n")
    import hashlib
    sums = []
    for n in copied:
        with open(os.path.join(args.out, n), "rb") as f:
            sums.append(f"{hashlib.sha256(f.read()).hexdigest()}  {n}")
    with open(os.path.join(args.out, "SHA256SUMS"), "w", encoding="utf-8") as f:
        f.write("\n".join(sums) + "\n")
    print(f"forensic kit written to {args.out}: {', '.join(copied)}")
    return 0


def cmd_console(args) -> int:
    import uvicorn
    from ulpf.api.app import create_app
    print(f"ULPF web console: http://{args.host}:{args.port}/console/")
    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="warning")
    return 0


def register(sub) -> dict:
    p = sub.add_parser("soar", help="Cases, playbooks, approvals and containment (SOAR)")
    p.add_argument("action", choices=["cases", "create", "playbooks", "validate", "run", "approvals", "approve",
                                      "reject", "rollback", "audit-verify"])
    p.add_argument("--tenant", default="default")
    p.add_argument("--config", "-c")
    p.add_argument("--data-dir")
    p.add_argument("--state")
    p.add_argument("--title")
    p.add_argument("--severity", default="medium", choices=["low", "medium", "high", "critical"])
    p.add_argument("--file", help="validate: playbook YAML/JSON")
    p.add_argument("--playbook")
    p.add_argument("--inputs", help="run: JSON object")
    p.add_argument("--case")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--id", help="approve/reject: approval id; rollback: run id")
    p.add_argument("--reason")

    p = sub.add_parser("copilot", help="Offline SecOps copilot: NL to query, triage, ATT&CK explanations")
    p.add_argument("action", choices=["status", "ask", "triage", "explain"])
    p.add_argument("text", nargs="*")
    p.add_argument("--lang", default="kql", choices=["kql", "spl", "hql"])
    p.add_argument("--case")
    p.add_argument("--tenant", default="default")
    p.add_argument("--config", "-c")
    p.add_argument("--data-dir")

    p = sub.add_parser("matrix", help="Compliance matrix: CERT-In, RBI, SEBI CSCRF, SOC 2, ISO 27001, PCI DSS v4")
    p.add_argument("action", choices=["run", "export"])
    p.add_argument("--frameworks", help="comma-separated (default: all)")
    p.add_argument("--since")
    p.add_argument("--until")
    p.add_argument("--out", default="compliance-evidence.zip")
    p.add_argument("--org")
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-ntp", action="store_true", help="skip the live NTP query (air-gapped without NTP)")
    p.add_argument("--config", "-c")
    p.add_argument("--data-dir")

    p = sub.add_parser("certin", help="CERT-In: 6-hour incident report, NTP sync check, 180-day retention audit")
    p.add_argument("action", choices=["report", "ntp-check", "retention"])
    p.add_argument("--case")
    p.add_argument("--tenant", default="default")
    p.add_argument("--org", default="")
    p.add_argument("--server", action="append", help="ntp-check: NTP server (repeatable)")
    p.add_argument("--config", "-c")
    p.add_argument("--data-dir")

    p = sub.add_parser("fleet", help="Forwarder fleet: enrollment tokens, agents, signed configs, the agent itself")
    p.add_argument("action", choices=["token", "agents", "publish", "agent", "ca"])
    p.add_argument("--group", default="default")
    p.add_argument("--ttl", type=float, default=86400)
    p.add_argument("--file")
    p.add_argument("--server")
    p.add_argument("--id")
    p.add_argument("--enroll-token")
    p.add_argument("--ca", help="agent: CA bundle to trust before enrollment")
    p.add_argument("--state-dir")
    p.add_argument("--data-dir")

    p = sub.add_parser("raft", help="Raft member state on disk (term, vote, log, snapshot)")
    p.add_argument("action", choices=["status"])
    p.add_argument("--node", required=True)
    p.add_argument("--raft-dir")
    p.add_argument("--data-dir")

    p = sub.add_parser("forensic-kit", help="Copy the standalone forensic verifiers for an air-gapped workstation")
    p.add_argument("out")

    p = sub.add_parser("console", help="Serve the web console with the standalone API")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)

    return {"soar": cmd_soar, "copilot": cmd_copilot, "matrix": cmd_matrix, "certin": cmd_certin,
            "fleet": cmd_fleet, "raft": cmd_raft, "forensic-kit": cmd_forensic_kit, "console": cmd_console}
