"""
Auto-Parser Generator (APG) evaluation
=======================================
Measures what matters for learned parsers on formats NO built-in parser
handles:

  1. Learnability — does `learn()` accept a validated parser from a small
     training sample (40 lines, all from one day)?
  2. Generalisation — coverage on 1,000 *unseen* lines from other days with
     different hosts, IPs, users, severities and actions.
  3. Field accuracy — extracted timestamp / IPs / ports / user / action /
     severity compared with the generator's ground truth.
  4. Throughput — events/second through the full pipeline for these lines.

    python -m benchmarks.apg_eval            # prints a report, exit 1 on failure
"""
from __future__ import annotations

import os
import random
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "svc_backup", "jdoe"]
LEVELS = ["INFO", "WARN", "ERROR", "DEBUG", "CRITICAL"]
ACTIONS = ["accept", "deny", "drop", "allow", "reject"]
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def _ip(rng):
    return f"{rng.choice([10, 172, 192, 45, 185])}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _gen(fmt: str, rng: random.Random, day: datetime) -> tuple[str, dict]:
    """Return (line, ground_truth)."""
    ts = day + timedelta(seconds=rng.randint(0, 86399), milliseconds=rng.randint(0, 999))
    iso_space = ts.strftime("%Y-%m-%d %H:%M:%S")
    truth = {"timestamp": ts.replace(microsecond=0)}
    user, ip, lvl, act = rng.choice(USERS), _ip(rng), rng.choice(LEVELS), rng.choice(ACTIONS)
    if fmt == "pipe_app":
        truth.update(user=user, src_ip=ip)
        return f"UNKNOWN-APP-LOG | {iso_space} | User {user} logged in from {ip}", truth
    if fmt == "bracket_app":
        port = rng.randint(1024, 65535)
        truth.update(dst_ip=ip, dst_port=port)
        comp = rng.choice(["CUSTOM", "DB", "AUTH", "API"])
        return f"[{iso_space}] [{comp}] [{lvl}] Connection refused to database at {ip}:{port}", truth
    if fmt == "transaction":
        truth.update(user=user, action=act)
        return f"Transaction {rng.randint(1000, 99999)} initiated by {user} on {iso_space} with status: {act}", truth
    if fmt == "multichar":
        iso_z = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"
        truth["timestamp"] = ts.replace(microsecond=(ts.microsecond // 1000) * 1000)
        truth.update(severity_word=lvl)
        msg = rng.choice(["Authentication token rejected: signature invalid", "Session expired for client",
                          "MFA challenge failed", "Token refreshed"])
        return (f"*{lvl}* }}|{{ {iso_z} }}|{{ auth-engine }}|{{ (({msg})) }}|{{ "
                f"+ps_id:{rng.randint(1000, 99999)};env:{rng.choice(['prod', 'stage'])};status:active+"), truth
    if fmt == "log4j":
        ms = rng.randint(0, 999)
        truth.update(src_ip=ip, severity_word=lvl)
        return (f"{lvl} {iso_space},{ms:03d} [{rng.choice(['main', 'worker-3', 'http-nio-8080-exec-7'])}] "
                f"com.acme.PaymentService - Payment failed for order {rng.randint(100, 99999)} from {ip}"), truth
    if fmt == "scada_semicolon":
        iso_z = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
        return (f"PLC-{rng.randint(1, 40):02d};{iso_z};PUMP_{rng.randint(1, 9)};"
                f"{rng.uniform(0, 100):.2f};{rng.choice(['GOOD', 'BAD', 'UNCERTAIN'])}"), truth
    if fmt == "apache_error":
        truth["timestamp"] = ts.replace(microsecond=0)
        truth.update(src_ip=ip)
        return (f"[{ts.strftime('%a')} {MONTHS[ts.month - 1]} {ts.day:02d} {ts.strftime('%H:%M:%S')} {ts.year}] "
                f"[{rng.choice(['error', 'warn', 'notice'])}] [client {ip}] File does not exist: "
                f"/var/www/html/{rng.choice(['favicon.ico', 'wp-login.php', 'admin'])}"), truth
    raise ValueError(fmt)


FORMATS = ["pipe_app", "bracket_app", "transaction", "multichar", "log4j", "scada_semicolon", "apache_error"]


def _check(event: dict, truth: dict) -> dict[str, bool]:
    res = {}
    if "timestamp" in truth:
        try:
            got = datetime.fromisoformat(event["timestamp"])
            exp = truth["timestamp"].replace(tzinfo=timezone.utc)
            res["timestamp"] = abs((got - exp).total_seconds()) < 1.0
        except (ValueError, TypeError):
            res["timestamp"] = False
    if "src_ip" in truth:
        res["src_ip"] = event["source"]["ip"] == truth["src_ip"]
    if "dst_ip" in truth:
        res["dst_ip"] = event["destination"]["ip"] == truth["dst_ip"]
    if "dst_port" in truth:
        res["dst_port"] = event["destination"]["port"] == truth["dst_port"]
    if "user" in truth:
        res["user"] = event["user"]["name"] == truth["user"]
    if "action" in truth:
        from ulpf.engine.normalizer import normalize_action
        res["action"] = event["action"] == normalize_action(truth["action"])
    if "severity_word" in truth:
        from ulpf.engine.normalizer import normalize_severity
        res["severity"] = event["severity"] == normalize_severity(truth["severity_word"])[0]
    return res


def run(train_n: int = 40, test_n: int = 1000, seed: int = 7, verbose: bool = True) -> dict:
    tmp = tempfile.mkdtemp(prefix="ulpf_apg_")
    os.environ["ULPF_LEARNED_PARSERS_DIR"] = os.path.join(tmp, "learned")
    os.environ.setdefault("ULPF_DATA_DIR", os.path.join(tmp, "data"))
    from ulpf.engine.pipeline import Pipeline

    rng = random.Random(seed)
    pipeline = Pipeline()
    engine = pipeline.auto_engine

    def is_known(line: str) -> bool:
        parser = pipeline.registry.get_parser_for_format(pipeline._detect(line)["format_name"])
        return parser is not None and parser.parse(line) is not None

    train_day = datetime(2026, 9, 27)
    report = {"formats": {}, "passed": True}
    for fmt in FORMATS:
        train = [_gen(fmt, rng, train_day)[0] for _ in range(train_n)]
        t0 = time.perf_counter()
        learned = engine.learn(train, is_known=is_known, save=True)
        learn_ms = (time.perf_counter() - t0) * 1000

        tests = [_gen(fmt, rng, train_day + timedelta(days=rng.randint(1, 200))) for _ in range(test_n)]
        t0 = time.perf_counter()
        results = [pipeline.process_line(line) for line, _ in tests]
        elapsed = time.perf_counter() - t0
        auto = sum(1 for r in results if r.get("auto_parsed"))
        field_ok: dict[str, list[int]] = {}
        for r, (_, truth) in zip(results, tests):
            if r.get("auto_parsed"):
                for k, ok in _check(r["event"], truth).items():
                    field_ok.setdefault(k, [0, 0])
                    field_ok[k][0] += ok
                    field_ok[k][1] += 1
        accuracy = {k: round(v[0] / v[1] * 100, 1) for k, v in field_ok.items()}
        coverage = auto / test_n * 100
        ok = bool(learned["accepted"]) and coverage >= 95 and all(a >= 95 for a in accuracy.values())
        report["passed"] &= ok
        report["formats"][fmt] = {
            "accepted": len(learned["accepted"]),
            "known_lines_in_training": learned["known_lines"],
            "template": learned["accepted"][0]["template"] if learned["accepted"] else None,
            "rejected": [r["reason"] for r in learned["rejected"]],
            "learn_ms": round(learn_ms, 1),
            "coverage_pct": round(coverage, 1),
            "field_accuracy_pct": accuracy,
            "eps": round(test_n / elapsed),
            "pass": ok,
        }
        if verbose:
            r = report["formats"][fmt]
            print(f"\n[{'PASS' if ok else 'FAIL'}] {fmt}")
            print(f"  learned    : {r['accepted']} parser(s) in {r['learn_ms']} ms   template: {r['template']}")
            if r["rejected"]:
                print(f"  rejected   : {r['rejected']}")
            print(f"  coverage   : {r['coverage_pct']}% of {test_n} unseen lines (other days / values)")
            print(f"  accuracy   : {r['field_accuracy_pct']}")
            print(f"  throughput : {r['eps']:,} events/s (full pipeline, single core)")
    pipeline.close()
    report["autonomous"] = run_autonomous(seed=seed, verbose=verbose)
    report["passed"] &= report["autonomous"]["pass"]
    if verbose:
        print(f"\nAPG EVALUATION: {'PASS' if report['passed'] else 'FAIL'}")
    return report


def run_autonomous(fmt: str = "log4j", total: int = 5000, seed: int = 11, verbose: bool = True) -> dict:
    """Zero-touch learning: a live stream of an unknown format, no operator action.

    The background learner samples unknown lines, mines + validates a parser
    after 50 samples, admits it as a canary, and the pipeline starts using it.
    """
    from ulpf.engine.pipeline import Pipeline
    os.environ["ULPF_LEARNED_PARSERS_DIR"] = tempfile.mkdtemp(prefix="ulpf_apg_auto_")
    rng = random.Random(seed)
    pipeline = Pipeline()
    t0 = time.perf_counter()
    first_auto_at = None
    auto = 0
    for i in range(total):
        line, _ = _gen(fmt, rng, datetime(2026, 9, 27) + timedelta(days=i % 30))
        r = pipeline.process_line(line)
        if r.get("auto_parsed"):
            auto += 1
            if first_auto_at is None:
                first_auto_at = (i, time.perf_counter() - t0)
        elif i % 200 == 0:
            time.sleep(0.01)  # live traffic is not a tight loop; give the learner its slice
    states = [s.state for s in pipeline.auto_engine.registry.list_parsers()]
    pipeline.close()
    tail_cov = None
    if first_auto_at is not None:
        tail_cov = round(auto / (total - first_auto_at[0]) * 100, 1)
    result = {
        "format": fmt, "lines": total,
        "learned_after_lines": first_auto_at[0] if first_auto_at else None,
        "learned_after_sec": round(first_auto_at[1], 2) if first_auto_at else None,
        "coverage_after_learning_pct": tail_cov, "parser_states": states,
        "pass": bool(first_auto_at) and first_auto_at[0] < 1000 and (tail_cov or 0) >= 99,
    }
    if verbose:
        print(f"\n[{'PASS' if result['pass'] else 'FAIL'}] autonomous learning ({fmt})")
        print(f"  first auto-parsed event after {result['learned_after_lines']} lines "
              f"({result['learned_after_sec']} s); coverage afterwards {tail_cov}%; parser states {states}")
    return result


if __name__ == "__main__":
    sys.exit(0 if run()["passed"] else 1)
