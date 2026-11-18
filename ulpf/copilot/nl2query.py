"""
Natural language -> KQL / SPL2 / HQL, validated by ULPF's own query compilers.

The deterministic translator understands the questions analysts actually type:
time windows ("last 24 hours", "past 7 days", "today", "since yesterday"),
subjects ("failed logins", "firewall denies", "powershell", "dns", "malware",
"privileged / admin", "detections", "high severity"), entities (IP addresses,
``user alice``, ``host web01``, ports), aggregations ("top 10 source ips",
"count by user", "per hour", "how many", "distinct users") and output size.

Every candidate — from the grammar or from a local model — is compiled with
``ulpf.query.engine.QueryEngine.compile`` before it is returned; an invalid
model answer is replaced by the grammar's. Time windows are embedded in KQL
(``ago()``) and returned as ``start``/``end`` for SPL2/HQL (the API applies them).
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import re

from ulpf.copilot.inference import Backend, ModelError, parse_json

_UNITS = {"minute": "m", "min": "m", "mins": "m", "minutes": "m", "hour": "h", "hours": "h", "hr": "h", "hrs": "h",
          "day": "d", "days": "d", "week": "d7", "weeks": "d7", "month": "d30", "months": "d30"}
_SUBJECTS = [
    (r"\b(failed|failure|unsuccessful|invalid|bad)\b.{0,20}\b(log ?ins?|log ?ons?|logins?|auth\w*|sign[- ]?ins?|"
     r"passwords?|ssh)\b|\bbrute[- ]?force\b|\bpassword spray", [("action", "==", "failed")], "authentication"),
    (r"\b(successful|accepted|succeeded)\b.{0,20}\b(log ?ins?|log ?ons?|logins?|sign[- ]?ins?|auth\w*)\b",
     [("action", "==", "success")], "authentication"),
    (r"\b(log ?ins?|log ?ons?|sign[- ]?ins?|authentications?)\b", [], "authentication"),
    (r"\b(firewall|blocked|denied|dropped)\b", [("action", "in", ["denied", "blocked", "dropped"])], None),
    (r"\bpowershell\b", [("message", "contains", "powershell")], None),
    (r"\bdns\b", [("message", "contains", "dns")], None),
    (r"\b(malware|ransomware|trojan|virus)\b", [("message", "contains", "malware")], None),
    (r"\b(privileged|admin(istrator)?|root)\b", [("user.name", "in", ["root", "administrator", "admin"])], None),
    (r"\b(detections?|alerts?|sigma)\b", [("event_kind", "==", "detection")], None),
]
_SEV = [(r"\bcritical\b", 9), (r"\bhigh[- ]?severity\b|\bhigh\b", 7), (r"\bmedium\b", 4)]
_GROUP = [(r"source ?ips?|src ?ips?|attackers?|sources?", "source_ip"),
          (r"dest(ination)? ?ips?|targets?|dst ?ips?", "destination_ip"),
          (r"users?|accounts?|usernames?", "user.name"), (r"hosts?|devices?|machines?", "device_vendor"),
          (r"ports?", "destination_port"), (r"categor(y|ies)", "category"), (r"actions?", "action"),
          (r"rules?|detections?", "rule.id")]
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")


class Intent:
    def __init__(self):
        self.window: tuple[int, str] | None = None
        self.filters: list[tuple[str, str, object]] = []
        self.category: str | None = None
        self.severity: int | None = None
        self.group: str | None = None
        self.top: int | None = None
        self.count_only = False
        self.distinct: str | None = None
        self.per: str | None = None
        self.limit = 100


def understand(q: str) -> Intent:
    t = " " + q.lower().strip() + " "
    it = Intent()
    m = re.search(r"\b(?:last|past|previous|in the last)\s+(\d+)?\s*(minutes?|mins?|hours?|hrs?|days?|weeks?|months?)\b", t)
    if m:
        n = int(m.group(1) or 1)
        u = _UNITS[m.group(2)]
        it.window = (n * int(u[1:]), "d") if u.startswith("d") and len(u) > 1 else (n, u)
    elif "today" in t:
        it.window = (24, "h")
    elif "yesterday" in t:
        it.window = (2, "d")
    elif "this week" in t:
        it.window = (7, "d")
    for pat, filters, cat in _SUBJECTS:
        if re.search(pat, t):
            it.filters += [f for f in filters if f not in it.filters]
            if cat and not it.category:
                it.category = cat
    for pat, sev in _SEV:
        if re.search(pat, t):
            it.severity = sev
            break
    for ip in _IP.findall(q):
        try:
            if "/" in ip:
                ipaddress.ip_network(ip, strict=False)
            else:
                ipaddress.ip_address(ip)
        except ValueError:
            continue
        field = "destination_ip" if re.search(r"(to|towards|destination|dst)\s+" + re.escape(ip), t) else "source_ip"
        it.filters.append((field, "==", ip))
    for kw, field in (("user", "user.name"), ("account", "user.name"), ("host", "device_vendor"),
                      ("port", "destination_port")):
        mm = re.search(rf"\b{kw}\s+(?:named\s+|=\s*)?['\"]?([A-Za-z0-9_.\\@-]{{1,64}})['\"]?", q, re.I)
        if mm and mm.group(1).lower() not in ("ips", "ip", "names", "is", "by", "with", "and", "in", "from"):
            v = mm.group(1)
            it.filters.append((field, "==", int(v) if field == "destination_port" and v.isdigit() else v))
    m = re.search(r"\btop\s+(\d+)?\s*([a-z ]{2,30}?)(?:\s+(?:by|with|for|in|from|over|during)\b|$|[?.!,])", t)
    if m:
        it.top = int(m.group(1) or 10)
        for pat, field in _GROUP:
            if re.search(pat, m.group(2)):
                it.group = field
                break
    m = re.search(r"\b(?:count|number of \w+|how many)\b.*?\bby\s+([a-z ]{2,30}?)(?:$|[?.!,]|\s+(?:in|over|for|during)\b)", t) \
        or re.search(r"\b(?:by|per|for each)\s+([a-z ]{2,20}?)(?:$|[?.!,]|\s+(?:in|over|for|during)\b)", t)
    if m and not it.group:
        for pat, field in _GROUP:
            if re.search(pat, m.group(1)):
                it.group = field
                break
    if re.search(r"\b(per|by|each)\s+(hour|hourly)\b|\bhourly\b|\bover time\b|\btimeline\b|\btrend\b", t):
        it.per = "1h"
    elif re.search(r"\b(per|by|each)\s+day\b|\bdaily\b", t):
        it.per = "1d"
    if re.search(r"\bhow many\b|\bcount\b|\bnumber of\b", t) and not it.group and not it.per:
        it.count_only = True
    m = re.search(r"\b(?:distinct|unique)\s+([a-z ]{2,20}?)(?:$|[?.!,]|\s)", t)
    if m:
        for pat, field in _GROUP:
            if re.search(pat, m.group(1)):
                it.distinct = field
                break
    m = re.search(r"\b(?:show|list|give me|first|latest|last)\s+(\d{1,5})\b", t)
    if m:
        it.limit = min(int(m.group(1)), 10000)
    return it


def _kql_lit(v) -> str:
    return str(v) if isinstance(v, int) else '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _cond_kql(f) -> str:
    field, op, v = f
    if op == "in":
        return f"{field} in ({', '.join(_kql_lit(x) for x in v)})"
    if op == "contains":
        return f"{field} contains {_kql_lit(v)}"
    return f"{field} == {_kql_lit(v)}"


def to_kql(it: Intent) -> str:
    where = []
    if it.window:
        where.append(f"timestamp > ago({it.window[0]}{it.window[1]})")
    if it.category:
        where.append(f'category has "{it.category[:4]}"')
    where += [_cond_kql(f) for f in it.filters]
    if it.severity:
        where.append(f"severity >= {it.severity}")
    q = "events" + (f"\n| where {' and '.join(where)}" if where else "")
    if it.distinct:
        return q + f"\n| summarize dcount({it.distinct})"
    if it.group and it.per:
        return q + f"\n| summarize count() by {it.group}, bin(timestamp, {it.per})\n| sort by timestamp asc"
    if it.group:
        q += f"\n| summarize count() by {it.group}"
        return q + (f"\n| top {it.top} by count_" if it.top else "\n| sort by count_ desc")
    if it.per:
        return q + f"\n| summarize count() by bin(timestamp, {it.per})\n| sort by timestamp asc"
    if it.count_only:
        return q + "\n| count"
    return q + f"\n| sort by timestamp desc\n| take {it.limit}"


def _spl_term(f) -> str:
    field, op, v = f
    if op == "in":
        return "(" + " OR ".join(f"{field}={x}" for x in v) + ")"
    if op == "contains":
        return f'"{v}"' if field == "message" else f"{field}=*{v}*"
    sv = str(v)
    return f'{field}="{sv}"' if any(c in sv for c in " =|") else f"{field}={sv}"


def to_spl(it: Intent) -> str:
    terms = [_spl_term(f) for f in it.filters]
    if it.category:
        terms.append(f"category=*{it.category[:4]}*")
    q = "search " + (" ".join(terms) if terms else "*")
    if it.severity:
        q += f" | where severity >= {it.severity}"
    if it.distinct:
        return q + f" | stats dc({it.distinct}) as distinct_count"
    if it.group and it.per:
        return q + f" | bin timestamp span={it.per} | stats count by {it.group}, timestamp"
    if it.group:
        q += f" | stats count by {it.group} | sort -count"
        return q + (f" | head {it.top}" if it.top else "")
    if it.per:
        return q + f" | timechart span={it.per} count"
    if it.count_only:
        return q + " | stats count"
    return q + f" | head {it.limit}"


def to_hql(it: Intent) -> str:
    terms = []
    for field, op, v in it.filters:
        if op == "in":
            terms.append("(" + " or ".join(f'{field}="{x}"' for x in v) + ")")
        elif op == "contains":
            terms.append(f'{field}=*{v}*')
        else:
            terms.append(f'{field}="{v}"')
    if it.category:
        terms.append(f"category=*{it.category[:4]}*")
    if it.severity:
        terms.append(f"severity>={it.severity}")
    q = " ".join(terms) if terms else "*"
    if it.distinct:
        return q + f" | count({it.distinct}, distinct=true)"
    if it.group:
        q += f" | groupBy({it.group})"
        return q + (f" | sort(_count, limit={it.top})" if it.top else " | sort(_count)")
    if it.per:
        return q + f" | timeChart(span={it.per})"
    if it.count_only:
        return q + " | count()"
    return q + f" | tail({it.limit})"


_GEN = {"kql": to_kql, "spl": to_spl, "hql": to_hql}

SYSTEM = ("You translate security questions into {lang} for ULPF. The table is `events` with fields: timestamp, "
          "category, event_type, action (failed|success|denied|blocked|allowed...), severity (0-10), source_ip, "
          "source_port, destination_ip, destination_port, protocol, device_vendor, device_product, message, "
          "user.name, rule.id, event_kind. Answer only JSON: {{\"query\": \"...\", \"explanation\": \"...\"}}.")


def translate(question: str, language: str = "kql", backend: Backend | None = None, engine=None) -> dict:
    language = {"spl2": "spl", "splunk": "spl", "kusto": "kql", "humio": "hql", "logscale": "hql"}.get(
        language.lower(), language.lower())
    if language not in _GEN:
        raise ValueError("language must be kql, spl or hql")
    if len(question) > 2000:
        raise ValueError("question too long (max 2000 characters)")
    from ulpf.query.engine import QueryEngine
    engine = engine or QueryEngine(None)
    it = understand(question)
    candidates: list[tuple[str, str]] = []
    if backend is not None and backend.name != "rules":
        try:
            out = parse_json(backend.generate(SYSTEM.format(lang=language.upper()), question, 400, grammar_json=True))
            if out and isinstance(out.get("query"), str):
                candidates.append(("model", out["query"].strip()))
        except ModelError:
            pass
    candidates.append(("grammar", _GEN[language](it)))
    errors = []
    for origin, q in candidates:
        try:
            _plan, sql = engine.compile(language, q)
            start = None
            if it.window and language != "kql":
                n, u = it.window
                secs = n * {"m": 60, "h": 3600, "d": 86400}[u]
                start = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=secs)).isoformat()
            return {"language": language, "query": q, "valid": True, "origin": origin, "start": start,
                    "explanation": explain(it), "sql_preview": sql[:400], "rejected": errors}
        except Exception as e:      # QuerySyntaxError and friends: try the next candidate
            errors.append({"origin": origin, "query": q, "error": str(e)[:300]})
    return {"language": language, "query": candidates[-1][1], "valid": False, "origin": "grammar",
            "explanation": explain(it), "rejected": errors}


def explain(it: Intent) -> str:
    parts = []
    if it.category:
        parts.append(f"{it.category} events")
    for f, op, v in it.filters:
        parts.append(f"{f} {'is one of' if op == 'in' else op} {v}")
    if it.severity:
        parts.append(f"severity >= {it.severity}")
    if it.window:
        parts.append(f"in the last {it.window[0]}{it.window[1]}")
    shape = (f"top {it.top} by {it.group}" if it.top and it.group else f"counted by {it.group}" if it.group
             else f"distinct {it.distinct}" if it.distinct else f"per {it.per}" if it.per
             else "total count" if it.count_only else f"latest {it.limit} events")
    return "Events: " + (", ".join(parts) or "all") + f"; result: {shape}."
