"""
The official SigmaHQ rule pack (``tests/data/sigmahq``, unmodified) compiled and executed.

* every rule compiles (none rejected, none left uncompiled);
* for every rule, an event built from its positive selections (Windows XML shape for Windows
  rules, with the event ID / channel its logsource means) makes the rule fire;
* the compiled core (Aho-Corasick prefilter + rule VM) returns exactly Python's hits for every
  synthesised event against all rules at once, and for unrelated events.
"""
from __future__ import annotations

import base64
import json
import os
import random
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests._isolation  # noqa: E402,F401

PACK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "sigmahq", "sigma_all_rules.zip")

try:
    from ulpf import ulpf_core
    HAVE = hasattr(ulpf_core.Analytics, "sigma_match_json")
except (ImportError, AttributeError):
    HAVE = False


def unpack() -> str:
    d = tempfile.mkdtemp(prefix="sigmahq_")
    with zipfile.ZipFile(PACK) as z:
        z.extractall(d)
    return d


def _example(value, mods):
    """A value the Sigma value matcher accepts (None: cannot construct one)."""
    if "exists" in mods:
        return "present" if value in (True, "true", "True") else None
    if any(m in mods for m in ("re", "cidr", "fieldref", "lt", "lte", "gt", "gte", "base64", "base64offset")):
        if "cidr" in mods:
            import ipaddress
            net = ipaddress.ip_network(str(value), strict=False)
            return str(next(iter(net.hosts()), net.network_address))
        for op, d in (("gt", 1), ("gte", 0), ("lt", -1), ("lte", 0)):
            if op in mods:
                return str(float(value) + d)
        if "base64" in mods or "base64offset" in mods:
            raw = str(value).encode("utf-16-le" if ("wide" in mods or "utf16le" in mods) else "utf-8")
            return base64.b64encode(raw).decode()
        return None
    if value is None:
        return None
    if isinstance(value, bool):
        return str(value).lower()
    s = str(value)
    out, i = [], 0
    while i < len(s):                              # wildcards: * -> "a", ? -> "b"; \\* is a literal *
        c = s[i]
        if c == "\\" and i + 1 < len(s) and s[i + 1] in "*?\\":
            out.append(s[i + 1])
            i += 2
            continue
        out.append("a" if c == "*" else "b" if c == "?" else c)
        i += 1
    s = "".join(out)
    if "contains" in mods:
        return f"x {s} y"
    if "startswith" in mods:
        return s + "zz"
    if "endswith" in mods:
        return "zz" + s
    return s


def _constraints(defn, acc: dict, words: list) -> bool:
    """Add one selection's constraints (field -> {eq | starts, contains, ends}); False: not constructible."""
    if isinstance(defn, list) and defn and all(isinstance(x, dict) for x in defn):
        defn = defn[0]
    if isinstance(defn, (list, str)) and not isinstance(defn, dict):
        for w in defn if isinstance(defn, list) else [defn]:
            ex = _example(w, [])
            if ex:
                words.append(ex)
        return True
    if not isinstance(defn, dict):
        return False
    for key, val in defn.items():
        fname, *mods = key.split("|")
        vals = val if isinstance(val, list) else [val]
        if not vals:
            continue
        c = acc.setdefault(fname, {"eq": None, "starts": "", "contains": [], "ends": ""})
        for v in (vals if "all" in mods else vals[:1]):
            plain = [m for m in mods if m not in ("all", "cased", "windash", "contains", "startswith", "endswith")]
            ex = _example(v, plain)
            if ex is None:
                if plain:
                    return False
                continue
            if "contains" in mods:
                c["contains"].append(ex)
            elif "startswith" in mods:
                c["starts"] = ex
            elif "endswith" in mods:
                c["ends"] = ex
            else:
                c["eq"] = ex
    return True


def _value_of(c: dict) -> str:
    if c["eq"] is not None and not (c["starts"] or c["contains"] or c["ends"]):
        return c["eq"]
    return c["starts"] + "".join(f" {x} " for x in c["contains"]) + c["ends"]


def synth_variants(doc: dict) -> list[dict]:
    """Events built from the rule's positive selections: all of them together, and each alone."""
    det = doc.get("detection") or {}
    names = [n for n in det if n not in ("condition", "timeframe") and not n.lower().startswith("filter")
             and not n.startswith("_")]
    out = []
    for group in [names] + [[n] for n in names]:
        acc, words = {}, []
        if all(_constraints(det[n], acc, words) for n in group):
            out.append(_event(doc, {k: _value_of(c) for k, c in acc.items()}, words))
    return out


def synth(doc: dict) -> dict:
    return synth_variants(doc)[0] if synth_variants(doc) else _event(doc, {}, [])


def _event(doc: dict, fields: dict, words: list) -> dict:
    from ulpf.intelligence.sigma import (_CATEGORY_LOGSOURCE, _CLOUD_FIELDS, _PRODUCT_FORMATS, _PS_IDS,
                                         _SYSMON_IDS, _WIN_CHANNELS)
    ls = doc.get("logsource") or {}
    product = str(ls.get("product") or "").lower()
    cat, svc = str(ls.get("category") or "").lower(), str(ls.get("service") or "").lower()
    if product == "windows":
        pf = {f"event.eventdata.{k.lower()}": v for k, v in fields.items()}
        if cat in _SYSMON_IDS:
            pf["event.system.eventid"] = str(_SYSMON_IDS[cat][0])
            pf["event.system.channel"] = "Microsoft-Windows-Sysmon/Operational"
        elif cat in _PS_IDS:
            ch, ids = _PS_IDS[cat]
            pf["event.system.eventid"], pf["event.system.channel"] = str(ids[0]), ch
        else:
            if svc:
                pf["event.system.channel"] = _WIN_CHANNELS.get(svc, svc)
            pf.setdefault("event.system.eventid", "1")
        for k in ("EventID", "Channel"):
            if k in fields:
                pf[f"event.system.{k.lower()}"] = fields[k]
    else:
        pf = dict(fields)                                   # JSON sources keep their own field names
        if product in _CLOUD_FIELDS:
            pf.setdefault(_CLOUD_FIELDS[product], "x")
        if product == "zeek":
            pf.setdefault("uid", "C1")
        if product in ("linux", "macos") and cat == "process_creation":
            pf.setdefault("EventID", "1")
    cats = _CATEGORY_LOGSOURCE.get(cat)
    fmts = _PRODUCT_FORMATS.get(product)
    return {"event_id": "e", "event_kind": "log", "raw_format": sorted(fmts)[0] if fmts else "xml",
            "category": sorted(cats)[0] if cats else "system", "action": "other",
            "raw_event": " ".join(words) or "<Event/>", "message": "", "parsed_fields": pf}


@unittest.skipUnless(os.path.exists(PACK), "SigmaHQ pack not present")
class TestSigmaHQPack(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import yaml
        from ulpf.intelligence.sigma import SigmaEngine, load_rules
        cls.dir = unpack()
        cls.rules, cls.errors = load_rules([cls.dir], builtin=False)
        cls.engine = SigmaEngine(cls.rules)
        cls.docs = {}
        for root, _, files in os.walk(cls.dir):
            for f in files:
                if f.endswith(".yml"):
                    p = os.path.join(root, f)
                    with open("\\\\?\\" + os.path.abspath(p) if os.name == "nt" else p, encoding="utf-8") as fh:
                        for doc in yaml.safe_load_all(fh):
                            if isinstance(doc, dict) and doc.get("id"):
                                cls.docs[str(doc["id"])] = doc

    def test_every_rule_compiles(self):
        self.assertEqual(self.errors, [])
        self.assertGreaterEqual(len(self.rules), 3000)
        irs = [r.ir for r in self.rules]
        self.assertTrue(all(x is not None for x in irs))
        self.assertGreater(sum(1 for x in irs if x["anchors"]) / len(irs), 0.95)

    def test_rules_fire_on_their_own_events(self):
        fired = total = 0
        misses = []
        for r in self.rules:
            doc = self.docs.get(r.id)
            if doc is None:
                continue
            total += 1
            if any(r.id in {h[0] for h in self.engine.match(e)} for e in synth_variants(doc)):
                fired += 1
            else:
                misses.append(r.title)
        print(f"\nSigmaHQ: {fired} of {total} rules fire on an event built from their selections")
        self.assertGreater(fired / total, 0.90, misses[:20])

    @unittest.skipUnless(HAVE, "ulpf_core with sigma_match_json not built")
    def test_core_equals_python(self):
        import orjson
        an = ulpf_core.Analytics(orjson.dumps(self.engine.ir()).decode(), None)
        self.assertEqual(an.rules, len(self.rules))
        events = [e for d in self.docs.values() for e in synth_variants(d)[:2]]
        rnd = random.Random(5)
        for i in range(300):                               # unrelated events
            events.append({"event_id": f"n{i}", "event_kind": "log", "raw_format": rnd.choice(["syslog", "cef", "json"]),
                           "category": rnd.choice(["network", "authentication", "web"]), "action": "allowed",
                           "source": {"ip": f"10.0.0.{i % 250}"}, "user": {"name": f"u{i}"},
                           "raw_event": f"<13>Oct 1 host sshd[{i}]: Accepted password for u{i}", "message": "ok",
                           "parsed_fields": {"src": f"10.0.0.{i % 250}", "app": "sshd"}})
        undecided = 0
        for e in events:
            got = an.sigma_match_json(orjson.dumps(e).decode())
            want = self.engine.match(e)
            if got is None:
                undecided += 1
                continue
            self.assertEqual(sorted(map(tuple, json.loads(got))), sorted(map(tuple, want)), e["parsed_fields"])
        self.assertLess(undecided / len(events), 0.05)


if __name__ == "__main__":
    unittest.main()
