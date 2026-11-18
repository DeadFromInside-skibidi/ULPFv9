"""
Standard views (ulpf/engine/standards): OCSF 1.3.0, Google Security Operations
UDM and Microsoft Sentinel ASIM.

* every document of a corpus that exercises each mapped activity conforms to
  the bundled schema definitions (OCSF schema server, UDM field list and usage
  guide, ASIM reference pages);
* unified -> standard -> unified gives the event back, field for field; parsed
  fields come back as the facets the view wrote plus every vendor-only field;
* representative records land in the expected class / event type / schema;
* vendor extension namespaces are deterministic;
* documents from other producers (no x_ulpf block) import.
"""
from __future__ import annotations

import json
import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests._isolation  # noqa: E402,F401

from tests.standards_corpus import cloud_lines, events, windows_lines  # noqa: E402
from ulpf.engine.standards import asim, ocsf, udm  # noqa: E402
from ulpf.engine.standards.common import as_int  # noqa: E402
from ulpf.engine.standards.facets import CANDIDATES, unmapped_vendor_fields  # noqa: E402

VIEWS = {"ocsf": (ocsf._to_ocsf, ocsf.from_ocsf, ocsf.validate), "udm": (udm._to_udm, udm.from_udm, udm.validate),
         "asim": (asim._to_asim, asim.from_asim, asim.validate)}


def _event(line: str) -> dict:
    from ulpf.engine.pipeline import Pipeline
    r = Pipeline(enable_auto_parser=False).process_line(line)
    assert r.get("success"), line
    return json.loads(json.dumps(r["event"], default=str))


class TestStandards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = events(1200)

    def test_documents_conform(self):
        for name, (to, _back, validate) in VIEWS.items():
            bad = []
            for e in self.events:
                doc = to(e)[0]
                problems = validate(doc)
                if name == "udm":
                    for ent in udm.to_udm_entities(e):
                        problems += udm.validate_entity(ent)
                if problems:
                    bad.append(((e.get("raw_event") or "")[:120], problems[:3]))
            self.assertEqual(bad[:3], [], f"{name}: {len(bad)} of {len(self.events)} documents do not conform")

    def test_round_trip_gives_the_event_back(self):
        for name, (to, back, _v) in VIEWS.items():
            diffs = []
            for e in self.events:
                doc, f = to(e)
                e2 = back(json.loads(json.dumps(doc)))
                for k in set(e) | set(e2):
                    if k != "parsed_fields" and e.get(k) != e2.get(k):
                        diffs.append((name, k, e.get(k), e2.get(k)))
                p2 = e2["parsed_fields"]
                for k, v in unmapped_vendor_fields(e, f).items():
                    if p2.get(k) != v:
                        diffs.append((name, "vendor field " + k, v, p2.get(k)))
                for fac in f.emitted:
                    want, got = f.values[fac], p2.get(CANDIDATES[fac][0])
                    if got is None and fac.startswith("actor.process."):   # acting process of non-process classes
                        got = p2.get(CANDIDATES[fac.replace("actor.", "", 1)][0])
                    same = str(got) == str(want) or (fac.endswith(".pid") and as_int(got) == as_int(want)) \
                        or (fac == "dns.rcode" and (str(got).lower() == str(want).lower() or str(want).isdigit())) \
                        or (fac == "http.query" and str(want) in str(p2.get(CANDIDATES["http.url"][0]))) \
                        or (fac == "file.hashes" and all(h.split("=", 1)[1].lower() in
                                                         [str(x).lower() for x in p2.values()]
                                                         for h in str(want).split(",")))
                    if not same:
                        diffs.append((name, "facet " + fac, want, got))
            self.assertEqual(diffs[:3], [], f"{len(diffs)} differences")

    def test_activities_map_to_their_classes(self):
        w = windows_lines(random.Random(1))
        c = cloud_lines(random.Random(1))
        by_id = {}
        for line in w:
            eid = int(line.split("<EventID>")[1].split("<")[0])
            prov = "sysmon" if "Sysmon" in line else "sec"
            by_id[(prov, eid)] = line
        cases = [
            (by_id[("sysmon", 1)], (1007, 1), "PROCESS_LAUNCH", ("ProcessEvent", "ProcessCreated")),
            (by_id[("sec", 4625)], (3002, 1), "USER_LOGIN", ("Authentication", "Logon")),
            (by_id[("sysmon", 13)], (201002, 2), "REGISTRY_MODIFICATION", ("RegistryEvent", "RegistryValueSet")),
            (by_id[("sec", 4720)], (3001, 1), "USER_CREATION", ("UserManagement", "UserCreated")),
            (by_id[("sec", 4728)], (3006, 3), "GROUP_MODIFICATION", ("UserManagement", "UserAddedToGroup")),
            (by_id[("sysmon", 22)], (4003, 1), "NETWORK_DNS", ("Dns", "Query")),
            (by_id[("sysmon", 11)], (1001, 1), "FILE_CREATION", ("FileEvent", "FileCreated")),
            (by_id[("sysmon", 7)], (1005, 1), "PROCESS_MODULE_LOAD", ("AuditEvent", "Execute")),
            (by_id[("sec", 1102)], (1008, 1), "SYSTEM_AUDIT_LOG_WIPE", ("AuditEvent", "Clear")),
            (by_id[("sec", 7045)], (201004, 1), "SERVICE_CREATION", ("AuditEvent", "Install")),
            (by_id[("sec", 4698)], (1006, 1), "SCHEDULED_TASK_CREATION", ("AuditEvent", "Create")),
            (c[0].replace('"GetObject"', '"DeleteBucket"').replace('"PutBucketPolicy"', '"DeleteBucket"')
             .replace('"CreateUser"', '"DeleteBucket"'), (6003, 4), "RESOURCE_DELETION", ("AuditEvent", "Delete")),
        ]
        for line, (cls, act), udm_type, (schema, etype) in cases:
            e = _event(line)
            o = ocsf.to_ocsf(e)
            self.assertEqual((o["class_uid"], o["activity_id"]), (cls, act), line[:120])
            self.assertEqual(udm.to_udm(e)["metadata"]["event_type"], udm_type, line[:120])
            a = asim.to_asim(e)
            self.assertEqual((a["EventSchema"], a["EventType"]), (schema, etype), line[:120])
        # a failed logon is a failure in all three
        e = _event(by_id[("sec", 4625)])
        self.assertEqual(ocsf.to_ocsf(e)["status_id"], 2)
        self.assertEqual(asim.to_asim(e)["EventResult"], "Failure")
        self.assertEqual(asim.to_asim(e)["EventResultDetails"], "No such user or password")
        # the process created by Sysmon 1: name, command line, parent, hashes
        p = ocsf.to_ocsf(_event(by_id[("sysmon", 1)]))["process"]
        self.assertEqual(p["name"], "powershell.exe")
        self.assertEqual(p["parent_process"]["name"], "cmd.exe")
        self.assertEqual({h["algorithm_id"] for h in p["file"]["hashes"]}, {1, 3})

    def test_vendor_namespace_is_deterministic(self):
        line = ("CEF:0|Check Point|VPN-1 & FireWall-1|R81.20|Drop|Rule Drop|8|src=45.33.32.156 dst=10.0.1.50 "
                "spt=12345 dpt=4444 proto=TCP act=Drop zz_custom=1 aa_custom=2 cs1Label=policy cs1=strict")
        e = _event(line)
        a, b = ocsf.to_ocsf(e), ocsf.to_ocsf(json.loads(json.dumps(e)))
        self.assertEqual(json.dumps(a, sort_keys=False), json.dumps(b, sort_keys=False))
        ns = a["unmapped"]["x_check_point"]
        self.assertEqual(list(ns), sorted(ns))
        self.assertEqual(ns["zz_custom"], "1")
        self.assertIn("x_check_point", udm.to_udm(e)["additional"])
        self.assertIn("x_check_point", asim.to_asim(e)["AdditionalFields"])

    def test_imports_documents_of_other_producers(self):
        doc = {"class_uid": 4001, "category_uid": 4, "activity_id": 6, "type_uid": 400106, "severity_id": 4,
               "time": 1760000000000, "metadata": {"version": "1.3.0", "uid": "abc",
                                                  "product": {"name": "NGFW", "vendor_name": "Acme"}},
               "src_endpoint": {"ip": "10.0.0.1", "port": 5555}, "dst_endpoint": {"ip": "8.8.8.8", "port": 53},
               "connection_info": {"protocol_name": "udp", "direction_id": 2}, "disposition": "Blocked",
               "message": "dns blocked", "unmapped": {"x_acme": {"policy_tag": "p1"}}}
        e = ocsf.from_ocsf(doc)
        self.assertEqual((e["source"]["ip"], e["destination"]["port"], e["network"]["protocol"]),
                         ("10.0.0.1", 53, "UDP"))
        self.assertEqual((e["category"], e["action"], e["severity_label"]), ("network", "blocked", "high"))
        self.assertEqual(e["device"]["vendor"], "Acme")
        self.assertEqual(e["parsed_fields"]["policy_tag"], "p1")
        u = {"metadata": {"event_timestamp": "2023-07-03T12:14:38.164507Z", "event_type": "FILE_MODIFICATION",
                          "vendor_name": "Acme", "product_name": "EDR"},
             "principal": {"hostname": "pinguino-01"}, "target": {"file": {"full_path": "foo.bar"}}}
        self.assertEqual(udm.validate(u), [])
        e = udm.from_udm(u)
        self.assertEqual((e["category"], e["source"]["hostname"], e["parsed_fields"]["file.path"]),
                         ("endpoint", "pinguino-01", "foo.bar"))
        row = {"TimeGenerated": "2026-10-21T10:00:00Z", "EventSchema": "Authentication", "EventType": "Logon",
               "EventResult": "Failure", "EventSeverity": "Medium", "TargetUsername": "alice",
               "SrcIpAddr": "203.0.113.9", "EventVendor": "Okta", "EventProduct": "Okta", "EventUid": "u1"}
        e = asim.from_asim(row)
        self.assertEqual((e["category"], e["user"]["name"], e["source"]["ip"], e["action"]),
                         ("authentication", "alice", "203.0.113.9", "failed"))

    def test_validators_report_problems(self):
        e = _event("CEF:0|V|P|1|2|allow|7|src=1.2.3.4 dst=5.6.7.8 spt=1 dpt=80 proto=TCP act=allow")
        o = ocsf.to_ocsf(e)
        bad = {**o, "bogus": 1, "severity_id": 42}
        bad.pop("metadata")
        problems = ocsf.validate(bad)
        self.assertTrue(any("bogus" in p for p in problems))
        self.assertTrue(any("severity_id" in p for p in problems))
        self.assertTrue(any("metadata" in p and "required" in p for p in problems))
        u = udm.to_udm(e)
        u["metadata"]["event_type"] = "NOT_A_TYPE"
        self.assertTrue(udm.validate(u))
        a = asim.to_asim(e)
        a["NotAColumn"] = 1
        a.pop("EventCount")
        problems = asim.validate(a)
        self.assertTrue(any("NotAColumn" in p for p in problems) and any("EventCount" in p for p in problems))


if __name__ == "__main__":
    unittest.main()
