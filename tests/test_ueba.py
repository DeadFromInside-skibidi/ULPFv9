"""
UEBA: identity resolution across directory systems, time-ranged asset bindings and CMDB
context, session stitching, impossible travel (vectorised Haversine), peer-group hours,
privilege escalation detectors, bounded memory with SQLite persistence, and the runtime API.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import socket
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests._isolation  # noqa: E402,F401

from ulpf.ueba.engine import UebaEngine  # noqa: E402
from ulpf.ueba.identity import parse_identity  # noqa: E402
from ulpf.ueba.models import activity, haversine_km  # noqa: E402

T0 = dt.datetime(2026, 11, 2, 9, 0, tzinfo=dt.timezone.utc).timestamp()     # a Monday


def proj(t, user=None, email=None, uid=None, ip="10.0.0.5", host=None, product=None, category="authentication",
         action="success", message="", lat=None, lon=None, country=None, bytes_out=None, token=None, mac=None,
         event_type=None, dev_ip=None):
    return {"event_id": f"e{t}-{user}-{product}", "timestamp": dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat(),
            "category": category, "action": action, "severity": 3, "message": message, "event_type": event_type,
            "raw_format": "test", "source": {"ip": ip, "hostname": None, "mac": mac, "port": None},
            "destination": {"ip": None, "hostname": None, "port": None},
            "device": {"hostname": host, "ip": dev_ip, "product": product, "vendor": None},
            "user": {"name": user, "domain": None, "id": uid, "email": email, "source": None},
            "network": {"session_id": token, "bytes_in": None, "bytes_out": bytes_out, "protocol": None},
            "threat": {}, "rule": {}, "geo": {"src_country_code": country, "src_city": None, "src_latitude": lat,
                                              "src_longitude": lon}}


def engine(**opts):
    opts.setdefault("realm_aliases", [["corp", "corp.com", "CORP.COM"]])
    return UebaEngine(tempfile.mkdtemp(prefix="ulpf_ueba_"), opts)


class TestIdentity(unittest.TestCase):
    def test_parsing(self):
        cases = {"CORP\\jdoe": ("ad", "jdoe", "corp"), "jdoe@corp.com": ("upn", "jdoe", "corp.com"),
                 "JDoe@CORP.COM": ("kerberos", "jdoe", "corp.com"),
                 "arn:aws:iam::123456789012:user/jdoe": ("aws_user", "jdoe", "123456789012"),
                 "arn:aws:sts::123456789012:assumed-role/Admin/jdoe": ("aws_role", "jdoe", "123456789012"),
                 "uid=1000(jdoe)": ("linux", "jdoe", ""), "CN=jdoe,OU=Staff,DC=corp,DC=com": ("dn", "jdoe", "corp.com"),
                 "jdoe": ("plain", "jdoe", "")}
        for raw, want in cases.items():
            i = parse_identity(raw)
            self.assertEqual((i.kind, i.name, i.realm), want, raw)
        self.assertIsNone(parse_identity("-"))

    def test_one_actor_across_systems_and_generic_names_apart(self):
        u = engine()
        ids = ["CORP\\jdoe", "jdoe@corp.com", "JDoe@CORP.COM", "CN=jdoe,OU=Staff,DC=corp,DC=com", "jdoe"]
        actors = {u.ident.resolve([x], T0) for x in ids}
        self.assertEqual(len(actors), 1)
        self.assertNotEqual(u.ident.resolve(["OTHERCO\\jdoe"], T0), next(iter(actors)))   # another organisation
        self.assertNotEqual(u.ident.resolve(["CORP\\root"], T0), u.ident.resolve(["root@other.org"], T0))
        # an AWS identity joins through the event that carries both (co-occurrence)
        aws = u.ident.resolve(["arn:aws:iam::123456789012:user/john.d"], T0)
        self.assertNotEqual(aws, next(iter(actors)))
        both = u.ident.resolve(["arn:aws:iam::123456789012:user/john.d", "jdoe@corp.com"], T0)
        self.assertEqual(u.ident.resolve(["arn:aws:iam::123456789012:user/john.d"], T0), both)
        self.assertEqual(u.ident.resolve(["CORP\\jdoe"], T0), both)
        self.assertEqual(len(u.ident.aliases(both)), 6)        # ad, upn, kerberos, dn, plain, aws

    def test_directory_import(self):
        u = engine()
        n = u.ident.import_directory([{"id": "CORP\\asmith", "aliases": ["alice.smith@corp.com", "uid=1001(asmith)"],
                                       "department": "Finance", "title": "Analyst", "display_name": "Alice Smith"}])
        self.assertEqual(n, 1)
        a = u.ident.resolve(["alice.smith@corp.com"], T0)
        self.assertEqual(u.ident.resolve(["uid=1001(asmith)"], T0), a)
        self.assertEqual(u.ident.attributes(a)["department"], "Finance")
        self.assertEqual(u.actor_view("CORP\\asmith")["display"], "Alice Smith")


class TestAssets(unittest.TestCase):
    def test_bindings_over_time_cmdb_and_zones(self):
        u = engine(zones=[{"cidr": "10.20.0.0/16", "name": "datacenter", "criticality": "high"},
                          {"cidr": "10.0.0.0/8", "name": "corporate", "criticality": 1}])
        u.assets.import_cmdb([{"hostname": "db01", "owner": "dba-team", "criticality": "critical", "os": "RHEL 9"}])
        u.assets.observe("10.20.1.5", T0, mac="AA:BB:CC:00:00:01", hostname="web01")
        u.assets.observe("10.20.1.5", T0 + 3600, mac="aa:bb:cc:00:00:01", hostname="web01")
        u.assets.observe("10.20.1.5", T0 + 7200, mac="aa:bb:cc:00:00:02", hostname="db01")    # re-leased
        self.assertEqual(u.assets.binding_at("10.20.1.5", T0 + 1800)["hostname"], "web01")
        later = u.assets.resolve("10.20.1.5", ts=T0 + 9000)
        self.assertEqual((later["hostname"], later["owner"], later["criticality"], later["zone"]),
                         ("db01", "dba-team", 4, "datacenter"))
        early = u.assets.resolve("10.20.1.5", ts=T0 + 100)
        self.assertEqual((early["hostname"], early["criticality"]), ("web01", 3))                 # the zone's
        self.assertEqual(len(u.assets.history("10.20.1.5")), 2)
        self.assertEqual(u.assets.resolve("10.9.9.9")["zone"], "corporate")


class TestTimelines(unittest.TestCase):
    def test_session_stitching(self):
        u = engine()
        steps = [proj(T0, "CORP\\jdoe", category="vpn", product="GlobalProtect", message="GlobalProtect login"),
                 proj(T0 + 30, "jdoe@corp.com", category="authentication", product="Okta",
                      message="Okta Verify push approved"),
                 proj(T0 + 90, "jdoe", product="sshd", host="bastion01"),
                 proj(T0 + 300, "jdoe", category="other", product="postgres", host="db01",
                      message="SELECT * FROM payroll"),
                 proj(T0 + 900, "jdoe@corp.com", category="other", product="aws-cli",
                      message="aws s3 sync s3://finance-reports ."),
                 proj(T0 + 9000, "jdoe", product="sshd", host="bastion01")]                     # after a gap
        self.assertEqual([activity(p) for p in steps],
                         ["vpn_logon", "mfa", "ssh_logon", "db_query", "cloud_storage", "ssh_logon"])
        u.observe(steps)
        tl = u.timeline("CORP\\jdoe")
        self.assertEqual([s["steps"] for s in tl["sessions"]],
                         [["vpn_logon", "mfa", "ssh_logon", "db_query", "cloud_storage"], ["ssh_logon"]])


class TestAnomalies(unittest.TestCase):
    def test_haversine_and_impossible_travel(self):
        km = haversine_km([40.7128], [-74.0060], [51.5074], [-0.1278]).to_pylist()[0]
        self.assertAlmostEqual(km, 5570, delta=10)                                             # NYC - London
        u = engine()
        a = u.observe([proj(T0, "CORP\\jdoe", lat=40.7128, lon=-74.0060, country="US", ip="198.51.100.7"),
                       proj(T0 + 3600, "jdoe@corp.com", lat=51.5074, lon=-0.1278, country="GB", ip="203.0.113.9"),
                       proj(T0, "CORP\\bob", lat=40.7, lon=-74.0, country="US"),
                       proj(T0 + 3600 * 9, "CORP\\bob", lat=51.5, lon=-0.12, country="GB")])           # 620 km/h
        travel = [x for x in a if x["kind"] == "impossible_travel"]
        self.assertEqual([x["display"] for x in travel], ["jdoe"])
        self.assertGreater(travel[0]["detail"]["speed_kmh"], 5000)

    def test_peer_group_unusual_hour_and_rare_app(self):
        u = engine(warmup_logons=20, warmup_events=20)
        rows = [{"id": f"CORP\\fin{i}", "department": "Finance"} for i in range(10)]
        u.ident.import_directory(rows)
        evs = []
        for day in range(10):
            for i in range(10):
                for h in (0, 3, 6):                                        # logons 09:00, 12:00, 15:00
                    evs.append(proj(T0 + day * 86400 + h * 3600 + i, f"CORP\\fin{i}", product="excel"))
        u.observe(evs)
        u.maintenance(T0 + 11 * 86400, force=True)                       # peer groups built
        a = u.observe([proj(T0 + 11 * 86400 - 6 * 3600, "CORP\\fin3", product="excel"),     # 03:00 UTC
                       proj(T0 + 11 * 86400, "CORP\\fin4", product="mimikatz")])
        kinds = {(x["kind"], x["display"]) for x in a}
        self.assertIn(("unusual_hour", "fin3"), kinds)
        self.assertIn(("rare_application", "fin4"), kinds)
        self.assertEqual(u.peers.group_of[u.ident.resolve(["CORP\\fin1"])], "dept:finance")

    def test_privilege_escalation_detectors(self):
        u = engine(warmup_events=10, egress_min_bytes=1000)
        u.assets.import_cmdb([{"hostname": "dc01", "criticality": "critical", "owner": "it"}])
        base = []
        for day in range(6):
            for k in range(5):
                t = T0 + day * 86400 + k * 600
                base.append(proj(t, "CORP\\ops", product="sshd", host="app01", bytes_out=500))
                if k == 0:
                    base.append(proj(t + 1, "CORP\\ops", category="system", product="sudo",
                                     message="sudo: ops : USER=root ; COMMAND=/bin/ls"))
        u.observe(base)
        d6 = T0 + 6 * 86400
        a = u.observe([proj(d6 + i, "CORP\\ops", category="system", product="sudo",
                            message="sudo: ops : USER=root ; COMMAND=/bin/sh") for i in range(8)]
                      + [proj(d6 + 100, "CORP\\ops", product="sshd", host="dc01"),
                         proj(d6 + 200, "CORP\\ops", category="other", product="aws",
                              event_type="CreateAccessKey", message="iam CreateAccessKey"),
                         proj(d6 + 300, "CORP\\ops", product="sshd", host="app01", bytes_out=10_000_000),
                         proj(d6 + 400, "CORP\\ops", product="okta", token="tok-1", ip="198.51.100.1"),
                         proj(d6 + 500, "CORP\\ops", product="okta", token="tok-1", ip="203.0.113.50")])
        kinds = sorted({x["kind"] for x in a})
        # rare_application too: ops' behaviour cluster never used the aws or okta tools
        self.assertEqual(kinds, ["abnormal_privilege", "egress_spike", "first_asset_access", "privileged_api_first_use",
                                 "rare_application", "token_reuse"])
        fa = next(x for x in a if x["kind"] == "first_asset_access")
        self.assertEqual((fa["detail"]["asset"], fa["detail"]["criticality"]), ("dc01", 4))
        # once per key: the same burst again raises nothing new
        self.assertEqual(u.observe([proj(d6 + 600, "CORP\\ops", product="okta", token="tok-1", ip="203.0.113.50")]), [])


class TestBoundedState(unittest.TestCase):
    def test_eviction_and_persistence(self):
        d = tempfile.mkdtemp(prefix="ulpf_ueba_b_")
        u = UebaEngine(d, {"profile_cache": 100, "identity_cache": 200})
        u.observe([proj(T0 + i, f"CORP\\user{i}", product="sshd", host=f"h{i % 7}") for i in range(1000)])
        self.assertLessEqual(len(u.profiles), 100)
        self.assertLessEqual(len(u.ident.cache), 200)
        self.assertEqual(u.ident.count(), (1000, 1000))
        u.close()
        u2 = UebaEngine(d, {})
        v = u2.actor_view("CORP\\user7")
        self.assertEqual((v["events"], v["assets"]), (1, ["h0"]))
        u2.close()


class TestUebaRuntime(unittest.TestCase):
    def test_runtime_actor_timeline_and_api(self):
        import urllib.request
        from tests.test_inputs import free_port, start_runtime, wait_for
        d = tempfile.mkdtemp(prefix="ulpf_ueba_rt_")
        directory = os.path.join(d, "directory.json")
        with open(directory, "w", encoding="utf-8") as f:
            json.dump([{"id": "CORP\\jdoe", "aliases": ["jdoe@corp.com"], "department": "Engineering",
                        "display_name": "John Doe"}], f)
        port = free_port()
        rt = start_runtime(d, [{"type": "syslog", "name": "tcp", "protocol": "tcp", "host": "127.0.0.1", "port": port}],
                           api=True, analytics={"correlation": {"enabled": True}, "anomaly": {"enabled": False},
                                                "drift": {"enabled": False},
                                                "ueba": {"directory": directory,
                                                         "realm_aliases": [["corp", "corp.com"]]}})
        try:
            lines = [b"<38>Nov  2 09:00:00 gw sshd[1]: Accepted password for jdoe from 10.4.4.4 port 22 ssh2\n",
                     b"<38>Nov  2 09:05:00 gw sudo: jdoe : TTY=pts/0 ; PWD=/home/jdoe ; USER=root ; COMMAND=/bin/ls\n"]
            with socket.create_connection(("127.0.0.1", port)) as c:
                c.sendall(b"".join(lines))
            base = rt.api_server.url

            def get(path):
                with urllib.request.urlopen(base + path, timeout=10) as r:
                    return json.loads(r.read())
            self.assertTrue(wait_for(lambda: rt.correlator.ueba.stats["events"] >= 2, 30))
            v = get("/api/v1/ueba/actors/jdoe@corp.com")
            self.assertEqual((v["display"], v["attributes"]["department"]), ("John Doe", "Engineering"))
            tl = get("/api/v1/ueba/timeline/jdoe")
            self.assertEqual(tl["sessions"][0]["steps"], ["ssh_logon", "privilege"])
            self.assertIn("groups", get("/api/v1/ueba/peer-groups"))
        finally:
            rt.stop()
        self.assertTrue(os.path.exists(os.path.join(d, "ueba", "ueba.db")))


if __name__ == "__main__":
    unittest.main()
