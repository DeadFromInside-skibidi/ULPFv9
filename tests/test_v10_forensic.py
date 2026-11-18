"""v10 forensic integrity: correlation side table, standalone verifier, key providers."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

import pyarrow as pa


def _event(eid: str, i: int) -> dict:
    return {"event_id": eid, "timestamp": f"2026-01-01T00:00:{i:02d}Z", "category": "authentication",
            "event_type": "logon", "action": "failure", "severity": 5, "severity_label": "medium",
            "source": {"ip": f"10.0.0.{i}"}, "raw_event": f"line {i}", "raw_format": "syslog",
            "evidence": {"raw_hash": "ab" * 32}, "message": f"m{i}", "tags": []}


class CorrelationIsolation(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_correlating_keeps_row_mac_valid(self):
        from ulpf.storage.database import EVENT_COLUMNS, Database, event_to_row, row_mac, rows_to_arrow, sign_row
        key = os.urandom(32)
        db = Database(os.path.join(self.d, "s.duckdb"))
        rows = [sign_row(key, event_to_row(_event(f"e{i}", i))) for i in range(5)]
        db.store_arrow_table(rows_to_arrow(rows))
        db.set_correlation(["e1", "e3"], "grp1")
        db.set_correlation(["e3"], "grp2")          # newest assignment wins
        cols = ", ".join(EVENT_COLUMNS)
        stored = db.conn.execute(f"SELECT {cols} FROM events ORDER BY event_id").fetchall()
        i_mac = EVENT_COLUMNS.index("row_mac")
        for r in stored:
            self.assertEqual(row_mac(key, r), r[i_mac], r[0])
        self.assertEqual(db.correlations_for(["e1", "e3", "e4"]), {"e1": "grp1", "e3": "grp2"})
        self.assertEqual(db.get_event("e3")["correlation_id"], "grp2")
        got = {e["event_id"] for e in db.query_events({"correlation_id": "grp1"})}
        self.assertEqual(got, {"e1"})
        self.assertEqual({e["event_id"] for e in db.query_events({"correlation_id": "grp2"})}, {"e3"})
        db.close()



class ForensicVerifier(unittest.TestCase):
    """Real journal + sealer on disk, verified by the standalone tool; then single-bit tampering."""

    @classmethod
    def setUpClass(cls):
        from ulpf.runtime.evidence import Sealer
        from ulpf.runtime.journal import Journal
        cls.d = tempfile.mkdtemp()
        os.environ.pop("ULPF_EVIDENCE_PASSPHRASE", None)
        jdir = os.path.join(cls.d, "journal")
        cls.jdir = jdir
        j = Journal(jdir, sync="always")
        ev = os.path.join(cls.d, "evidence")
        sealer = Sealer(os.path.join(ev, "seals"), "n1", 50, 3600)
        j.add_listener(sealer.on_append)
        for b in range(6):
            j.append("10.0.0.1", "syslog", [f"<13>Jan 1 host app[{b}]: event {b}-{i} user=alice".encode()
                                            for i in range(20)])
        sealer.seal_now()
        sealer.seal_now()
        sealer.close()
        j.close()
        cls.seals = os.path.join(ev, "seals")
        cls.pub = os.path.join(ev, "evidence.pub")
        with open(os.path.join(cls.seals, "sealer.state"), encoding="utf-8") as f:
            cls.state = json.load(f)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def _verify(self, jdir):
        from ulpf.forensic_verify import verify_journal
        from ulpf.compliance.verify_pack import public_key_raw
        with open(self.pub, "rb") as f:
            pub = public_key_raw(f.read())
        return verify_journal(jdir, self.seals, pub)

    def test_clean_journal_verifies(self):
        res = self._verify(self.jdir)
        self.assertTrue(res["valid"], res["problems"])
        self.assertEqual(res["records"], 120)
        self.assertGreaterEqual(res["merkle_roots_checked"], 3)
        self.assertGreaterEqual(res["signatures_checked"], 3)

    def test_one_time_key_not_plaintext_at_rest(self):
        self.assertNotIn("fs_sk", self.state)
        self.assertIn("ct", self.state["fs_sk_enc"])

    def test_single_bit_flip_located_exactly(self):
        t = tempfile.mkdtemp()
        try:
            dst = os.path.join(t, "journal")
            shutil.copytree(self.jdir, dst)
            seg = sorted(n for n in os.listdir(dst) if n.endswith(".ulj"))[0]
            path = os.path.join(dst, seg)
            with open(path, "rb") as f:
                data = bytearray(f.read())
            target = data.index(b"event 3-7 ") + 6         # inside the raw bytes of record 3*20+7+1
            data[target] ^= 0x10                          # bit 4
            with open(path, "wb") as f:
                f.write(data)
            res = self._verify(dst)
            self.assertFalse(res["valid"])
            crc = [p for p in res["problems"] if p["kind"] == "block_crc"][0]
            self.assertEqual((crc["offset"], crc["bit"]), (target, 4))
            self.assertEqual(crc["seq_altered"], 68)
            rec = [p for p in res["problems"] if p["kind"] == "record_hash"][0]
            self.assertEqual(rec["seq"], 68)
            self.assertTrue(rec["offset"] <= target < rec["offset"] + rec["length"])
        finally:
            shutil.rmtree(t, ignore_errors=True)

    def test_edited_seal_detected(self):
        t = tempfile.mkdtemp()
        try:
            sd = os.path.join(t, "seals")
            shutil.copytree(self.seals, sd)
            n = sorted(x for x in os.listdir(sd) if x.startswith("seal-"))[1]
            with open(os.path.join(sd, n), encoding="utf-8") as f:
                s = json.load(f)
            s["count"] += 1
            with open(os.path.join(sd, n), "w", encoding="utf-8") as f:
                json.dump(s, f)
            from ulpf.forensic_verify import verify_journal
            from ulpf.compliance.verify_pack import public_key_raw
            with open(self.pub, "rb") as f:
                res = verify_journal(self.jdir, sd, public_key_raw(f.read()))
            self.assertIn("seal_hash", {p["kind"] for p in res["problems"]})
        finally:
            shutil.rmtree(t, ignore_errors=True)

    def test_cli_exit_codes(self):
        from ulpf.forensic_verify import main
        import contextlib, io
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["journal", "--journal", self.jdir, "--seals", self.seals, "--pubkey", self.pub]), 0)


class HardwareProviders(unittest.TestCase):
    def test_pkcs11_signer_with_fake_module(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from ulpf.runtime import hwkeys
        from ulpf.runtime.keys import raw_public, verify_signature

        class FakeModule:
            def __init__(self, path):
                self.objs = {}
            def slots(self):
                return [7]
            def token_label(self, s):
                return "ULPF-HSM"
            def open(self, slot, pin):
                assert pin == b"123456"
                return 1
            def find(self, s, cls, label):
                return self.objs.get((cls, label))
            def generate_ed25519(self, s, label):
                self.sk = Ed25519PrivateKey.generate()
                self.objs[(hwkeys.CKO_PUBLIC_KEY, label)] = 10
                self.objs[(hwkeys.CKO_PRIVATE_KEY, label)] = 11
                return 10, 11
            def attribute(self, s, obj, attr):
                return b"\x04\x20" + raw_public(self.sk)       # DER OCTET STRING
            def sign(self, s, key, data):
                assert key == 11
                return self.sk.sign(data)

        os.environ["ULPF_PKCS11_PIN"] = "123456"
        try:
            hwkeys._modules.clear()
            key = hwkeys.pkcs11_key({"module": "fake.so", "token_label": "ULPF-HSM"}, "ulpf-evidence",
                                    module_factory=FakeModule)
        finally:
            os.environ.pop("ULPF_PKCS11_PIN", None)
        sig = key.sign(b"seal")
        self.assertTrue(verify_signature(raw_public(key), sig.hex(), b"seal"))
        with self.assertRaises(TypeError):
            key.private_bytes()

    @unittest.skipUnless(os.name == "nt", "CNG key storage is Windows-only")
    def test_tpm_sealed_key_roundtrip_cng_software_ksp(self):
        from ulpf.runtime import hwkeys
        d = tempfile.mkdtemp()
        w = hwkeys.tpm_wrapper({"backend": "software-test", "key_name": "ULPF-UnitTest-KEK"}, d)
        try:
            k1 = hwkeys.tpm_sealed_key(os.path.join(d, "evidence.pem"), {}, wrapper=w)
            k2 = hwkeys.tpm_sealed_key(os.path.join(d, "evidence.pem"), {}, wrapper=w)
            self.assertEqual(k1.public_key().public_bytes_raw(), k2.public_key().public_bytes_raw())
            with open(os.path.join(d, "evidence.pem.tpm"), encoding="utf-8") as f:
                doc = json.load(f)
            self.assertNotIn(k1.private_bytes_raw().hex(), json.dumps(doc))
        finally:
            try:
                w.delete()
            except Exception:
                pass
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
