"""Phase 1 / Phase 2 hardening: packaging, API roles, shared APG engine, Ed25519 + forward-secure
evidence, parser provenance, egress DNS refresh and native-code lockdown."""
from __future__ import annotations

import json
import os
import queue
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tests._isolation  # noqa: E402,F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------
# Bug 1: packaging
# ---------------------------------------------------------------------------

class TestPackaging(unittest.TestCase):
    def _pyproject(self) -> dict:
        try:
            import tomllib
        except ImportError:
            raise unittest.SkipTest("tomllib needs Python 3.11+")
        with open(os.path.join(ROOT, "pyproject.toml"), "rb") as f:
            return tomllib.load(f)

    def test_only_the_ulpf_package_is_installed(self):
        find = self._pyproject()["tool"]["setuptools"]["packages"]["find"]
        self.assertEqual(find["include"], ["ulpf*"])
        for p in ("benchmarks*", "tests*", "native*", "docs*"):
            self.assertIn(p, find["exclude"])
        from setuptools import find_packages
        pkgs = find_packages(ROOT, include=find["include"], exclude=find["exclude"])
        self.assertIn("ulpf", pkgs)
        self.assertFalse([p for p in pkgs if not p.startswith("ulpf")], pkgs)

    def test_dev_extra_has_the_toolchain(self):
        dev = " ".join(self._pyproject()["project"]["optional-dependencies"]["dev"])
        for tool in ("pytest", "pytest-cov", "pytest-asyncio", "hypothesis", "httpx", "maturin", "ruff", "mypy"):
            self.assertIn(tool, dev)

    def test_clean_repo_lists_then_removes_only_artifacts(self):
        sys.path.insert(0, os.path.join(ROOT, "scripts"))
        import clean_repo
        d = tempfile.mkdtemp(prefix="ulpf_clean_")
        files = {
            "native/ulpf_core/target/release/x.dll": True, "build/lib/a.py": True, ".hypothesis/c": True,
            "benchmarks/results/live/corpus_100000_42.log": True, "benchmarks/results/a/results.zip": True,
            "benchmarks/results.zip": True, "ulpf/ulpf_core.pyd": True, "ulpf/sub/__pycache__/m.pyc": True,
            "benchmarks/results/live/summary.json": False, "benchmarks/suite.py": False, "ulpf/main.py": False,
            "python311/__pycache__/keep.pyc": False,
        }
        for rel in files:
            p = os.path.join(d, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write("x")
        from contextlib import redirect_stdout
        import io
        with redirect_stdout(io.StringIO()):
            self.assertEqual(clean_repo.main(["--root", d]), 0)
        self.assertTrue(all(os.path.exists(os.path.join(d, r)) for r in files))     # dry run
        with redirect_stdout(io.StringIO()):
            self.assertEqual(clean_repo.main(["--root", d, "--yes"]), 0)
        for rel, removed in files.items():
            self.assertEqual(not os.path.exists(os.path.join(d, rel)), removed, rel)


# ---------------------------------------------------------------------------
# Bug 2: v8 API roles
# ---------------------------------------------------------------------------

class TestV8ApiRoles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import uvicorn
        except ImportError:
            raise unittest.SkipTest("uvicorn not installed")
        from ulpf.api.app import create_app
        from ulpf.api.auth import new_key
        d = tempfile.mkdtemp(prefix="ulpf_rbac_")
        cls.keys_file = os.path.join(d, "keys.json")
        cls.k = {r: new_key(cls.keys_file, r, r) for r in ("read", "write", "admin")}
        cls._saved = {k: os.environ.pop(k, None) for k in ("ULPF_API_KEY", "ULPF_API_KEYS_FILE")}
        os.environ["ULPF_API_KEYS_FILE"] = cls.keys_file
        cls.port = free_port()
        cls.server = uvicorn.Server(uvicorn.Config(create_app(), host="127.0.0.1", port=cls.port,
                                                   log_level="warning"))
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()
        deadline = time.time() + 20
        while not cls.server.started and time.time() < deadline:
            time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.thread.join(timeout=10)
        os.environ.pop("ULPF_API_KEYS_FILE", None)
        for k, v in cls._saved.items():
            if v is not None:
                os.environ[k] = v

    def call(self, method, path, role=None, body=None):
        import urllib.error
        import urllib.request
        headers = {"Content-Type": "application/json"}
        if role:
            headers["X-API-Key"] = self.k[role]
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", method=method, headers=headers,
                                     data=json.dumps(body if body is not None else {}).encode()
                                     if method == "POST" else None)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    def test_read_key_cannot_mutate(self):
        for path, body in (("/api/v1/ingest", {"raw": "CEF:0|V|P|1|1|n|5|src=10.0.0.1"}),
                           ("/api/v1/ingest/batch", {"lines": ["a"]}),
                           ("/api/v1/auto-learn", {"lines": ["x"]}),
                           ("/api/v1/correlate", {"limit": 1}),
                           ("/api/v1/listener/start", {"port": free_port()}),
                           ("/api/v1/listener/stop", {})):
            self.assertEqual(self.call("POST", path, "read", body), 403, path)

    def test_write_key_cannot_administer(self):
        for path, body in (("/api/v1/auto-learn", {"lines": ["x"]}),
                           ("/api/v1/correlate", {"limit": 1}),
                           ("/api/v1/listener/start", {"port": free_port()}),
                           ("/api/v1/listener/stop", {})):
            self.assertEqual(self.call("POST", path, "write", body), 403, path)
        self.assertEqual(self.call("POST", "/api/v1/ingest", "write", {"raw": "CEF:0|V|P|1|1|n|5|src=10.0.0.1"}), 200)

    def test_roles_are_hierarchical_and_keys_required(self):
        self.assertEqual(self.call("GET", "/api/v1/events"), 401)
        for role in ("read", "write", "admin"):
            self.assertEqual(self.call("GET", "/api/v1/events", role), 200, role)
        self.assertEqual(self.call("GET", "/api/v1/health"), 200)                      # public
        self.assertEqual(self.call("POST", "/api/v1/listener/stop", "admin"), 400)     # authorised: no listener

    def test_every_route_declares_a_role(self):
        from ulpf.api.app import create_app
        undeclared = []
        for route in create_app().routes:
            path = getattr(route, "path", "")
            if not path.startswith("/api/v1") or path == "/api/v1/health":
                continue
            if path == "/api/v1/console/stream":
                continue          # WebSocket: authenticated by a single-use ticket issued to an API key (rbac)
            calls = [d.call for d in route.dependant.dependencies]
            # legacy roles (auth.require) or v10 RBAC permissions (rbac.need) / authenticated principal
            if not any(getattr(c, "__qualname__", "").startswith(("require.", "need.", "principal"))
                       for c in calls):
                undeclared.append(path)
        self.assertEqual(undeclared, [])


# ---------------------------------------------------------------------------
# Bug 2: one APG engine per runtime
# ---------------------------------------------------------------------------

class TestSharedParserEngine(unittest.TestCase):
    def test_engine_is_built_once_and_sees_new_specs(self):
        from ulpf.config import load_pipeline_config
        from ulpf.intelligence.auto_parser.engine import AutoParserEngine
        from ulpf.runtime.supervisor import Runtime
        d = tempfile.mkdtemp(prefix="ulpf_apg_")
        rt = Runtime(load_pipeline_config(data={"node": {"data_dir": d}, "api": {"enabled": False},
                                                "outputs": [{"type": "duckdb", "name": "store"}],
                                                "learning": {"approval_required": True}}))
        eng = rt.apg_engine
        self.assertIs(rt.apg_engine, eng)
        self.assertEqual(eng.registry.list_parsers(), [])
        # a worker learns a parser that waits for approval (another engine, same directory)
        other = AutoParserEngine(learned_dir=rt.learned_dir)
        lines = [f"VALVE|{i}|2026-01-0{i % 9 + 1}T00:00:00Z|OPEN" for i in range(8)]
        report = other.learn(lines, save=True, state="pending_approval")
        pid = report["accepted"][0]["spec"].parser_id
        time.sleep(0.05)
        self.assertIs(rt.apg_engine, eng)
        self.assertEqual(rt.apg_engine.registry.get_spec(pid).state, "pending_approval")
        self.assertEqual(rt.decide_parser(pid, "approve", "test").state, "active")
        other.registry.reload_if_changed()
        self.assertEqual(other.registry.get_spec(pid).state, "active")
        self.assertEqual(other.registry.get_spec(pid).metadata["decided_by"], "test")

    def test_decisions_are_broadcast_to_workers(self):
        from ulpf.runtime.dispatch import Dispatcher
        fake = type("D", (), {})()
        fake.in_qs = [queue.Queue(), queue.Queue()]
        Dispatcher.broadcast(fake, "reload_parsers")
        self.assertEqual([q.get_nowait() for q in fake.in_qs], [("reload_parsers",), ("reload_parsers",)])


# ---------------------------------------------------------------------------
# Bug 8: keys, ratchet, escrow
# ---------------------------------------------------------------------------

class TestKeys(unittest.TestCase):
    def test_ratchet_derivation_and_erasure(self):
        from ulpf.runtime.keys import RowKeyChain, ratchet
        k0 = os.urandom(32)
        chain = RowKeyChain(0, k0, 100)
        self.assertEqual(chain.key_for_seq(1), k0)
        self.assertEqual(chain.key_for_seq(100), k0)
        self.assertEqual(chain.key_for_seq(101), ratchet(k0))
        self.assertEqual(chain.key_for_seq(350), ratchet(ratchet(ratchet(k0))))
        self.assertEqual(chain.key_for_seq(5), k0)                     # cursor rewinds from the base
        host = RowKeyChain.from_snapshot(chain.snapshot())
        self.assertTrue(host.advance_to_seq(201))
        self.assertIsNone(host.key_for_seq(150))                       # erased epoch
        self.assertEqual(host.key_for_seq(250), chain.key_for_seq(250))
        self.assertEqual(host.k0, chain.k0)                            # K_0 identity survives advances
        self.assertFalse(host.advance_to_seq(150))                     # never moves backwards

    def test_persistent_ratchet_overwrites_old_keys(self):
        from ulpf.runtime.keys import RowKeyChain, RowKeyRatchet
        d = tempfile.mkdtemp()
        r = RowKeyRatchet(d, 10)
        with open(os.path.join(d, "row_key.k0"), "rb") as f:
            k0 = f.read()
        r.advance_to_seq(35)
        with open(os.path.join(d, "row_key.state"), "rb") as f:
            state = f.read()
        self.assertNotIn(k0.hex().encode(), state)
        again = RowKeyRatchet(d, 10)
        self.assertEqual(again.base_epoch, 3)
        self.assertEqual(again.key_for_seq(40), RowKeyChain(0, k0, 10).key_for_seq(40))

    def test_escrow_seal_open(self):
        from ulpf.runtime.keys import RowKeyRatchet, generate_escrow_keypair, load_row_key
        d = tempfile.mkdtemp()
        priv, pub = generate_escrow_keypair(d)
        r = RowKeyRatchet(os.path.join(d, "ev"), 10, escrow_pub=pub)
        self.assertFalse(os.path.exists(os.path.join(d, "ev", "row_key.k0")))     # never in clear on the host
        sealed = os.path.join(d, "ev", "row_key.k0.sealed")
        k0 = load_row_key(sealed, priv)
        self.assertEqual(r.key_for_seq(1), k0)
        with self.assertRaises(ValueError):
            load_row_key(sealed)                          # needs the escrow private key
        other, _ = generate_escrow_keypair(d, name="other")
        with self.assertRaises(ValueError):
            load_row_key(sealed, other)

    def test_signing_key_file_is_encrypted_with_the_passphrase(self):
        from ulpf.runtime.keys import load_or_create_signing_key, pub_path, raw_public, load_public_key
        d = tempfile.mkdtemp()
        path = os.path.join(d, "k.pem")
        key = load_or_create_signing_key(path, b"pw")
        with open(path, "rb") as f:
            self.assertIn(b"ENCRYPTED", f.read())
        self.assertEqual(load_public_key(pub_path(path)), raw_public(key))
        from ulpf.runtime import keys
        keys._key_cache.clear()
        with self.assertRaises(ValueError):
            load_or_create_signing_key(path, None)
        keys._key_cache.clear()
        self.assertEqual(raw_public(load_or_create_signing_key(path, b"pw")), raw_public(key))


# ---------------------------------------------------------------------------
# Bug 8: forward-secure Ed25519 seals
# ---------------------------------------------------------------------------

class TestForwardSecureSeals(unittest.TestCase):
    def _sealed(self, n_batches=6, every=20):
        from ulpf.runtime.evidence import Sealer
        from ulpf.runtime.journal import Journal
        d = tempfile.mkdtemp(prefix="ulpf_fs_")
        j = Journal(os.path.join(d, "journal"), sync="always")
        sealer = Sealer(os.path.join(d, "evidence", "seals"), "node-t", every, 3600)
        j.add_listener(sealer.on_append)
        for i in range(n_batches):
            j.append("src", "in", [f"line {i}-{k}".encode() for k in range(10)])
        while sealer.seal_now("test"):
            pass
        return d, j, sealer, os.path.join(d, "evidence", "seals")

    def test_seals_verify_with_the_public_key_only(self):
        from ulpf.runtime.evidence import load_seals, verify_seals
        d, j, sealer, sd = self._sealed()
        seals = load_seals(sd)
        self.assertEqual(seals[0]["anchor"]["reason"], "genesis")
        self.assertTrue(all("signature" in s and "hmac_sha256" not in s for s in seals))
        res = verify_seals(sd, j, None, pubkey=os.path.join(d, "evidence", "evidence.pub"))
        self.assertTrue(res["valid"], res["problems"])
        self.assertEqual(res["signatures_checked"], len(seals))
        sealer.close()
        j.close()

    def test_host_compromise_cannot_resign_history(self):
        """An attacker with the host's current state (next one-time key) rewrites an old seal."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from ulpf.runtime.evidence import load_seals, seal_hash, verify_seals
        d, j, sealer, sd = self._sealed()
        with open(os.path.join(sd, "sealer.state")) as f:
            st = json.load(f)
        self.assertNotIn("fs_sk", st)          # v10: the one-time key is never stored in clear
        # an attacker who owns the host (identity key and passphrase included) decrypts the current key
        stolen = sealer._load_fs_key(st)
        self.assertIsInstance(stolen, Ed25519PrivateKey)
        names = sorted(n for n in os.listdir(sd) if n.startswith("seal-"))
        path = os.path.join(sd, names[1])
        s = load_seals(sd)[1]
        s["merkle_root"] = "00" * 32                       # hide altered records
        s["seal_hash"] = seal_hash(s)
        s["signature"] = stolen.sign(s["seal_hash"].encode()).hex()
        with open(path, "w") as f:
            json.dump(s, f)
        res = verify_seals(sd, j, None)
        self.assertFalse(res["valid"])
        joined = "\n".join(res["problems"])
        self.assertIn("Ed25519 signature invalid", joined)
        self.assertIn("chain broken", joined)
        sealer.close()
        j.close()

    def test_a_foreign_identity_is_refused_when_pinned(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from ulpf.runtime.evidence import verify_seals
        from ulpf.runtime.keys import raw_public
        d, j, sealer, sd = self._sealed(2)
        res = verify_seals(sd, j, None, pubkey=raw_public(Ed25519PrivateKey.generate()))
        self.assertFalse(res["valid"])
        self.assertIn("unknown identity key", "\n".join(res["problems"]))
        sealer.close()
        j.close()

    def test_restart_and_crash_between_seal_and_state(self):
        from ulpf.runtime.evidence import Sealer, verify_seals
        d, j, sealer, sd = self._sealed(4)
        sealer.close()
        with open(os.path.join(sd, "sealer.state")) as f:
            before = f.read()
        # clean restart: the chain continues without a new anchor
        s2 = Sealer(sd, "node-t", 20, 3600)
        j.add_listener(s2.on_append)
        j.append("src", "in", [b"after restart %d" % k for k in range(10)])
        s2.seal_now("test")
        with open(os.path.join(sd, "sealer.state")) as f:
            stale = f.read()
        j.append("src", "in", [b"before crash %d" % k for k in range(10)])
        s2.seal_now("test")
        s2.close()
        # crash: the seal file was written but the state still describes the seal before it
        with open(os.path.join(sd, "sealer.state"), "w") as f:
            f.write(stale)
        s3 = Sealer(sd, "node-t", 20, 3600)
        s3.recover(j)
        j.add_listener(s3.on_append)
        j.append("src", "in", [b"after crash %d" % k for k in range(10)])
        s3.seal_now("test")
        res = verify_seals(sd, j, None)
        self.assertTrue(res["valid"], res["problems"])
        self.assertEqual(len([n for n in res["notes"] if "re-anchored (recovery)" in n]), 1, res["notes"])
        self.assertNotEqual(before, stale)
        s3.close()
        j.close()

    def test_v1_hmac_chain_upgrades_in_place(self):
        """Seals written by 9.0 (HMAC) followed by 9.1 seals (Ed25519) verify as one chain."""
        import hashlib
        import hmac as hmac_mod
        from ulpf.runtime.evidence import Sealer, leaf, merkle_root, seal_hash, verify_seals
        from ulpf.runtime.journal import Journal
        d = tempfile.mkdtemp(prefix="ulpf_v1_")
        j = Journal(os.path.join(d, "journal"), sync="always")
        legacy = os.urandom(32)
        sd = os.path.join(d, "evidence", "seals")
        os.makedirs(sd)
        first, _ = j.append("src", "in", [b"old %d" % k for k in range(5)])
        leaves = [leaf(q, j.read(q).sha256) for q in range(first, first + 5)]
        v1 = {"type": "ulpf.seal", "version": 1, "node": "n", "first_seq": first, "last_seq": first + 4,
              "count": 5, "merkle_root": merkle_root(leaves).hex(), "prev_seal_hash": "0" * 64,
              "created_at": time.time(), "schema_version": "1.1.0", "reason": "window"}
        v1["seal_hash"] = seal_hash(v1)
        v1["hmac_sha256"] = hmac_mod.new(legacy, v1["seal_hash"].encode(), hashlib.sha256).hexdigest()
        with open(os.path.join(sd, f"seal-{first:020d}-{first + 4:020d}.json"), "w") as f:
            json.dump(v1, f)
        with open(os.path.join(sd, "sealer.state"), "w") as f:
            json.dump({"prev_seal_hash": v1["seal_hash"], "last_sealed_seq": first + 4}, f)
        s = Sealer(sd, "n", 50, 3600, key=legacy)
        j.add_listener(s.on_append)
        j.append("src", "in", [b"new %d" % k for k in range(5)])
        new = s.seal_now("test")
        self.assertEqual(new["anchor"]["reason"], "upgrade")
        self.assertTrue(verify_seals(sd, j, legacy)["valid"])
        res = verify_seals(sd, j, os.urandom(32))
        self.assertIn("HMAC invalid", "\n".join(res["problems"]))
        s.close()
        j.close()


# ---------------------------------------------------------------------------
# Bug 8: parser provenance
# ---------------------------------------------------------------------------

class TestParserProvenance(unittest.TestCase):
    def _spec(self):
        from ulpf.intelligence.auto_parser.miners.native import NativeTemplateMiner
        return NativeTemplateMiner().mine([f"PUMP-{i},2026-02-0{i}T10:00:00Z,{i}.5,ok" for i in range(1, 6)],
                                          "fp")[0]

    def test_ed25519_signature_binds_content_state_and_decision(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from ulpf.intelligence.auto_parser.provenance import ProvenanceManager
        pm = ProvenanceManager(signing_key=Ed25519PrivateKey.generate())
        spec = self._spec()
        spec.metadata["decided_by"] = "alice"
        pm.sign_parser_spec(spec)
        self.assertNotIn("hmac_sha256", spec.metadata)
        self.assertTrue(pm.verify_parser_spec(spec))
        spec.metadata["decided_by"] = "mallory"
        self.assertFalse(pm.verify_parser_spec(spec))
        spec.metadata["decided_by"] = "alice"
        spec.state = "retired" if spec.state != "retired" else "active"
        self.assertFalse(pm.verify_parser_spec(spec))

    def test_only_trusted_signers_are_accepted(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from ulpf.intelligence.auto_parser.provenance import ProvenanceManager
        from ulpf.runtime.keys import raw_public
        other_key = Ed25519PrivateKey.generate()
        spec = self._spec()
        ProvenanceManager(signing_key=other_key).sign_parser_spec(spec)
        self.assertFalse(ProvenanceManager(signing_key=Ed25519PrivateKey.generate()).verify_parser_spec(spec))
        trusting = ProvenanceManager(signing_key=Ed25519PrivateKey.generate(), trusted=[raw_public(other_key)])
        self.assertTrue(trusting.verify_parser_spec(spec))

    def test_legacy_hmac_specs_still_verify(self):
        import hashlib
        import hmac as hmac_mod
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from ulpf.intelligence.auto_parser.provenance import ProvenanceManager
        legacy = os.urandom(32)
        spec = self._spec()
        spec.metadata.update(hmac_scheme=2, hmac_sha256=hmac_mod.new(
            legacy, f"{spec.content_hash}|state={spec.state}".encode(), hashlib.sha256).hexdigest())
        self.assertTrue(ProvenanceManager(legacy, Ed25519PrivateKey.generate()).verify_parser_spec(spec))
        self.assertFalse(ProvenanceManager(os.urandom(32), Ed25519PrivateKey.generate()).verify_parser_spec(spec))

    def test_stripped_signature_is_refused_when_signatures_are_required(self):
        from ulpf.intelligence.auto_parser.engine import AutoParserEngine
        from ulpf.intelligence.auto_parser.registry import AutoParserRegistry
        d = tempfile.mkdtemp()
        eng = AutoParserEngine(learned_dir=d)
        report = eng.learn([f"TANK|{i}|2026-01-0{i % 9 + 1}T00:00:00Z|LOW" for i in range(8)], save=True)
        path = report["accepted"][0]["saved_to"]
        with open(path) as f:
            doc = json.load(f)
        for k in ("ed25519", "signer", "signer_pub", "sig_scheme"):
            doc["metadata"].pop(k)
        doc["state"] = "active"
        with open(path, "w") as f:
            json.dump(doc, f)
        self.assertIsNotNone(AutoParserRegistry(d).get_spec(doc["parser_id"]))   # industry: unsigned loads
        strict = AutoParserRegistry(d)
        self.assertEqual(strict.require_signatures(), 1)
        self.assertIsNone(strict.get_spec(doc["parser_id"]))
        strict.load_from_disk()
        self.assertIsNone(strict.get_spec(doc["parser_id"]))


# ---------------------------------------------------------------------------
# Bug 6: egress
# ---------------------------------------------------------------------------

class TestEgress(unittest.TestCase):
    def test_dns_rotation_is_followed_with_grace(self):
        from ulpf.runtime.egress import EgressPolicy
        answers = {"siem.internal": ["10.0.0.1"]}

        def resolve(name, _port):
            return [(2, 1, 6, "", (ip, 0)) for ip in answers[name]]

        p = EgressPolicy(["siem.internal", "192.168.50.0/24"], enforce=True, dns_refresh_s=0.05,
                         dns_grace_s=0.2, resolve=resolve)
        self.assertTrue(p.allowed("10.0.0.1"))
        self.assertTrue(p.allowed("192.168.50.7"))
        self.assertFalse(p.allowed("10.0.0.2"))
        answers["siem.internal"] = ["10.0.0.2"]          # load balancer fail-over
        p.refresh()
        self.assertTrue(p.allowed("10.0.0.2"))
        self.assertTrue(p.allowed("10.0.0.1"))           # draining connections: grace period
        time.sleep(0.35)
        p.refresh()
        self.assertTrue(p.allowed("10.0.0.2"))
        self.assertFalse(p.allowed("10.0.0.1"))
        with self.assertRaises(PermissionError):
            p.check("socket.connect", None, ("10.0.0.1", 514))

    def test_application_lookups_are_learned_immediately(self):
        from ulpf.runtime import egress
        real = egress._real_getaddrinfo
        egress._real_getaddrinfo = lambda host, *a, **k: [(2, 1, 6, "", ("10.9.9.9", 0))] \
            if host == "kafka.internal" else real(host, *a, **k)
        try:
            p = egress.install(["kafka.internal"], enforce=True, dns_refresh_s=0)
            self.assertTrue(p.allowed("10.9.9.9"))
            p._addrs.clear()
            self.assertFalse(p.allowed("10.9.9.9"))
            socket.getaddrinfo("kafka.internal", 9092)      # the app resolves the name
            self.assertTrue(p.allowed("10.9.9.9"))
        finally:
            egress.uninstall()
            egress._real_getaddrinfo = real

    def test_native_client_endpoints_are_vetted(self):
        from ulpf.runtime import egress
        try:
            egress.install(["10.0.0.5"], enforce=True, dns_refresh_s=0)
            egress.vet_endpoints(["10.0.0.5:9092", "127.0.0.1:9092", "[::1]:9092"], "kafka")
            with self.assertRaises(PermissionError):
                egress.vet_endpoints("10.0.0.5:9092,broker.evil.example:9092", "kafka")
            self.assertIn("broker.evil.example:9092", egress.current().blocked)
            egress.install(["10.0.0.5"], enforce=False, dns_refresh_s=0)
            egress.vet_endpoints(["203.0.113.9:9092"], "kafka")      # record mode never refuses
        finally:
            egress.uninstall()

    def test_duckdb_external_access_is_locked(self):
        import duckdb
        import pyarrow as pa
        import pyarrow.parquet as pq
        from ulpf.storage.database import Database
        d, outside = tempfile.mkdtemp(), tempfile.mkdtemp()
        pq.write_table(pa.table({"a": [1]}), os.path.join(outside, "x.parquet"))
        db = Database(os.path.join(d, "store", "s.duckdb"))
        db.lock_down([os.path.join(d, "buffers")])
        self.assertTrue(db.locked_down)
        for stmt in (f"SELECT * FROM read_parquet('{os.path.join(outside, 'x.parquet')}')",
                     "INSTALL httpfs", "SET enable_external_access=true",
                     "SELECT * FROM read_csv('https://example.com/x.csv')"):
            with self.assertRaises(duckdb.Error, msg=stmt):
                db.conn.execute(stmt)
        db.close()

    def test_defence_store_ingests_its_buffers_after_lockdown(self):
        from ulpf.runtime.sinks.duckdb_sink import DuckDBSink, encode_parquet
        d = tempfile.mkdtemp()
        sink = DuckDBSink("store", {"path": os.path.join(d, "s.duckdb")}, {"mode": "defence", "data_dir": d})
        sink.open()
        self.assertTrue(sink.db.locked_down)
        seg = os.path.join(d, "buffers", "store", "L-1-1-1.parquet")
        os.makedirs(os.path.dirname(seg))
        ev = {"event_id": "e1", "timestamp": "2026-01-01T00:00:00+00:00", "raw_event": "x", "raw_format": "raw",
              "raw_hash": "0" * 64, "message": "x", "severity": 1}
        with open(seg, "wb") as f:
            f.write(encode_parquet([ev]))
        self.assertEqual(sink.db.ingest_parquet([seg]), 1)
        sink.db.close()

    def test_os_policy_rendering(self):
        from ulpf.runtime import egress_os
        nft = egress_os.render_nftables(["10.1.0.0/16", "192.0.2.10", "no-such-host.invalid"], user="ulpf")
        self.assertIn("10.1.0.0/16", nft)
        self.assertIn("192.0.2.10/32", nft)
        self.assertIn('meta skuid != "ulpf" accept', nft)
        self.assertIn("ct state established,related accept", nft)
        self.assertIn("'no-such-host.invalid' did not resolve", nft)
        unit = egress_os.render_systemd(["10.1.0.0/16"], ingress_from=["172.16.0.0/12"])
        self.assertIn("IPAddressDeny=any", unit)
        self.assertIn("IPAddressAllow=172.16.0.0/12", unit)
        res = egress_os.os_check()
        if not sys.platform.startswith("linux"):
            self.assertFalse(res["supported"])
        else:
            self.assertIn(res["blocked"], (True, False))


# ---------------------------------------------------------------------------
# defence.key_protection
# ---------------------------------------------------------------------------

class TestKeyProtectionRule(unittest.TestCase):
    def test_defence_requires_protected_keys(self):
        from ulpf.config import ConfigError, load_pipeline_config
        saved = os.environ.pop("ULPF_EVIDENCE_PASSPHRASE", None)
        try:
            doc = {"mode": "defence", "inputs": [], "api": {"enabled": False},
                   "outputs": [{"type": "duckdb", "name": "store"}]}
            with self.assertRaises(ConfigError) as cm:
                load_pipeline_config(data=dict(doc))
            self.assertIn("defence.key_protection", str(cm.exception))
            cfg = load_pipeline_config(data={**doc, "overrides": ["defence.key_protection"]})
            self.assertTrue(any("defence.key_protection" in w for w in cfg.waived))
            os.environ["ULPF_EVIDENCE_PASSPHRASE"] = "pw"
            load_pipeline_config(data=dict(doc))
        finally:
            os.environ.pop("ULPF_EVIDENCE_PASSPHRASE", None)
            if saved is not None:
                os.environ["ULPF_EVIDENCE_PASSPHRASE"] = saved


if __name__ == "__main__":
    unittest.main()
