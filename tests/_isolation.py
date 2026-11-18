"""Import first in every test module: isolates all ULPF state in a temp directory.

Tests must never read or write the user's real event store, learned parsers
or signing key, and must not spawn worker processes or bind syslog ports
unless a test does so explicitly.
"""
import os
import tempfile

_root = tempfile.mkdtemp(prefix="ulpf_tests_")
os.environ["ULPF_DATA_DIR"] = os.path.join(_root, "data")
os.environ["ULPF_LEARNED_PARSERS_DIR"] = os.path.join(_root, "learned_parsers")
os.environ.pop("ULPF_DB_PATH", None)
os.environ.setdefault("ULPF_GUI_WORKERS", "0")
os.environ.setdefault("ULPF_NO_AUTO_LISTENER", "1")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
# Signing keys are encrypted with it; defence mode refuses to run without one (defence.key_protection)
os.environ.setdefault("ULPF_EVIDENCE_PASSPHRASE", "ulpf-test-passphrase")
os.environ.pop("ULPF_PARSER_SIGNING_KEY", None)
os.environ.pop("ULPF_PARSER_TRUSTED_KEYS", None)
TEST_ROOT = _root
