"""PKCS#11 provider against a real module (SoftHSM2, YubiKey ykcs11, Nitrokey, CloudHSM, Luna).

    softhsm2-util --init-token --free --label ULPF --pin 123456 --so-pin 12345678
    ULPF_PKCS11_PIN=123456 python -m scripts.long_tests.pkcs11_softhsm --module /usr/lib/softhsm/libsofthsm2.so

Generates (or finds) a non-extractable Ed25519 key on the token, signs 10,000 seals, verifies every signature
with the exported public key, checks the private key cannot be read, and runs a full Sealer cycle with
evidence.key_provider: pkcs11.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
import time


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--module", required=True)
    ap.add_argument("--token-label", default="ULPF")
    ap.add_argument("--n", type=int, default=10000)
    a = ap.parse_args()
    from ulpf.runtime import hwkeys
    from ulpf.runtime.keys import configure_provider, raw_public, verify_signature
    key = hwkeys.pkcs11_key({"module": a.module, "token_label": a.token_label}, "ulpf-longtest")
    pub = raw_public(key)
    t0 = time.time()
    for i in range(a.n):
        msg = f"seal {i}".encode()
        assert verify_signature(pub, key.sign(msg).hex(), msg), i
    rate = a.n / (time.time() - t0)
    try:
        key.private_bytes()
        print("FAIL: private key extractable")
        return 1
    except TypeError:
        pass
    from ulpf.runtime.evidence import Sealer, verify_seals
    from ulpf.runtime.journal import Journal
    d = tempfile.mkdtemp()
    try:
        configure_provider("pkcs11", {"module": a.module, "token_label": a.token_label, "key_label": "ulpf-sealer"})
        j = Journal(os.path.join(d, "journal"))
        s = Sealer(os.path.join(d, "evidence", "seals"), "n1", 100, 3600, key_provider="pkcs11")
        j.add_listener(s.on_append)
        for b in range(20):
            j.append("h", "i", [f"r{b}-{i}".encode() for i in range(100)])
        while s.seal_now():
            pass
        res = verify_seals(os.path.join(d, "evidence", "seals"), j)
        s.close()
        j.close()
        print(f"token signatures/s: {rate:.0f}; sealer verify: {res['valid']} ({res['seals']} seals)")
        return 0 if res["valid"] else 1
    finally:
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
