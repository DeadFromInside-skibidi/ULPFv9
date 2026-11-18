"""
Hardware-backed signing keys: PKCS#11 tokens/HSMs and TPM 2.0.

``pkcs11``  The Ed25519 identity key is generated *inside* a PKCS#11 v2.40+/3.0
            token (YubiKey 5 via ykcs11, Nitrokey HSM, SoftHSM2, AWS CloudHSM,
            Thales Luna, any module with ``CKM_EDDSA``) as a sensitive,
            non-extractable object. Signing happens on the token
            (``C_Sign``/``CKM_EDDSA``); the private key never enters this
            process. Only the module's ``C_*`` exports are used (ctypes), so
            no Python PKCS#11 package is needed.

``tpm``     TPM 2.0 chips cannot hold Ed25519 keys (the TCG algorithm registry
            has no EdDSA). The identity key is therefore *sealed* by the TPM:
            it is stored AES-256-GCM encrypted under a data key that only the
            TPM can unwrap (Windows: an RSA-2048 key in the Microsoft Platform
            Crypto Provider, NCrypt OAEP-SHA256; Linux: a ``tpm2-tools`` sealed
            object under the owner hierarchy). The plaintext key exists only
            inside OpenSSL's memory while the process runs; disk holds
            ciphertext bound to this machine's TPM.

Both expose the duck type the evidence code uses: ``sign(bytes) -> bytes``
and ``public_key() -> Ed25519PublicKey``.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

PIN_ENV = "ULPF_PKCS11_PIN"

# ---------------------------------------------------------------------------
# PKCS#11 (v2.40 / v3.0 constants)
# ---------------------------------------------------------------------------
CKR_OK = 0x0
CKR_USER_ALREADY_LOGGED_IN = 0x100
CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x191
CKF_RW_SESSION = 0x2
CKF_SERIAL_SESSION = 0x4
CKU_USER = 1
CKO_PUBLIC_KEY = 2
CKO_PRIVATE_KEY = 3
CKA_CLASS, CKA_TOKEN, CKA_PRIVATE, CKA_LABEL = 0x0, 0x1, 0x2, 0x3
CKA_KEY_TYPE, CKA_ID, CKA_SENSITIVE, CKA_SIGN, CKA_VERIFY = 0x100, 0x102, 0x103, 0x108, 0x10A
CKA_EXTRACTABLE, CKA_EC_PARAMS, CKA_EC_POINT = 0x162, 0x180, 0x181
CKK_EC_EDWARDS = 0x40
CKM_EC_EDWARDS_KEY_PAIR_GEN = 0x1055
CKM_EDDSA = 0x1057
# DER: PrintableString "edwards25519" (RFC 8410 curve name form most tokens accept) and OID 1.3.101.112
EC_PARAMS_ED25519 = (bytes.fromhex("130c656477617264733235353139"), bytes.fromhex("06032b6570"))

_CK_ULONG = ctypes.c_ulong
_PACK = 1 if sys.platform == "win32" else 0   # cryptoki structs are packed to 1 byte on Windows


class _Attr(ctypes.Structure):
    if _PACK:
        _pack_ = 1
    _fields_ = [("type", _CK_ULONG), ("pValue", ctypes.c_void_p), ("ulValueLen", _CK_ULONG)]


class _Mech(ctypes.Structure):
    if _PACK:
        _pack_ = 1
    _fields_ = [("mechanism", _CK_ULONG), ("pParameter", ctypes.c_void_p), ("ulParameterLen", _CK_ULONG)]


class Pkcs11Error(RuntimeError):
    def __init__(self, fn: str, rv: int):
        super().__init__(f"PKCS#11 {fn} failed: CKR 0x{rv:08x}")
        self.rv = rv


def _attrs(items: list[tuple[int, bytes]]):
    arr = (_Attr * len(items))()
    keep = []
    for i, (t, v) in enumerate(items):
        buf = ctypes.create_string_buffer(v, len(v))
        keep.append(buf)
        arr[i].type, arr[i].pValue, arr[i].ulValueLen = t, ctypes.cast(buf, ctypes.c_void_p), len(v)
    return arr, keep


def _ul(v: int) -> bytes:
    return bytes(_CK_ULONG(v))


def _bool(v: bool) -> bytes:
    return b"\x01" if v else b"\x00"


def _octet_string(der: bytes) -> bytes:
    """CKA_EC_POINT is DER OCTET STRING(raw point) on conforming tokens; some return the raw 32 bytes."""
    if len(der) == 32:
        return der
    if len(der) >= 34 and der[0] == 0x04 and der[1] == 32:
        return der[2:34]
    raise ValueError("unexpected CKA_EC_POINT encoding")


class Pkcs11Module:
    """Minimal ctypes binding over a vendor module's exported ``C_*`` functions."""

    def __init__(self, path: str):
        self.path = path
        self.lib = ctypes.WinDLL(path) if sys.platform == "win32" else ctypes.CDLL(path)
        self._lock = threading.RLock()
        rv = self.lib.C_Initialize(None)
        if rv not in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED):
            raise Pkcs11Error("C_Initialize", rv)

    def call(self, name: str, *args) -> None:
        with self._lock:
            rv = getattr(self.lib, name)(*args) & 0xFFFFFFFF
        if rv != CKR_OK:
            raise Pkcs11Error(name, rv)

    def slots(self) -> list[int]:
        n = _CK_ULONG(0)
        self.call("C_GetSlotList", ctypes.c_ubyte(1), None, ctypes.byref(n))
        arr = (_CK_ULONG * n.value)()
        self.call("C_GetSlotList", ctypes.c_ubyte(1), arr, ctypes.byref(n))
        return [arr[i] for i in range(n.value)]

    def token_label(self, slot: int) -> str:
        info = ctypes.create_string_buffer(512)      # CK_TOKEN_INFO starts with label[32]
        self.call("C_GetTokenInfo", _CK_ULONG(slot), info)
        return info.raw[:32].decode("utf-8", "replace").rstrip()

    def open(self, slot: int, pin: bytes | None) -> int:
        h = _CK_ULONG(0)
        self.call("C_OpenSession", _CK_ULONG(slot), _CK_ULONG(CKF_SERIAL_SESSION | CKF_RW_SESSION), None, None,
                  ctypes.byref(h))
        if pin:
            with self._lock:
                rv = self.lib.C_Login(h, _CK_ULONG(CKU_USER), ctypes.c_char_p(pin), _CK_ULONG(len(pin))) & 0xFFFFFFFF
            if rv not in (CKR_OK, CKR_USER_ALREADY_LOGGED_IN):
                raise Pkcs11Error("C_Login", rv)
        return h.value

    def find(self, session: int, cls: int, label: str) -> int | None:
        arr, keep = _attrs([(CKA_CLASS, _ul(cls)), (CKA_LABEL, label.encode())])
        with self._lock:
            self.call("C_FindObjectsInit", _CK_ULONG(session), arr, _CK_ULONG(len(keep)))
            obj, n = _CK_ULONG(0), _CK_ULONG(0)
            try:
                self.call("C_FindObjects", _CK_ULONG(session), ctypes.byref(obj), _CK_ULONG(1), ctypes.byref(n))
            finally:
                self.call("C_FindObjectsFinal", _CK_ULONG(session))
        return obj.value if n.value else None

    def attribute(self, session: int, obj: int, attr: int) -> bytes:
        a = (_Attr * 1)()
        a[0].type, a[0].pValue, a[0].ulValueLen = attr, None, 0
        self.call("C_GetAttributeValue", _CK_ULONG(session), _CK_ULONG(obj), a, _CK_ULONG(1))
        buf = ctypes.create_string_buffer(a[0].ulValueLen)
        a[0].pValue = ctypes.cast(buf, ctypes.c_void_p)
        self.call("C_GetAttributeValue", _CK_ULONG(session), _CK_ULONG(obj), a, _CK_ULONG(1))
        return buf.raw[:a[0].ulValueLen]

    def generate_ed25519(self, session: int, label: str) -> tuple[int, int]:
        last: Exception | None = None
        for params in EC_PARAMS_ED25519:
            pub, pk = _attrs([(CKA_TOKEN, _bool(True)), (CKA_LABEL, label.encode()), (CKA_VERIFY, _bool(True)),
                              (CKA_EC_PARAMS, params)])
            prv, pk2 = _attrs([(CKA_TOKEN, _bool(True)), (CKA_LABEL, label.encode()), (CKA_SIGN, _bool(True)),
                               (CKA_PRIVATE, _bool(True)), (CKA_SENSITIVE, _bool(True)),
                               (CKA_EXTRACTABLE, _bool(False))])
            mech = _Mech(CKM_EC_EDWARDS_KEY_PAIR_GEN, None, 0)
            hpub, hprv = _CK_ULONG(0), _CK_ULONG(0)
            try:
                self.call("C_GenerateKeyPair", _CK_ULONG(session), ctypes.byref(mech), pub, _CK_ULONG(len(pk)),
                          prv, _CK_ULONG(len(pk2)), ctypes.byref(hpub), ctypes.byref(hprv))
                return hpub.value, hprv.value
            except Pkcs11Error as e:
                last = e
        raise last  # type: ignore[misc]

    def sign(self, session: int, key: int, data: bytes) -> bytes:
        mech = _Mech(CKM_EDDSA, None, 0)
        with self._lock:
            self.call("C_SignInit", _CK_ULONG(session), ctypes.byref(mech), _CK_ULONG(key))
            out = ctypes.create_string_buffer(64)
            n = _CK_ULONG(64)
            self.call("C_Sign", _CK_ULONG(session), ctypes.c_char_p(data), _CK_ULONG(len(data)), out,
                      ctypes.byref(n))
        return out.raw[:n.value]


class HardwareEd25519Key:
    """Duck-types ``Ed25519PrivateKey`` for code that only signs and reads the public key."""

    hardware = True

    def __init__(self, signer, public: bytes, description: str):
        self._signer = signer
        self._pub = Ed25519PublicKey.from_public_bytes(public)
        self.description = description

    def sign(self, data: bytes) -> bytes:
        sig = self._signer(bytes(data))
        self._pub.verify(sig, bytes(data))   # a faulty token must not produce unverifiable seals
        return sig

    def public_key(self) -> Ed25519PublicKey:
        return self._pub

    def private_bytes(self, *a, **k):
        raise TypeError(f"{self.description}: the private key is not extractable")


_modules: dict[str, Pkcs11Module] = {}


def pkcs11_key(options: dict, label: str, module_factory=Pkcs11Module) -> HardwareEd25519Key:
    """Ed25519 key ``options['key_label'] or label`` on a PKCS#11 token; generated on the token if absent."""
    module = options.get("module") or os.environ.get("ULPF_PKCS11_MODULE")
    if not module:
        raise ValueError("evidence.pkcs11.module (path to the vendor PKCS#11 library) is required")
    pin_env = options.get("pin_env") or PIN_ENV
    pin = os.environ.get(pin_env)
    mod = _modules.get(module)
    if mod is None:
        mod = _modules[module] = module_factory(module)
    slot = options.get("slot")
    if slot is None:
        want = options.get("token_label")
        slots = mod.slots()
        cand = [s for s in slots if want is None or mod.token_label(s) == want]
        if not cand:
            raise RuntimeError(f"no PKCS#11 token{' labelled ' + want if want else ''} present in {module}")
        slot = cand[0]
    session = mod.open(int(slot), pin.encode() if pin else None)
    klabel = options.get("key_label") or label
    prv = mod.find(session, CKO_PRIVATE_KEY, klabel)
    pubh = mod.find(session, CKO_PUBLIC_KEY, klabel)
    if prv is None:
        if not options.get("generate", True):
            raise RuntimeError(f"PKCS#11 key {klabel!r} not found and generation is disabled")
        pubh, prv = mod.generate_ed25519(session, klabel)
        logger.info(f"generated non-extractable Ed25519 key {klabel!r} on PKCS#11 token (slot {slot})")
    if pubh is None:
        raise RuntimeError(f"PKCS#11 key {klabel!r}: public key object missing")
    public = _octet_string(mod.attribute(session, pubh, CKA_EC_POINT))
    return HardwareEd25519Key(lambda d: mod.sign(session, prv, d), public, f"pkcs11:{klabel}")


# ---------------------------------------------------------------------------
# TPM 2.0 sealing
# ---------------------------------------------------------------------------
MS_PLATFORM_PROVIDER = "Microsoft Platform Crypto Provider"
MS_SOFTWARE_PROVIDER = "Microsoft Software Key Storage Provider"
NTE_BAD_KEYSET = 0x80090016
NCRYPT_PAD_OAEP_FLAG = 0x4
NCRYPT_SILENT_FLAG = 0x40


class _OaepInfo(ctypes.Structure):
    _fields_ = [("pszAlgId", ctypes.c_wchar_p), ("pbLabel", ctypes.c_void_p), ("cbLabel", ctypes.c_ulong)]


class NCryptWrapper:
    """Wrap/unwrap a data key with a persisted, non-exportable RSA-2048 key of a CNG key storage provider."""

    def __init__(self, provider: str = MS_PLATFORM_PROVIDER, key_name: str = "ULPF-Evidence-KEK"):
        if sys.platform != "win32":
            raise RuntimeError("NCrypt is Windows-only; use tpm2-tools on Linux")
        self.nc = ctypes.WinDLL("ncrypt.dll")
        self.provider, self.key_name = provider, key_name

    def _ok(self, fn: str, rv: int) -> None:
        if rv & 0xFFFFFFFF:
            raise RuntimeError(f"{fn} failed: 0x{rv & 0xFFFFFFFF:08x} ({self.provider})")

    def _key(self):
        hp, hk = ctypes.c_size_t(0), ctypes.c_size_t(0)
        self._ok("NCryptOpenStorageProvider", self.nc.NCryptOpenStorageProvider(
            ctypes.byref(hp), ctypes.c_wchar_p(self.provider), 0))
        rv = self.nc.NCryptOpenKey(hp, ctypes.byref(hk), ctypes.c_wchar_p(self.key_name), 0, NCRYPT_SILENT_FLAG)
        if (rv & 0xFFFFFFFF) == NTE_BAD_KEYSET:
            self._ok("NCryptCreatePersistedKey", self.nc.NCryptCreatePersistedKey(
                hp, ctypes.byref(hk), ctypes.c_wchar_p("RSA"), ctypes.c_wchar_p(self.key_name), 0, 0))
            length = ctypes.c_ulong(2048)
            self._ok("NCryptSetProperty", self.nc.NCryptSetProperty(
                hk, ctypes.c_wchar_p("Length"), ctypes.byref(length), 4, 0))
            self._ok("NCryptFinalizeKey", self.nc.NCryptFinalizeKey(hk, NCRYPT_SILENT_FLAG))
        else:
            self._ok("NCryptOpenKey", rv)
        return hp, hk

    def _crypt(self, fn: str, data: bytes) -> bytes:
        hp, hk = self._key()
        try:
            pad = _OaepInfo("SHA256", None, 0)
            n = ctypes.c_ulong(0)
            f = getattr(self.nc, fn)
            self._ok(fn, f(hk, data, len(data), ctypes.byref(pad), None, 0, ctypes.byref(n),
                           NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG))
            out = ctypes.create_string_buffer(n.value)
            self._ok(fn, f(hk, data, len(data), ctypes.byref(pad), out, n, ctypes.byref(n),
                           NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG))
            return out.raw[:n.value]
        finally:
            self.nc.NCryptFreeObject(hk)
            self.nc.NCryptFreeObject(hp)

    def wrap(self, dek: bytes) -> bytes:
        return self._crypt("NCryptEncrypt", dek)

    def unwrap(self, blob: bytes) -> bytes:
        return self._crypt("NCryptDecrypt", blob)

    def delete(self) -> None:
        hp, hk = self._key()
        self.nc.NCryptDeleteKey(hk, 0)
        self.nc.NCryptFreeObject(hp)


class Tpm2ToolsWrapper:
    """Linux: seal the data key into a TPM 2.0 sealed-data object with ``tpm2-tools`` (>= 4.0)."""

    def __init__(self, directory: str, tcti: str | None = None):
        if not shutil.which("tpm2_createprimary"):
            raise RuntimeError("tpm2-tools are not installed (tpm2_createprimary not found)")
        self.dir = directory
        self.env = dict(os.environ, **({"TPM2TOOLS_TCTI": tcti} if tcti else {}))

    def _run(self, *args: str) -> None:
        subprocess.run(list(args), check=True, capture_output=True, env=self.env, timeout=60)

    def wrap(self, dek: bytes) -> bytes:
        with tempfile.TemporaryDirectory() as t:
            ctx, pub, prv, inp = (os.path.join(t, n) for n in ("primary.ctx", "seal.pub", "seal.priv", "in"))
            fd = os.open(inp, os.O_WRONLY | os.O_CREAT, 0o600)
            os.write(fd, dek)
            os.close(fd)
            self._run("tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "ecc", "-c", ctx)
            self._run("tpm2_create", "-C", ctx, "-i", inp, "-u", pub, "-r", prv)
            os.remove(inp)
            with open(pub, "rb") as a, open(prv, "rb") as b:
                pa, pb = a.read(), b.read()
        return len(pa).to_bytes(4, "big") + pa + pb

    def unwrap(self, blob: bytes) -> bytes:
        n = int.from_bytes(blob[:4], "big")
        with tempfile.TemporaryDirectory() as t:
            ctx, pub, prv, obj = (os.path.join(t, n_) for n_ in ("primary.ctx", "seal.pub", "seal.priv", "obj.ctx"))
            with open(pub, "wb") as f:
                f.write(blob[4:4 + n])
            with open(prv, "wb") as f:
                f.write(blob[4 + n:])
            self._run("tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "ecc", "-c", ctx)
            self._run("tpm2_load", "-C", ctx, "-u", pub, "-r", prv, "-c", obj)
            out = subprocess.run(["tpm2_unseal", "-c", obj], check=True, capture_output=True, env=self.env,
                                 timeout=60).stdout
        return out


def tpm_wrapper(options: dict, directory: str):
    if options.get("backend") == "software-test":       # unit tests only: CNG software KSP / no TPM
        return NCryptWrapper(MS_SOFTWARE_PROVIDER, options.get("key_name") or "ULPF-Test-KEK")
    if sys.platform == "win32":
        return NCryptWrapper(options.get("provider") or MS_PLATFORM_PROVIDER,
                             options.get("key_name") or "ULPF-Evidence-KEK")
    return Tpm2ToolsWrapper(directory, options.get("tcti"))


def tpm_sealed_key(path: str, options: dict, wrapper=None) -> Ed25519PrivateKey:
    """Ed25519 key stored at ``path`` (``.tpm`` JSON) as AES-256-GCM ciphertext under a TPM-wrapped data key."""
    from ulpf.runtime.keys import atomic_write, raw_private
    sealed = path + ".tpm" if not path.endswith(".tpm") else path
    wrapper = wrapper or tpm_wrapper(options, os.path.dirname(sealed))
    if os.path.exists(sealed):
        with open(sealed, "r", encoding="utf-8") as f:
            doc = json.load(f)
        dek = bytearray(wrapper.unwrap(bytes.fromhex(doc["wrapped_dek"])))
        try:
            raw = AESGCM(bytes(dek)).decrypt(bytes.fromhex(doc["nonce"]), bytes.fromhex(doc["ciphertext"]),
                                             b"ulpf-tpm-sealed-ed25519")
        finally:
            for i in range(len(dek)):
                dek[i] = 0
        key = Ed25519PrivateKey.from_private_bytes(raw)
        if hashlib.sha256(key.public_key().public_bytes_raw()).hexdigest() != doc["pub_sha256"]:
            raise ValueError(f"{sealed}: unsealed key does not match its recorded public key")
        return key
    key = Ed25519PrivateKey.generate()
    dek = bytearray(os.urandom(32))
    nonce = os.urandom(12)
    try:
        ct = AESGCM(bytes(dek)).encrypt(nonce, raw_private(key), b"ulpf-tpm-sealed-ed25519")
        wrapped = wrapper.wrap(bytes(dek))
    finally:
        for i in range(len(dek)):
            dek[i] = 0
    doc = {"format": "ulpf.tpm-sealed-ed25519", "version": 1, "wrapper": type(wrapper).__name__,
           "wrapped_dek": wrapped.hex(), "nonce": nonce.hex(), "ciphertext": ct.hex(),
           "pub_sha256": hashlib.sha256(key.public_key().public_bytes_raw()).hexdigest()}
    atomic_write(sealed, json.dumps(doc).encode())
    logger.info(f"created TPM-sealed signing key {sealed}")
    return key
