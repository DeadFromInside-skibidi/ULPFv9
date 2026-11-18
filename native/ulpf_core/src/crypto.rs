//! Evidence cryptography in compiled code (ed25519-dalek, SHA-256 Merkle trees).
//!
//! `FsSigner` holds a forward-secure one-time Ed25519 key inside Rust memory:
//! Python receives only the public key and signatures. `rotate()` replaces the
//! key with a fresh one and the old `SigningKey` is zeroized on drop
//! (ed25519-dalek's `zeroize` feature). `export_sealed`/`import_sealed` move the
//! key across restarts only as AES-256-GCM ciphertext under a caller-supplied KEK.
//! Merkle leaves and roots follow `ulpf.runtime.evidence` exactly.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn leaf(seq: u64, digest: &[u8]) -> [u8; 32] {
    sha256(&[b"ulpf-leaf", &seq.to_be_bytes(), digest])
}

pub fn merkle_root_of(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return sha256(&[b""]);
    }
    let mut cur = leaves.to_vec();
    while cur.len() > 1 {
        let mut nxt = Vec::with_capacity(cur.len() / 2 + 1);
        for pair in cur.chunks(2) {
            nxt.push(if pair.len() == 2 { sha256(&[&pair[0], &pair[1]]) } else { pair[0] });
        }
        cur = nxt;
    }
    cur[0]
}

fn to32(b: &[u8], what: &str) -> PyResult<[u8; 32]> {
    b.try_into().map_err(|_| PyValueError::new_err(format!("{what} must be 32 bytes")))
}

/// Merkle root (32 bytes) of leaf hashes (each 32 bytes).
#[pyfunction]
pub fn merkle_root<'py>(py: Python<'py>, leaves: Vec<Vec<u8>>) -> PyResult<Bound<'py, PyBytes>> {
    let ls: Vec<[u8; 32]> = leaves.iter().map(|l| to32(l, "leaf")).collect::<PyResult<_>>()?;
    let root = py.allow_threads(|| merkle_root_of(&ls));
    Ok(PyBytes::new_bound(py, &root))
}

/// Leaf hashes for consecutive records: SHA-256("ulpf-leaf" | seq | digest).
#[pyfunction]
pub fn merkle_leaves<'py>(py: Python<'py>, first_seq: u64, digests: Vec<Vec<u8>>) -> PyResult<Vec<Bound<'py, PyBytes>>> {
    Ok(digests.iter().enumerate().map(|(i, d)| PyBytes::new_bound(py, &leaf(first_seq + i as u64, d))).collect())
}

#[pyfunction]
pub fn ed25519_verify(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let (Ok(p), Ok(s)) = (<[u8; 32]>::try_from(public), <[u8; 64]>::try_from(signature)) else { return false };
    VerifyingKey::from_bytes(&p).map(|vk| vk.verify(message, &Signature::from_bytes(&s)).is_ok()).unwrap_or(false)
}

#[pyclass(module = "ulpf_core")]
pub struct FsSigner {
    key: SigningKey,
}

#[pymethods]
impl FsSigner {
    #[new]
    fn new() -> Self {
        FsSigner { key: SigningKey::generate(&mut OsRng) }
    }

    fn public<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, self.key.verifying_key().as_bytes())
    }

    fn sign<'py>(&self, py: Python<'py>, message: &[u8]) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.key.sign(message).to_bytes())
    }

    /// Replace the key with a fresh one (the old key is zeroized); returns the new public key.
    fn rotate<'py>(&mut self, py: Python<'py>) -> Bound<'py, PyBytes> {
        self.key = SigningKey::generate(&mut OsRng);
        self.public(py)
    }

    /// The key as nonce(12) | AES-256-GCM ciphertext under `kek`, bound to `aad`.
    fn export_sealed<'py>(&self, py: Python<'py>, kek: &[u8], aad: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let cipher = Aes256Gcm::new_from_slice(&to32(kek, "kek")?).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ct = cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: self.key.as_bytes(), aad })
            .map_err(|_| PyValueError::new_err("encryption failed"))?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        Ok(PyBytes::new_bound(py, &out))
    }

    #[staticmethod]
    fn import_sealed(blob: &[u8], kek: &[u8], aad: &[u8]) -> PyResult<Self> {
        if blob.len() < 12 + 16 + 32 {
            return Err(PyValueError::new_err("sealed key too short"));
        }
        let cipher = Aes256Gcm::new_from_slice(&to32(kek, "kek")?).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let mut pt = cipher.decrypt(Nonce::from_slice(&blob[..12]), Payload { msg: &blob[12..], aad })
            .map_err(|_| PyValueError::new_err("sealed key failed authentication"))?;
        let sk = SigningKey::from_bytes(&to32(&pt, "key")?);
        pt.iter_mut().for_each(|b| *b = 0);
        Ok(FsSigner { key: sk })
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(merkle_root, m)?)?;
    m.add_function(wrap_pyfunction!(merkle_leaves, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_verify, m)?)?;
    m.add_class::<FsSigner>()?;
    Ok(())
}
