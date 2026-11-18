//! Bloom filters for lakehouse file pruning (one per indexed column per data file).
//!
//! Probes: double hashing over a 128-bit BLAKE2b digest of the value, so the bit pattern is
//! stable across builds and platforms. Serialised as `ULPFBLM1 | k u32 | m u64 | bits`.

const MAGIC: &[u8; 8] = b"ULPFBLM1";
const MAX_BITS: u64 = 1 << 28;          // 32 MiB per filter

pub struct Bloom {
    k: u32,
    m: u64,
    bits: Vec<u64>,
}

fn digest(v: &[u8]) -> (u64, u64) {
    let h = blake2b_simd::Params::new().hash_length(16).hash(v);
    let b = h.as_bytes();
    (u64::from_le_bytes(b[..8].try_into().unwrap()), u64::from_le_bytes(b[8..16].try_into().unwrap()) | 1)
}

impl Bloom {
    /// Sized for `ndv` distinct values at false-positive rate `fpp`.
    pub fn new(ndv: u64, fpp: f64) -> Bloom {
        let n = ndv.max(1) as f64;
        let p = fpp.clamp(1e-6, 0.5);
        let m = ((-n * p.ln() / (2f64.ln().powi(2))).ceil() as u64).clamp(64, MAX_BITS);
        let k = ((m as f64 / n) * 2f64.ln()).round().clamp(1.0, 16.0) as u32;
        let m = (m + 63) & !63;
        Bloom { k, m, bits: vec![0; (m / 64) as usize] }
    }

    pub fn add(&mut self, v: &[u8]) {
        let (h1, h2) = digest(v);
        for i in 0..self.k as u64 {
            let b = h1.wrapping_add(i.wrapping_mul(h2)) % self.m;
            self.bits[(b / 64) as usize] |= 1 << (b % 64);
        }
    }

    pub fn contains(&self, v: &[u8]) -> bool {
        let (h1, h2) = digest(v);
        (0..self.k as u64).all(|i| {
            let b = h1.wrapping_add(i.wrapping_mul(h2)) % self.m;
            self.bits[(b / 64) as usize] & (1 << (b % 64)) != 0
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(20 + self.bits.len() * 8);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.k.to_le_bytes());
        out.extend_from_slice(&self.m.to_le_bytes());
        for w in &self.bits {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Bloom, String> {
        if b.len() < 20 || &b[..8] != MAGIC {
            return Err("not a ULPF bloom filter".into());
        }
        let k = u32::from_le_bytes(b[8..12].try_into().unwrap());
        let m = u64::from_le_bytes(b[12..20].try_into().unwrap());
        if !(1..=16).contains(&k) || m == 0 || m % 64 != 0 || m > MAX_BITS || b.len() as u64 != 20 + m / 8 {
            return Err("corrupt bloom filter".into());
        }
        let bits = b[20..].chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
        Ok(Bloom { k, m, bits })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_false_negatives_and_rate_near_target() {
        let mut b = Bloom::new(100_000, 0.01);
        for i in 0..100_000 {
            b.add(format!("10.{}.{}.{}", i % 250, i % 199, i % 97).as_bytes());
        }
        let b = Bloom::from_bytes(&b.to_bytes()).unwrap();
        assert!((0..100_000).all(|i| b.contains(format!("10.{}.{}.{}", i % 250, i % 199, i % 97).as_bytes())));
        let fp = (0..100_000).filter(|i| b.contains(format!("x{i}").as_bytes())).count();
        assert!(fp < 2_000, "{fp}");
        assert!(Bloom::from_bytes(b"ULPFBLM1junk").is_err());
    }
}
