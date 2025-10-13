// File: numiproof-hash/src/lib.rs
use rand::{rngs::StdRng, RngCore, SeedableRng};
use sha3::{digest::{ExtendableOutput, Update, XofReader}, Shake256};
use serde::{Serialize, Deserialize};

pub const DIGEST_LEN: usize = 48; // 384-bit output

#[inline]
pub fn shake256_384(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Shake256::default();
    hasher.update(data);
    let mut xof = hasher.finalize_xof();
    let mut out = [0u8; DIGEST_LEN];
    xof.read(&mut out);
    out
}

#[inline]
pub fn h2(label: &str, a: &[u8], b: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Shake256::default();
    hasher.update(label.as_bytes());
    hasher.update(&[0]);
    hasher.update(a);
    hasher.update(&[1]);
    hasher.update(b);
    let mut xof = hasher.finalize_xof();
    let mut out = [0u8; DIGEST_LEN];
    xof.read(&mut out);
    out
}

#[inline]
pub fn h_many(label: &str, parts: &[&[u8]]) -> [u8; DIGEST_LEN] {
    let mut hasher = Shake256::default();
    hasher.update(label.as_bytes());
    for (i, p) in parts.iter().enumerate() {
        hasher.update(&[i as u8]);
        hasher.update(p);
    }
    let mut xof = hasher.finalize_xof();
    let mut out = [0u8; DIGEST_LEN];
    xof.read(&mut out);
    out
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Transcript {
    state: Vec<u8>,
}
impl Transcript {
    pub fn new(domain: &str) -> Self {
        Self { state: domain.as_bytes().to_vec() }
    }
    pub fn absorb(&mut self, label: &str, data: &[u8]) {
        let mut buf = Vec::with_capacity(self.state.len()+1+label.len()+data.len());
        buf.extend_from_slice(&self.state);
        buf.push(0xFF);
        buf.extend_from_slice(label.as_bytes());
        buf.push(0);
        buf.extend_from_slice(data);
        self.state = shake256_384(&buf).to_vec();
    }
    pub fn challenge_bytes(&self, out_len: usize) -> Vec<u8> {
        let mut hasher = Shake256::default();
        hasher.update(&self.state);
        let mut xof = hasher.finalize_xof();
        let mut out = vec![0u8; out_len];
        xof.read(&mut out);
        out
    }
    pub fn challenge_u64(&self) -> u64 {
        let b = self.challenge_bytes(8);
        u64::from_le_bytes(b.try_into().unwrap())
    }
    pub fn rng(&self) -> StdRng {
        let seed = self.challenge_bytes(32);
        StdRng::from_seed(seed.as_slice().try_into().unwrap())
    }
}