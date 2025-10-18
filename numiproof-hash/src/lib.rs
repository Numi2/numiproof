// File: numiproof-hash/src/lib.rs
use rand::{rngs::StdRng, SeedableRng};
use sha3::{digest::{ExtendableOutput, Update, XofReader}, Shake256};
use serde::{Serialize, Deserialize};

pub const DIGEST_LEN: usize = 48; // 384-bit output

// Domain labels
pub const DOM_ROW: &str = "row";
pub const DOM_MERKLE_NODE: &str = "merkle.node";
pub const DOM_FRI_LEAF: &str = "fri.leaf";
pub const DOM_PROOF_DIGEST: &str = "proof.digest";
pub const DOM_ACCUMULATOR: &str = "accumulator";

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shake256_384_length_and_differs() {
        let a = shake256_384(b"hello");
        let b = shake256_384(b"world");
        assert_eq!(a.len(), DIGEST_LEN);
        assert_eq!(b.len(), DIGEST_LEN);
        assert_ne!(a.to_vec(), b.to_vec());
    }

    #[test]
    fn h2_and_hmany_domain_separation() {
        let x = h2("domain", b"a", b"b");
        let y = h2("domain2", b"a", b"b");
        assert_ne!(x.to_vec(), y.to_vec());
        let m1 = h_many("domain", &[b"a", b"b"]);
        let m2 = h_many("domain", &[b"ab"]);
        assert_ne!(m1.to_vec(), m2.to_vec());
    }

    #[test]
    fn transcript_absorb_and_challenge_changes() {
        let mut t1 = Transcript::new("ns");
        let mut t2 = Transcript::new("ns");
        t1.absorb("k", b"v");
        t2.absorb("k", b"v");
        assert_eq!(t1.challenge_bytes(16), t2.challenge_bytes(16));
        t1.absorb("k", b"v2");
        assert_ne!(t1.challenge_bytes(16), t2.challenge_bytes(16));
    }
}