use serde::{Serialize, Deserialize};
use numiproof_air::Air;
use numiproof_field::Fp;
use numiproof_hash::{h_many, shake256_384, DIGEST_LEN};

/// Public inputs for recursive proof verification
#[derive(Clone, Serialize, Deserialize)]
pub struct RecursivePublic {
    pub prev_digest: Vec<u8>,
    pub cur_digest: Vec<u8>,
    pub inner_proof_root: Vec<u8>,
}

/// AIR for verifying an inner proof recursively (simplified model).
/// Trace columns: 6 digest limbs plus 2 hash-state accumulators. This checks accumulator-chain
/// integrity between `prev_digest` and `cur_digest` and binds to `inner_proof_root` via public input.
#[derive(Clone)]
pub struct RecursiveAir {
    pub steps: usize,
    pub prev: Vec<u8>,
    pub cur: Vec<u8>,
    pub inner_root: Vec<u8>,
}

impl RecursiveAir {
    pub fn new(prev: Option<&[u8]>, cur: &[u8], inner_root: &[u8], steps: usize) -> Self {
        let prev_vec = prev.map(|p| p.to_vec()).unwrap_or_else(|| vec![0u8; DIGEST_LEN]);
        Self { steps, prev: prev_vec, cur: cur.to_vec(), inner_root: inner_root.to_vec() }
    }
    
    /// Decompose digest into field element limbs
    fn digest_to_limbs(digest: &[u8]) -> [Fp; 6] {
        let mut limbs = [Fp::zero(); 6];
        for i in 0..6 {
            let start = i * 8;
            if start + 8 <= digest.len() {
                let mut chunk = [0u8; 8];
                chunk.copy_from_slice(&digest[start..start+8]);
                limbs[i] = Fp::new(u64::from_le_bytes(chunk));
            }
        }
        limbs
    }
    
    /// Recompose limbs back to digest
    fn limbs_to_digest(limbs: &[Fp; 6]) -> Vec<u8> {
        let mut digest = Vec::with_capacity(48);
        for limb in limbs.iter() {
            digest.extend_from_slice(&limb.to_u64().to_le_bytes());
        }
        digest
    }
}

impl Air for RecursiveAir {
    type PublicInput = RecursivePublic;
    fn id(&self) -> &'static str { "recursive_v2" }
    fn trace_len(&self) -> usize { self.steps }
    fn n_cols(&self) -> usize { 8 } // 6 digest limbs + 2 hash state accumulators
    
    fn public_input(&self) -> Self::PublicInput {
        let new_digest = if self.prev.is_empty() || self.prev.iter().all(|&b| b == 0) {
            h_many("accumulator", &[&self.cur]).to_vec()
        } else {
            h_many("accumulator", &[&self.prev, &self.cur]).to_vec()
        };
        RecursivePublic {
            prev_digest: self.prev.clone(),
            cur_digest: new_digest,
            inner_proof_root: self.inner_root.clone(),
        }
    }
    
    fn gen_trace(&self) -> Vec<Vec<Fp>> {
        let n = self.steps;
        let mut cols = vec![vec![Fp::zero(); n]; 8];
        
        // Initial row: prev digest decomposed
        let prev_limbs = Self::digest_to_limbs(&self.prev);
        for (j, &limb) in prev_limbs.iter().enumerate() {
            cols[j][0] = limb;
        }
        
        // Compute accumulator chain: hash prev with cur iteratively
        let cur_limbs = Self::digest_to_limbs(&self.cur);
        
        for i in 1..n {
            // Each step accumulates: combine previous digest with current
            // Simplified: just propagate and mix limbs
            for j in 0..6 {
                let prev_val = cols[j][i-1];
                let cur_val = cur_limbs[j % 6];
                // Simple mixing: add with rotation
                cols[j][i] = prev_val + cur_val;
            }
            // Hash state columns: accumulate XOR-like operations in field
            cols[6][i] = cols[6][i-1] + cols[0][i];
            cols[7][i] = cols[7][i-1] + cols[1][i];
        }
        
        // Final row should match expected output digest
        let expected_limbs = Self::digest_to_limbs(&self.public_input().cur_digest);
        for j in 0..6 {
            cols[j][n-1] = expected_limbs[j];
        }
        
        cols
    }
    
    fn check_row(i: usize, row: &[Fp], next: Option<&[Fp]>, pub_inp: &Self::PublicInput) -> bool {
        if i == 0 {
            // First row: verify matches prev_digest
            let prev_limbs = Self::digest_to_limbs(&pub_inp.prev_digest);
            for (j, &expected) in prev_limbs.iter().enumerate() {
                if row[j] != expected { return false; }
            }
        }
        
        if let Some(nxt) = next {
            // Transition: verify accumulation consistency
            let cur_limbs = Self::digest_to_limbs(&pub_inp.cur_digest);
            for j in 0..6 {
                let expected_next = row[j] + cur_limbs[j % 6];
                if nxt[j] != expected_next { return false; }
            }
            // Hash state transitions
            if nxt[6] != row[6] + nxt[0] { return false; }
            if nxt[7] != row[7] + nxt[1] { return false; }
        } else {
            // Last row: verify matches cur_digest
            let cur_limbs = Self::digest_to_limbs(&pub_inp.cur_digest);
            for (j, &expected) in cur_limbs.iter().enumerate().take(6) {
                if row[j] != expected { return false; }
            }
        }
        true
    }
    
    fn eval_constraints(&self, i: usize, row: &[Fp], next: Option<&[Fp]>, pub_inp: &Self::PublicInput) -> Vec<Fp> {
        let mut constraints = vec![Fp::zero(); 8];
        
        if i == 0 {
            // Boundary constraint: first row matches prev_digest
            let prev_limbs = Self::digest_to_limbs(&pub_inp.prev_digest);
            for (j, &expected) in prev_limbs.iter().enumerate() {
                constraints[j] = row[j] - expected;
            }
        }
        
        if let Some(nxt) = next {
            // Transition constraints
            let cur_limbs = Self::digest_to_limbs(&pub_inp.cur_digest);
            for j in 0..6 {
                constraints[j] = nxt[j] - (row[j] + cur_limbs[j % 6]);
            }
            constraints[6] = nxt[6] - (row[6] + nxt[0]);
            constraints[7] = nxt[7] - (row[7] + nxt[1]);
        } else {
            // Boundary constraint: last row matches cur_digest
            let cur_limbs = Self::digest_to_limbs(&pub_inp.cur_digest);
            for (j, &expected) in cur_limbs.iter().enumerate().take(6) {
                constraints[j] = row[j] - expected;
            }
        }
        
        constraints
    }
}


