use numiproof_field::Fp;
use numiproof_hash::{h_many, shake256_384, DOM_FRI_LEAF};
use numiproof_merkle::MerkleTree;
use serde::{Deserialize, Serialize};
use rayon::prelude::*;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OracleCommitment {
    pub root: Vec<u8>,
    pub len: usize,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OracleProof {
    pub idx: usize,
    pub value: Fp,
    pub path: Vec<Vec<u8>>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct FriCommitment {
    pub oracle: OracleCommitment,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct FriQuery {
    pub oracle_proof: OracleProof,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct FriRoundCommitment {
    pub root: Vec<u8>,
    pub len: usize,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct FriMultiCommitment {
    pub rounds: Vec<FriRoundCommitment>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PairOpening {
    pub pos: usize,
    pub lo: OracleProof,
    pub hi: OracleProof,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct FriRoundQuery {
    pub pair: PairOpening,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct FriMultiQuery {
    pub rounds: Vec<FriRoundQuery>,
}

/// DEEP-FRI: Out-of-domain evaluation samples and algebraic link primitives
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DeepSample {
    pub z: Fp,  // Out-of-domain point
    pub value: Fp,  // Polynomial evaluation at z
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DeepCommitment {
    pub samples: Vec<DeepSample>,
    pub composition_root: Vec<u8>,
}

pub struct FriProver;
impl FriProver {
    pub fn commit(values: &[Fp]) -> (FriCommitment, MerkleTree) {
        let leaves: Vec<Vec<u8>> = values
            .par_iter()
            .map(|v| {
                let bytes = v.to_u64().to_le_bytes();
                shake256_384(&h_many(DOM_FRI_LEAF, &[&bytes])).to_vec()
            })
            .collect();
        let mt = MerkleTree::build(&leaves);
        let root = mt.root();
        (FriCommitment { oracle: OracleCommitment { root, len: values.len() } }, mt)
    }

    /// DEEP-FRI: Sample polynomial at out-of-domain points for stronger security
    pub fn deep_sample(poly_coeffs: &[Fp], num_samples: usize, seed: &[u8]) -> Vec<DeepSample> {
        use numiproof_hash::shake256_384;
        let mut samples = Vec::with_capacity(num_samples);
        for i in 0..num_samples {
            // Derive deterministic out-of-domain point from seed
            let point_seed = [seed, &i.to_le_bytes()].concat();
            let hash = shake256_384(&point_seed);
            let z_raw = u64::from_le_bytes(hash[0..8].try_into().unwrap());
            let z = Fp::new(z_raw);
            
            // Evaluate polynomial at z using Horner's method
            let mut value = Fp::zero();
            for &coeff in poly_coeffs.iter().rev() {
                value = value * z + coeff;
            }
            
            samples.push(DeepSample { z, value });
        }
        samples
    }

    /// Compute DEEP composition quotient: (f(X) - f(z)) / (X - z) via synthetic division
    pub fn deep_quotient(poly_coeffs: &[Fp], z: Fp, f_z: Fp) -> Vec<Fp> {
        let n = poly_coeffs.len();
        if n == 0 { return vec![]; }
        
        // Build f(X) - f(z)
        let mut shifted = poly_coeffs.to_vec();
        shifted[0] = shifted[0] - f_z;
        
        // Polynomial division by (X - z)
        let mut quotient = vec![Fp::zero(); n.saturating_sub(1)];
        if n > 1 {
            let mut remainder = shifted[n - 1];
            quotient[n - 2] = remainder;
            
            for i in (0..n-1).rev() {
                remainder = shifted[i] + z * remainder;
                if i > 0 {
                    quotient[i - 1] = remainder;
                }
            }
        }
        quotient
    }

    pub fn open(mt: &MerkleTree, idx: usize, value: Fp) -> OracleProof {
        let path = mt.open(idx);
        OracleProof { idx, value, path }
    }

    pub fn commit_round(values: &[Fp]) -> (FriRoundCommitment, MerkleTree) {
        let (c, mt) = Self::commit(values);
        (FriRoundCommitment { root: c.oracle.root, len: c.oracle.len }, mt)
    }

    pub fn open_pair(values: &[Fp], mt: &MerkleTree, pos: usize) -> PairOpening {
        let len = values.len();
        let half = len / 2;
        let lo_idx = pos % len;
        let hi_idx = lo_idx ^ half;
        let lo_val = values[lo_idx];
        let hi_val = values[hi_idx];
        let lo = Self::open(mt, lo_idx, lo_val);
        let hi = Self::open(mt, hi_idx, hi_val);
        PairOpening { pos: lo_idx, lo, hi }
    }

    pub fn fold_values(alpha: Fp, values: &[Fp]) -> Vec<Fp> {
        let len = values.len();
        assert!(len % 2 == 0);
        let half = len / 2;
        let mut out = Vec::with_capacity(half);
        for i in 0..half {
            out.push(values[i] + alpha * values[i + half]);
        }
        out
    }
}

pub struct FriVerifier;
impl FriVerifier {
    pub fn verify_opening(commitment: &FriCommitment, proof: &OracleProof) -> bool {
        if proof.idx >= commitment.oracle.len { return false; }
        let leaf = {
            let b = proof.value.to_u64().to_le_bytes();
            shake256_384(&h_many(DOM_FRI_LEAF, &[&b])).to_vec()
        };
        MerkleTree::verify(&commitment.oracle.root, proof.idx, &leaf, &proof.path)
    }

    pub fn verify_pair(root: &[u8], len: usize, pair: &PairOpening) -> bool {
        if pair.lo.idx >= len || pair.hi.idx >= len { return false; }
        let leaf_lo = {
            let b = pair.lo.value.to_u64().to_le_bytes();
            shake256_384(&h_many(DOM_FRI_LEAF, &[&b])).to_vec()
        };
        let leaf_hi = {
            let b = pair.hi.value.to_u64().to_le_bytes();
            shake256_384(&h_many(DOM_FRI_LEAF, &[&b])).to_vec()
        };
        MerkleTree::verify(root, pair.lo.idx, &leaf_lo, &pair.lo.path) &&
        MerkleTree::verify(root, pair.hi.idx, &leaf_hi, &pair.hi.path)
    }

    /// Verify multi-round FRI folding consistency across all rounds
    pub fn verify_folding_chain(
        alpha: Fp,
        pair: &PairOpening,
        next_pair: Option<&PairOpening>,
    ) -> bool {
        // Compute expected folded value: lo + alpha * hi
        let expected_folded = pair.lo.value + alpha * pair.hi.value;
        
        // If there's a next round, verify consistency
        if let Some(next) = next_pair {
            // The folded value should appear in the next round at the mapped position
            let folded_idx = pair.pos / 2;
            if next.lo.idx != folded_idx && next.hi.idx != folded_idx {
                return false;
            }
            // Check that one of the next pair values matches our expected folded value
            next.lo.value == expected_folded || next.hi.value == expected_folded
        } else {
            // Final round - no further verification needed
            true
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fri_commit_and_verify_single_opening() {
        // Build a simple oracle and verify inclusion for several indices
        let values: Vec<Fp> = (0..32).map(|i| Fp::new(i as u64 + 1)).collect();
        let (commit, mt) = FriProver::commit(&values);
        for idx in [0usize, 1, 7, 15, 31] {
            let val = values[idx];
            let proof = FriProver::open(&mt, idx, val);
            assert!(FriVerifier::verify_opening(&commit, &proof));
        }
    }

    #[test]
    fn fri_fold_values_and_pair_opening_consistency() {
        let values: Vec<Fp> = (0..64).map(|i| Fp::new((i as u64).wrapping_mul(3) + 5)).collect();
        let (commit, mt) = FriProver::commit(&values);
        let alpha = Fp::new(7);
        let folded = FriProver::fold_values(alpha, &values);
        let (round_commit, round_mt) = FriProver::commit_round(&folded);

        // For a few positions, check the folded relation via the pair opening
        for base_idx in [0usize, 5, 13, 27, 31] {
            let pair = FriProver::open_pair(&values, &mt, base_idx);
            assert!(FriVerifier::verify_pair(&commit.oracle.root, commit.oracle.len, &pair));
            // Compute expected folded value
            let lo = pair.lo.value;
            let hi = pair.hi.value;
            let expected = lo + alpha * hi;
            // Verify inclusion in folded round for the mapped index
            let folded_idx = base_idx % folded.len();
            // We can't open folded oracle here directly without a corresponding proof builder,
            // but at least ensure the round commitment verifies the pair inclusion
            // and check the computed expected value equals folded value
            assert_eq!(expected, folded[folded_idx]);
            // Also verify pair against the round root
            // Construct a synthetic pair proof relative to round (reuse values and indices)
            let pair2 = FriProver::open_pair(&folded, &round_mt, folded_idx);
            assert!(FriVerifier::verify_pair(&round_commit.root, round_commit.len, &pair2));
        }
    }
}
