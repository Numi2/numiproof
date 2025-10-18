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
            shake256_384(&h_many("fri.leaf", &[&b])).to_vec()
        };
        MerkleTree::verify(root, pair.lo.idx, &leaf_lo, &pair.lo.path) &&
        MerkleTree::verify(root, pair.hi.idx, &leaf_hi, &pair.hi.path)
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
