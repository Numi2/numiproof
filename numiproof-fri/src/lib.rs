use numiproof_field::Fp;
use numiproof_hash::{h_many, shake256_384};
use numiproof_merkle::MerkleTree;
use serde::{Deserialize, Serialize};

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
            .iter()
            .map(|v| {
                let bytes = v.to_u64().to_le_bytes();
                shake256_384(&h_many("fri.leaf", &[&bytes])).to_vec()
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
            shake256_384(&h_many("fri.leaf", &[&b])).to_vec()
        };
        MerkleTree::verify(&commitment.oracle.root, proof.idx, &leaf, &proof.path)
    }

    pub fn verify_pair(root: &[u8], len: usize, pair: &PairOpening) -> bool {
        if pair.lo.idx >= len || pair.hi.idx >= len { return false; }
        let leaf_lo = {
            let b = pair.lo.value.to_u64().to_le_bytes();
            shake256_384(&h_many("fri.leaf", &[&b])).to_vec()
        };
        let leaf_hi = {
            let b = pair.hi.value.to_u64().to_le_bytes();
            shake256_384(&h_many("fri.leaf", &[&b])).to_vec()
        };
        MerkleTree::verify(root, pair.lo.idx, &leaf_lo, &pair.lo.path) &&
        MerkleTree::verify(root, pair.hi.idx, &leaf_hi, &pair.hi.path)
    }
}


