// File: numiproof-proof/src/lib.rs
use numiproof_air::{Air, row_to_bytes, FibPublic, FibonacciAir};
use numiproof_hash::{h_many, shake256_384, Transcript};
use numiproof_merkle::MerkleTree;
use rand::RngCore;
use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Opening {
    pub idx: usize,
    pub row: Vec<u8>,
    pub next_row: Option<Vec<u8>>,
    pub path_row: Vec<Vec<u8>>,
    pub path_next: Option<Vec<Vec<u8>>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Proof {
    pub air_id: String,
    pub pub_input_enc: Vec<u8>,
    pub merkle_root: Vec<u8>,
    pub n_rows: usize,
    pub n_cols: usize,
    pub queries: usize,
    pub openings: Vec<Opening>,
    pub proof_digest: Vec<u8>,
}

pub struct Prover {
    pub queries: usize,
}
impl Default for Prover { fn default() -> Self { Self { queries: 40 } } }

impl Prover {
    pub fn prove_fib(&self, air: &FibonacciAir) -> Proof {
        let pub_inp = air.public_input();
        let pub_inp_enc = bincode::serialize(&pub_inp).unwrap();

        // Build trace rows and leaves
        let cols = air.gen_trace();
        let n = air.trace_len();
        let mut leaves = Vec::with_capacity(n);
        let mut rows = Vec::with_capacity(n);
        for i in 0..n {
            let row = vec![cols[0][i], cols[1][i]];
            let bytes = row_to_bytes(&row);
            let leaf = shake256_384(&h_many("row", &[&bytes])).to_vec();
            leaves.push(leaf);
            rows.push(bytes);
        }
        let mt = MerkleTree::build(&leaves);
        let root = mt.root();

        // Fiat–Shamir for queries
        let mut tr = Transcript::new("numiproof.fs");
        tr.absorb("air_id", air.id().as_bytes());
        tr.absorb("pub_input", &pub_inp_enc);
        tr.absorb("root", &root);

        let mut rng = tr.rng();
        let mut openings = Vec::with_capacity(self.queries);
        for _ in 0..self.queries {
            let idx = (rng.next_u64() as usize) % n;
            // open row i
            let path_row = mt.open(idx);
            let next_idx = if idx+1 < n { Some(idx+1) } else { None };
            let (next_row, path_next) = if let Some(j) = next_idx {
                (Some(rows[j].clone()), Some(mt.open(j)))
            } else { (None, None) };
            openings.push(Opening {
                idx, row: rows[idx].clone(),
                next_row,
                path_row,
                path_next,
            });
        }

        let proof_digest = h_many("proof.digest", &[&root, &pub_inp_enc, &(self.queries as u64).to_le_bytes()]).to_vec();

        Proof {
            air_id: air.id().to_string(),
            pub_input_enc: pub_inp_enc,
            merkle_root: root,
            n_rows: n,
            n_cols: air.n_cols(),
            queries: self.queries,
            openings,
            proof_digest,
        }
    }
}

pub struct Verifier;
impl Verifier {
    pub fn verify_fib(proof: &Proof) -> bool {
        if proof.air_id != "fibonacci_v1" { return false; }
        let Ok(pub_inp) = bincode::deserialize::<FibPublic>(&proof.pub_input_enc) else { return false; };
        // Rebuild transcript to bind query positions
        let mut tr = Transcript::new("numiproof.fs");
        tr.absorb("air_id", proof.air_id.as_bytes());
        tr.absorb("pub_input", &proof.pub_input_enc);
        tr.absorb("root", &proof.merkle_root);
        let mut rng = tr.rng();

        for k in 0..proof.queries {
            let expected_idx = (rng.next_u64() as usize) % proof.n_rows;
            let o = &proof.openings[k];
            if o.idx != expected_idx { return false; }

            // Verify Merkle openings
            let leaf = shake256_384(&h_many("row", &[&o.row])).to_vec();
            if !numiproof_merkle::MerkleTree::verify(&proof.merkle_root, o.idx, &leaf, &o.path_row) {
                return false;
            }
            let row = match bytes_to_u64s(&o.row) {
                Some(r) => r,
                None => return false,
            };
            let next = match (&o.next_row, &o.path_next) {
                (Some(b), Some(path)) => {
                    let j = o.idx + 1;
                    let nleaf = shake256_384(&h_many("row", &[b])).to_vec();
                    if !numiproof_merkle::MerkleTree::verify(&proof.merkle_root, j, &nleaf, path) {
                        return false;
                    }
                    match bytes_to_u64s(b) {
                        Some(r) => Some(r),
                        None => return false,
                    }
                },
                (None, None) => None,
                _ => return false
            };
            if !FibonacciAir::check_row(o.idx, &row, next.as_deref(), &pub_inp) {
                return false;
            }
        }

        // Digest check
        let expect_digest = h_many("proof.digest", &[&proof.merkle_root, &proof.pub_input_enc, &(proof.queries as u64).to_le_bytes()]);
        proof.proof_digest == expect_digest
    }
}

fn bytes_to_u64s(b: &[u8]) -> Option<Vec<u64>> {
    if b.len()%8!=0 { return None; }
    Some(b.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect())
}

/// Hash-chain accumulator for "recursive" aggregation of proofs.
pub fn accumulate(prev: Option<&[u8]>, cur: &[u8]) -> Vec<u8> {
    match prev {
        Some(p) => h_many("accumulator", &[p, cur]).to_vec(),
        None => h_many("accumulator", &[cur]).to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fib_prove_verify() {
        let air = FibonacciAir::new(1,1,64);
        let prover = Prover { queries: 32 };
        let proof = prover.prove_fib(&air);
        assert!(Verifier::verify_fib(&proof));
    }
}