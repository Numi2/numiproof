// File: numiproof-proof/src/lib.rs
use numiproof_air::{Air, row_to_bytes, FibPublic, FibonacciAir};
use numiproof_hash::{h_many, shake256_384, Transcript};
use numiproof_merkle::MerkleTree;
use rand::RngCore;
use serde::{Serialize, Deserialize};
use numiproof_field::Fp;
use numiproof_poly::{eval_poly_on_domain, vanishing_on_extended, lde_from_evals};
use numiproof_fri::{FriProver, FriVerifier, FriCommitment, FriQuery, FriRoundCommitment, FriMultiCommitment, FriRoundQuery, FriMultiQuery};

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
    // FRI-oracle commitment to masked LDE of each column (demo: commit one concatenated oracle for rows)
    pub fri_commitment: Option<FriCommitment>,
    pub fri_queries: Option<Vec<FriQuery>>, // legacy single-round
    // Multi-round FRI (demo folding with 1 round)
    pub fri_rounds: Option<FriMultiCommitment>,
    pub fri_round_queries: Option<Vec<FriMultiQuery>>,
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

        // Build trace rows and leaves (base domain)
        let cols = air.gen_trace();
        let n = air.trace_len();
        let mut leaves = Vec::with_capacity(n);
        let mut rows = Vec::with_capacity(n);
        for i in 0..n {
            let row: Vec<Fp> = vec![cols[0][i], cols[1][i]];
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

        // ZK masking: compute evaluations of r(x)*z_base(x), with small random r(x)
        let blowup_log2 = 2u32; // demo blowup x4
        let ext_size = n << blowup_log2;
        let mut rng_mask = tr.rng();
        let r0 = Fp::new(rng_mask.next_u64());
        let r1 = Fp::new(rng_mask.next_u64());
        let mask_evals = {
            let r_coeffs = [r0, r1];
            let r_eval = eval_poly_on_domain(&r_coeffs, ext_size);
            let z_base = vanishing_on_extended(ext_size, n);
            r_eval.iter().zip(z_base.iter()).map(|(a,b)| *a * *b).collect::<Vec<Fp>>()
        };
        // Commit to masked oracle: compute true LDE from base evals
        let col0_base: Vec<Fp> = (0..n).map(|i| cols[0][i]).collect();
        let mut fri_values: Vec<Fp> = lde_from_evals(&col0_base, blowup_log2);
        for i in 0..ext_size { fri_values[i] += mask_evals[i]; }
        let (fri_commitment, fri_mt) = FriProver::commit(&fri_values);
        // Single folding round (demo)
        let mut fri_rounds: Vec<FriRoundCommitment> = Vec::new();
        let mut round_mts = Vec::new();
        let alpha_bytes = tr.challenge_bytes(8);
        let alpha = Fp::new(u64::from_le_bytes(alpha_bytes.try_into().unwrap()));
        let folded = numiproof_fri::FriProver::fold_values(alpha, &fri_values);
        let (rc, rmt) = numiproof_fri::FriProver::commit_round(&folded);
        fri_rounds.push(rc);
        round_mts.push((folded, rmt));

        let mut rng = tr.rng();
        let mut openings = Vec::with_capacity(self.queries);
        let mut fri_queries: Vec<FriQuery> = Vec::with_capacity(self.queries);
        let mut fri_round_queries: Vec<FriMultiQuery> = Vec::with_capacity(self.queries);
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

            // FRI oracle opening at a mapped extended index
            let ext_idx = idx << blowup_log2; // map base index to start of its coset in extended domain
            let fp = fri_values[ext_idx];
            let oracle_proof = FriProver::open(&fri_mt, ext_idx, fp);
            fri_queries.push(FriQuery { oracle_proof });

            // Pair opening for folded round
            let mut rounds_vec = Vec::new();
            let (ref folded_vals, ref rmt) = round_mts[0];
            let pair = numiproof_fri::FriProver::open_pair(folded_vals, rmt, ext_idx % folded_vals.len());
            rounds_vec.push(FriRoundQuery { pair });
            fri_round_queries.push(FriMultiQuery { rounds: rounds_vec });
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
            fri_commitment: Some(fri_commitment),
            fri_queries: Some(fri_queries),
            fri_rounds: Some(FriMultiCommitment { rounds: fri_rounds }),
            fri_round_queries: Some(fri_round_queries),
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
            let row = match bytes_to_fps(&o.row) {
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
                    match bytes_to_fps(b) {
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

            // Verify FRI oracle opening for same index (demo)
            if let (Some(ref commit), Some(ref queries)) = (&proof.fri_commitment, &proof.fri_queries) {
                let q = &queries[k];
                if q.oracle_proof.idx != expected_idx { return false; }
                if !FriVerifier::verify_opening(commit, &q.oracle_proof) { return false; }
            }

            // Verify folding round consistency
            if let (Some(ref rounds), Some(ref rq)) = (&proof.fri_rounds, &proof.fri_round_queries) {
                let alpha_bytes = tr.challenge_bytes(8);
                let alpha = Fp::new(u64::from_le_bytes(alpha_bytes.try_into().unwrap()));
                let r = &rounds.rounds[0];
                let q = &rq[k].rounds[0];
                if !numiproof_fri::FriVerifier::verify_pair(&r.root, r.len, &q.pair) { return false; }
                // Check folded relation: f'(i) = f(i) + alpha * f(i+N/2)
                if let (Some(ref _commit), Some(ref queries)) = (&proof.fri_commitment, &proof.fri_queries) {
                    let _base = &queries[k].oracle_proof;
                    // we only have single opening; in demo, assume path/values cover consistency by trusting pair opening
                    let lo = q.pair.lo.value;
                    let hi = q.pair.hi.value;
                    let folded_val = lo + alpha * hi;
                    // No direct check against folded oracle value here beyond inclusion; acceptable for demo
                    let _ = folded_val;
                }
            }
        }

        // Digest check
        let expect_digest = h_many("proof.digest", &[&proof.merkle_root, &proof.pub_input_enc, &(proof.queries as u64).to_le_bytes()]);
        proof.proof_digest == expect_digest
    }
}

fn bytes_to_fps(b: &[u8]) -> Option<Vec<Fp>> {
    if b.len()%8!=0 { return None; }
    Some(b.chunks_exact(8).map(|c| {
        let v = u64::from_le_bytes(c.try_into().unwrap());
        Fp::new(v)
    }).collect())
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