// File: numiproof-proof/src/lib.rs
use numiproof_air::{Air, row_to_bytes, FibPublic, FibonacciAir};
use numiproof_hash::{h_many, shake256_384, Transcript, DOM_ROW, DOM_PROOF_DIGEST, DOM_ACCUMULATOR};
use numiproof_merkle::MerkleTree;
use rand::RngCore;
use serde::{Serialize, Deserialize};
use numiproof_field::Fp;
use numiproof_poly::{eval_poly_on_domain, vanishing_on_extended, lde_from_evals};
use numiproof_fri::{FriProver, FriVerifier, FriCommitment, FriQuery, FriRoundCommitment, FriMultiCommitment, FriRoundQuery, FriMultiQuery};
use rayon::prelude::*;

#[derive(Clone, Serialize, Deserialize)]
pub struct Opening {
    pub idx: usize,
    pub row: Vec<u8>,
    pub next_row: Option<Vec<u8>>,
    pub path_row: Vec<Vec<u8>>,
    pub path_next: Option<Vec<Vec<u8>>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProofV1 {
    pub version: u8,
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

pub type Proof = ProofV1; // Backwards-compatible alias

#[derive(Clone, Copy)]
pub struct FriConfig {
    pub blowup_log2: u32,
    pub num_rounds: u32,
    pub queries: usize,
}
impl Default for FriConfig {
    fn default() -> Self {
        Self { blowup_log2: 3, num_rounds: 5, queries: 80 }
    }
}

pub struct Prover {
    pub cfg: FriConfig,
}
impl Default for Prover { fn default() -> Self { Self { cfg: FriConfig::default() } } }

impl Prover {
    pub fn prove_fib(&self, air: &FibonacciAir) -> ProofV1 {
        let pub_inp = air.public_input();
        let pub_inp_enc = bincode::serialize(&pub_inp).unwrap();

        // Build trace rows and leaves (base domain)
        let cols = air.gen_trace();
        let n = air.trace_len();
        let mut leaves = Vec::with_capacity(n);
        let mut rows = Vec::with_capacity(n);
        (0..n).into_par_iter().for_each(|_i| {}); // ensure rayon linked
        for i in 0..n {
            let row: Vec<Fp> = vec![cols[0][i], cols[1][i]];
            let bytes = row_to_bytes(&row);
            let leaf = shake256_384(&h_many(DOM_ROW, &[&bytes])).to_vec();
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
        let blowup_log2 = self.cfg.blowup_log2;
        // Use power-of-two base size for extended domain to align with FFT-based LDE
        let base_pow2 = n.next_power_of_two();
        let ext_size = base_pow2 << blowup_log2;
        let mut rng_mask = tr.rng();
        let r0 = Fp::new(rng_mask.next_u64());
        let r1 = Fp::new(rng_mask.next_u64());
        let mask_evals = {
            let r_coeffs = [r0, r1];
            let r_eval = eval_poly_on_domain(&r_coeffs, ext_size);
            // Vanish on the power-of-two base domain to ensure zeros align with LDE sampling points
            let z_base = vanishing_on_extended(ext_size, base_pow2);
            r_eval.iter().zip(z_base.iter()).map(|(a,b)| *a * *b).collect::<Vec<Fp>>()
        };
        // Commit to masked composition oracle: challenge-weighted combination of column LDEs
        let col0_base: Vec<Fp> = (0..n).map(|i| cols[0][i]).collect();
        let col1_base: Vec<Fp> = (0..n).map(|i| cols[1][i]).collect();
        let col0_ext: Vec<Fp> = lde_from_evals(&col0_base, blowup_log2);
        let col1_ext: Vec<Fp> = lde_from_evals(&col1_base, blowup_log2);
        let gamma0_bytes = tr.challenge_bytes(8);
        let gamma1_bytes = tr.challenge_bytes(8);
        let gamma0 = Fp::new(u64::from_le_bytes(gamma0_bytes.try_into().unwrap()));
        let gamma1 = Fp::new(u64::from_le_bytes(gamma1_bytes.try_into().unwrap()));
        let mut fri_values: Vec<Fp> = vec![Fp::zero(); ext_size];
        for i in 0..ext_size {
            // Simple composition: linear combination of columns + mask for zero-knowledge
            fri_values[i] = gamma0 * col0_ext[i] + gamma1 * col1_ext[i] + mask_evals[i];
        }
        let (fri_commitment, fri_mt) = FriProver::commit(&fri_values);
        // Multi-round folding (configurable; demo correctness checks kept simple)
        let mut fri_rounds: Vec<FriRoundCommitment> = Vec::new();
        let mut round_mts: Vec<(Vec<Fp>, numiproof_merkle::MerkleTree)> = Vec::new();
        let mut current_values = fri_values.clone();
        for _round in 0..self.cfg.num_rounds {
            let alpha_bytes = tr.challenge_bytes(8);
            let alpha = Fp::new(u64::from_le_bytes(alpha_bytes.try_into().unwrap()));
            let folded = numiproof_fri::FriProver::fold_values(alpha, &current_values);
            let (rc, rmt) = numiproof_fri::FriProver::commit_round(&folded);
            fri_rounds.push(rc);
            round_mts.push((folded.clone(), rmt));
            current_values = folded;
        }

        let mut rng = tr.rng();
        let mut openings = Vec::with_capacity(self.cfg.queries);
        let mut fri_queries: Vec<FriQuery> = Vec::with_capacity(self.cfg.queries);
        let mut fri_round_queries: Vec<FriMultiQuery> = Vec::with_capacity(self.cfg.queries);
        for _ in 0..self.cfg.queries {
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

            // Pair openings for each folded round
            let mut rounds_vec = Vec::new();
            for (folded_vals, rmt) in round_mts.iter() {
                let pair = numiproof_fri::FriProver::open_pair(folded_vals, rmt, ext_idx % folded_vals.len());
                rounds_vec.push(FriRoundQuery { pair });
            }
            fri_round_queries.push(FriMultiQuery { rounds: rounds_vec });
        }

        let proof_digest = h_many(DOM_PROOF_DIGEST, &[&root, &pub_inp_enc, &(self.cfg.queries as u64).to_le_bytes()]).to_vec();

        ProofV1 {
            version: 1,
            air_id: air.id().to_string(),
            pub_input_enc: pub_inp_enc,
            merkle_root: root,
            n_rows: n,
            n_cols: air.n_cols(),
            queries: self.cfg.queries,
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
    pub fn verify_fib(proof: &ProofV1) -> bool {
        if proof.version != 1 { return false; }
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
            let leaf = shake256_384(&h_many(DOM_ROW, &[&o.row])).to_vec();
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
                    let nleaf = shake256_384(&h_many(DOM_ROW, &[b])).to_vec();
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
                // Determine blowup from commitment length and base rows
                let base_pow2 = proof.n_rows.next_power_of_two();
                if commit.oracle.len % base_pow2 != 0 { return false; }
                let ratio = commit.oracle.len / base_pow2;
                if !ratio.is_power_of_two() { return false; }
                let blowup_log2 = ratio.trailing_zeros() as usize;
                let ext_idx = expected_idx << blowup_log2;
                if q.oracle_proof.idx != ext_idx { return false; }
                if !FriVerifier::verify_opening(commit, &q.oracle_proof) { return false; }
            }

            // Verify folding round inclusions (multi-round) with folding consistency checks
            if let (Some(ref rounds), Some(ref rq)) = (&proof.fri_rounds, &proof.fri_round_queries) {
                let num_rounds = rounds.rounds.len();
                if rq[k].rounds.len() != num_rounds { return false; }
                for r_i in 0..num_rounds {
                    // derive per-round alpha to match prover's sequence
                    let alpha_bytes = tr.challenge_bytes(8);
                    let alpha = Fp::new(u64::from_le_bytes(alpha_bytes.try_into().unwrap()));
                    let r = &rounds.rounds[r_i];
                    let q = &rq[k].rounds[r_i];
                    // Verify Merkle inclusion for this round
                    if !numiproof_fri::FriVerifier::verify_pair(&r.root, r.len, &q.pair) { return false; }
                    // Verify folding consistency between consecutive rounds
                    let next_pair = if r_i + 1 < num_rounds {
                        Some(&rq[k].rounds[r_i + 1].pair)
                    } else {
                        None
                    };
                    if !numiproof_fri::FriVerifier::verify_folding_chain(alpha, &q.pair, next_pair) {
                        return false;
                    }
                }
                // Final round should be smaller than initial (folding is working) when there are multiple rounds
                if num_rounds > 1 {
                    if let Some((first_round, last_round)) = rounds.rounds.first().zip(rounds.rounds.last()) {
                        if last_round.len >= first_round.len { return false; }
                    }
                }
            }
        }

        // Digest check
        let expect_digest = h_many(DOM_PROOF_DIGEST, &[&proof.merkle_root, &proof.pub_input_enc, &(proof.queries as u64).to_le_bytes()]);
        proof.proof_digest == expect_digest
    }
}

// -------------------- Gadgets and helpers for recursion/AIR use --------------------

/// Map a 384-bit digest (SHAKE256-384) to 6 field elements (little-endian 64-bit limbs).
pub fn digest_to_fps(digest: &[u8]) -> Option<[Fp; 6]> {
    if digest.len() != numiproof_hash::DIGEST_LEN { return None; }
    let mut limbs = [Fp::zero(); 6];
    for i in 0..6 {
        let start = i*8;
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&digest[start..start+8]);
        limbs[i] = Fp::new(u64::from_le_bytes(chunk));
    }
    Some(limbs)
}

/// Map 6 field elements back to a 48-byte digest by concatenating 8-byte little-endian words.
pub fn fps_to_digest(limbs: &[Fp; 6]) -> Vec<u8> {
    let mut out = Vec::with_capacity(numiproof_hash::DIGEST_LEN);
    for x in limbs.iter() { out.extend_from_slice(&x.to_u64().to_le_bytes()); }
    out
}

/// Re-export Merkle inclusion verification in a gadget-friendly signature.
pub fn merkle_verify_root(root: &[u8], idx: usize, leaf: &[u8], path: &[Vec<u8>]) -> bool {
    numiproof_merkle::MerkleTree::verify(root, idx, leaf, path)
}

/// Re-export FRI pair inclusion verification in a gadget-friendly signature.
pub fn fri_verify_pair(root: &[u8], len: usize, pair: &numiproof_fri::PairOpening) -> bool {
    numiproof_fri::FriVerifier::verify_pair(root, len, pair)
}

/// Compute accumulator digest used for recursion pipeline.
pub fn accumulator_digest(prev: Option<&[u8]>, cur: &[u8]) -> Vec<u8> { accumulate(prev, cur) }

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
        Some(p) => h_many(DOM_ACCUMULATOR, &[p, cur]).to_vec(),
        None => h_many(DOM_ACCUMULATOR, &[cur]).to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fib_prove_verify() {
        let air = FibonacciAir::new(1,1,64);
        let prover = Prover { cfg: FriConfig { blowup_log2: 2, num_rounds: 1, queries: 32 } };
        let proof = prover.prove_fib(&air);
        assert!(Verifier::verify_fib(&proof));
    }

    #[test]
    fn verify_rejects_tampered_row() {
        let air = FibonacciAir::new(1,1,32);
        let prover = Prover { cfg: FriConfig { blowup_log2: 2, num_rounds: 1, queries: 16 } };
        let mut proof = prover.prove_fib(&air);
        // Tamper a byte in first opening row; proof should fail
        if let Some(first) = proof.openings.get_mut(0) {
            if !first.row.is_empty() { first.row[0] ^= 1; }
        }
        assert!(!Verifier::verify_fib(&proof));
    }

    #[test]
    fn verify_rejects_wrong_query_index() {
        let air = FibonacciAir::new(1,1,32);
        let prover = Prover { cfg: FriConfig { blowup_log2: 2, num_rounds: 1, queries: 16 } };
        let mut proof = prover.prove_fib(&air);
        // Force an incorrect index for first opening
        if let Some(first) = proof.openings.get_mut(0) { first.idx = (first.idx + 1) % proof.n_rows; }
        assert!(!Verifier::verify_fib(&proof));
    }

    #[test]
    fn verify_rejects_bad_next_row_path() {
        let air = FibonacciAir::new(1,1,32);
        let prover = Prover { cfg: FriConfig { blowup_log2: 2, num_rounds: 1, queries: 16 } };
        let mut proof = prover.prove_fib(&air);
        // Tamper next_row path on an opening that has a next_row
        let k = proof.openings.iter().position(|o| o.next_row.is_some()).unwrap();
        if let Some(path_next) = &mut proof.openings[k].path_next { if let Some(first) = path_next.first_mut() { if !first.is_empty() { first[0] ^= 1; } } }
        assert!(!Verifier::verify_fib(&proof));
    }

    #[test]
    fn verify_rejects_pub_input_mismatch() {
        let air = FibonacciAir::new(2,3,16);
        let prover = Prover { cfg: FriConfig { blowup_log2: 2, num_rounds: 1, queries: 8 } };
        let mut proof = prover.prove_fib(&air);
        // Flip a byte in public input encoding
        if !proof.pub_input_enc.is_empty() { proof.pub_input_enc[0] ^= 1; }
        assert!(!Verifier::verify_fib(&proof));
    }
}