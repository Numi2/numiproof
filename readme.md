
# numiproof (prototype)

“numiproof”: a post‑quantum, recursive, succinct ZK system for rollups and private chains that leaks nothing about who transacts.

Design goals
	•	PQ security at ≥128‑bit against collision and preimage quantum attacks.
	•	Fast recursion for proof aggregation across many blocks.
	•	Zero‑knowledge by default.
	•	No trusted setup.
	•	Rollup‑ready verifier and DA model.
	•	No sender/receiver leakage on L1.

Current status
	•	Prime field (Goldilocks) replaces u64; AIR runs over field elements.
	•	FFT-based LDE implemented; FRI-style Merkle oracle commitments with masking integrated.
	•	Zero-knowledge masks z_base(X)·r(X) applied to witness oracles.
	•	Demo FRI folding round with transcript-derived challenge and pair openings.
	•	Hash-chain accumulator remains for recursion; verifier-inside-AIR planned.

Edge details
	•	Padding duplicates the last leaf to reach a power of two.
	•	Last-row boundary condition enforces the claimed number of steps.
	•	All serialization uses bincode. Public input is bound into transcript and digest.

How to extend to a real system
	•	Generalize to multi-column LDE and DEEP-FRI with multiple rounds and composition polynomial.
	•	Replace row Merkle with commitments to composition/evaluation oracles and verify low-degree proximity.
	•	Implement true recursion: embed the STARK verifier inside an AIR and aggregate proofs.

Security basis
	•	Hash‑only assumptions (random‑oracle model). zk‑STARKs are transparent and widely regarded as PQ‑resistant since they avoid algebraic groups broken by Shor.  ￼
	•	Polynomial commitments via FRI/DEEP‑FRI for proximity testing and improved soundness.  ￼
	•	Quantum collision search costs ≈2^(n/3) queries (BHT). Set Merkle/PC digest ≥384 bits to retain ~128‑bit PQ collision security.  ￼

Core construction
	•	Arithmetization: AIR over a 64‑bit‑friendly prime field (e.g., the “Goldilocks” family) for FFT‑based LDE and simple constraints.
	•	PC scheme: DEEP‑FRI with Merkle commitments to evaluation oracles; verifier queries are hash‑authenticated.  ￼
	•	ZK: add low‑degree random masks to witness polynomials before commitment; implement blinding in AIR composition step (standard ZK‑STARK technique).  ￼
	•	Fiat–Shamir: non‑interactive via QROM instantiation (SHAKE256 XOF) with domain‑separated transcripts.  ￼
	•	Hashes/Merkle: SHAKE256 with 384‑bit outputs for commitments, Merkle trees, and query authentication to offset BHT; sponge‑friendly hash inside circuits for efficiency.

Recursion (aggregation)
	•	IVC with STARK‑verifier‑inside‑STARK: define an AIR that verifies a numiproof instance (FRI checks, Merkle paths, algebraic checks). Each block proves its state transition and includes the previous proof’s digest; the recursive circuit verifies that digest and emits a new digest. This yields succinct accumulation across blocks.
	•	Practice shows FRI‑based recursion is fast; the approach follows the Plonky2 line (FRI for recursion) and similar STARK‑VM designs.  ￼
	•	Batching: amortize FRI rounds across k blocks by multi‑opening and shared queries.
	•	Output: a single STARK proof for N blocks; size grows polylog(N).

Privacy: no leakage of “who”
	•	Notes and nullifiers: adopt a Sapling/Orchard‑style note‑commitment Merkle tree and per‑note nullifier set so spends are unlinkable to notes yet unspendable twice. Publish only {root, nullifiers, new note commitments, encrypted payloads}.  ￼
	•	Recipient privacy: include recipient ciphertexts under a PQ KEM (e.g., ML‑KEM/Kyber) in calldata; recipients scan, decrypt, and reconstruct notes off‑chain. Sender and receiver identifiers never appear on‑chain.
	•	Amount privacy: enforce value conservation inside the proof. No homomorphic commitments are required; amounts remain private within AIR constraints.

Data availability
	•	DA payload per batch: previous root, new root, list of nullifiers, list of note commitments, per‑output ciphertexts, and the recursive proof. Light clients can rebuild the tree from posted commitments; no identities are revealed.  ￼

Parameters (PQ‑128 target)
	•	Hash/Merkle digest: 384 bits (SHAKE256‑384). BHT ⇒ ~2^(128) collision cost.
	•	Soundness: ≤2^-128 after DEEP‑FRI composition; tune query count and code rate accordingly.  ￼
	•	Field: 64‑bit‑friendly prime with large smooth multiplicative subgroup for radix‑2 FFTs.
	•	Transcripts: domain separation for roles (commit/query/challenge) and recursion levels.

Rollup integration
	•	State model: UTXO‑like shielded pool with note tree and nullifier set; optional public bridge for deposits/withdrawals.
	•	Sequencer: accepts encrypted transactions, runs prover, posts DA + numiproof to L1.
	•	L1 verifier: pure‑hash STARK verifier contract. No ECC. Gas is higher than pairing SNARKs but PQ‑sound.  ￼

Rust implementation plan (crate layout, no code)
	•	numiproof-air: AIR DSL, constraint composer, trace builders.
	•	numiproof-fri: DEEP‑FRI prover/verifier, multi‑open.
	•	numiproof-merkle: SHAKE256‑384 Merkle trees, proof objects.
	•	numiproof-hash: transcript, domain separation, sponge primitives.
	•	numiproof-recursion: verifier‑as‑AIR gadgets, accumulator digest format, recursive prover.
	•	numiproof-privacy: note format, nullifier computation, tree ops, PQ‑KEM envelope.
	•	numiproof-prover: parallelized prover, GPU hooks for FFTs/merklization.
	•	numiproof-verifier: native verifier plus on‑chain bytecode generator.
	•	numiproof-cli: prove/verify, keygen for KEM, test vectors.
	•	numiproof-spec: parameter files and vectors.

APIs (sketch)
	•	Proving: create trace → mask → commit (FRI) → prove → package.
	•	Recursion: accumulate(prev_digest, proof_i) → new_digest, proof_{i+1}.
	•	Privacy: build_notes(inputs, outputs) → {nullifiers, commitments, ciphertexts}.

Performance notes
	•	Prover time ≈ O(n log n) with FFT/Merkle parallelism; recursion adds small constant factors.
	•	Proof size ≈ hundreds of KB baseline; recursion amortizes per‑tx overhead across many blocks. Plonky2 results indicate sub‑second recursion is feasible on commodity CPUs; similar targets apply here under FRI.  ￼

Auditable claims
	•	Transparency and PQ orientation from hash‑only STARKs.  ￼
	•	Improved soundness via DEEP‑FRI.  ￼
	•	PQ collision scaling drives the 384‑bit choice.  ￼
	•	Nullifier and note‑tree pattern prevents identity leakage.  ￼
	•	FRI‑based recursion practicality.  ￼

Risks and caveats
	•	QROM proofs for IOP‑to‑NIZK Fiat–Shamir are heuristic; document assumptions clearly.  ￼
	•	On‑chain gas for 384‑bit hashing is higher; consider precompiles or a rollup L1 with native SHA‑3 variants.
	•	Parameter tuning must be re‑benchmarked with real circuits, DA sizes, and recursion depth.




# Build
#   cargo build --release
# Test
#   cargo test -p numiproof-proof
# Demo
#   cargo run -p numiproof-cli -- prove-fib --a0 1 --a1 1 --steps 64 --queries 32 --out proof.bin
#   cargo run -p numiproof-cli -- verify-fib --proof proof.bin
#   cargo run -p numiproof-cli -- accumulate --current-proof proof.bin