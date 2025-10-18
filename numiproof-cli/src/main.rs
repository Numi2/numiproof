// File: numiproof-cli/src/main.rs
use clap::{Parser, Subcommand};
use numiproof_air::{FibonacciAir};
use numiproof_proof::{Prover, Verifier, accumulate, FriConfig};
use numiproof_recursion::RecursiveAir;
use numiproof_privacy as privacy;
use numiproof_spec as spec;
use std::{fs, path::PathBuf};

#[derive(Parser)]
#[command(name="numiproof", version, about="Minimal PQ-friendly proof demo")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd
}
#[derive(Subcommand)]
enum Cmd {
    /// Prove Fibonacci transition
    ProveFib {
        #[arg(long, default_value_t=1)]
        a0: u64,
        #[arg(long, default_value_t=1)]
        a1: u64,
        #[arg(long, default_value_t=64)]
        steps: usize,
        #[arg(long, default_value = "proof.bin")]
        out: PathBuf,
        #[arg(long, default_value_t=32)]
        queries: usize,
        /// LDE blowup factor as log2 (e.g., 2 => x4)
        #[arg(long, default_value_t=2)]
        blowup_log2: u32,
        /// Number of FRI folding rounds
        #[arg(long, default_value_t=1)]
        fri_rounds: u32,
        /// Optional params file (toml) to override FRI settings
        #[arg(long)]
        params: Option<PathBuf>,
    },
    /// Verify a Fibonacci proof
    VerifyFib {
        #[arg(long, default_value = "proof.bin")]
        proof: PathBuf,
    },
    /// Accumulate proof digest into an aggregator
    Accumulate {
        #[arg(long)]
        current_proof: PathBuf,
        /// Optional previous digest hex
        #[arg(long)]
        prev_hex: Option<String>,
    },
    /// Aggregate a proof into a recursive AIR instance and output new digest (demo scaffold)
    Aggregate {
        #[arg(long)]
        current_proof: PathBuf,
        #[arg(long)]
        steps: usize,
        /// Optional previous digest hex
        #[arg(long)]
        prev_hex: Option<String>,
    },
    /// Generate a KEM keypair (placeholder PQ KEM)
    KemKeygen {},
    /// Make a note and print its commitment
    MakeNote {
        #[arg(long)]
        value: u64,
        #[arg(long)]
        recipient_pk_hex: String,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::ProveFib { a0, a1, steps, out, queries, blowup_log2, fri_rounds, params } => {
            let air = FibonacciAir::new(a0, a1, steps);
            let cfg = if let Some(p) = params {
                let txt = fs::read_to_string(p).expect("read params");
                let p = spec::load_params_toml(&txt).expect("parse params");
                FriConfig {
                    blowup_log2: p.blowup_log2.unwrap_or(blowup_log2),
                    num_rounds: p.fri_rounds.unwrap_or(fri_rounds),
                    queries: p.queries.unwrap_or(queries),
                }
            } else {
                FriConfig { blowup_log2, num_rounds: fri_rounds, queries }
            };
            let prover = Prover { cfg };
            let proof = prover.prove_fib(&air);
            // Streamed bincode writing
            let mut f = fs::File::create(&out).expect("create");
            bincode::serialize_into(&mut f, &proof).expect("encode");
            println!("wrote {}", out.display());
            if let Some(ref fri) = proof.fri_commitment { println!("fri_root={} len={}", hex::encode(&fri.oracle.root), fri.oracle.len); }
            if let Some(ref rounds) = proof.fri_rounds { for (i, r) in rounds.rounds.iter().enumerate() { println!("fri_round[{}]_root={} len={}", i, hex::encode(&r.root), r.len); } }
        }
        Cmd::VerifyFib { proof } => {
            let f = fs::File::open(&proof).expect("open");
            let proof: numiproof_proof::Proof = bincode::deserialize_from(f).expect("decode");
            let ok = Verifier::verify_fib(&proof);
            println!("{}", if ok { "valid" } else { "invalid" });
        }
        Cmd::Accumulate { current_proof, prev_hex } => {
            let f = fs::File::open(&current_proof).expect("open");
            let proof: numiproof_proof::Proof = bincode::deserialize_from(f).expect("decode");
            let cur = proof.proof_digest;
            let prev_bytes = prev_hex
                .as_ref()
                .and_then(|h| hex::decode(h).ok());
            let prev = prev_bytes.as_deref();
            let agg = accumulate(prev, &cur);
            println!("{}", hex::encode(agg));
        }
        Cmd::Aggregate { current_proof, steps, prev_hex } => {
            let f = fs::File::open(&current_proof).expect("open");
            let proof: numiproof_proof::Proof = bincode::deserialize_from(f).expect("decode");
            let prev_bytes = prev_hex
                .as_ref()
                .and_then(|h| hex::decode(h).ok());
            let prev = prev_bytes.as_deref();
            let air = RecursiveAir::new(prev, &proof.proof_digest, steps);
            let pub_inp = air.public_input();
            println!("new_digest={}", hex::encode(&pub_inp.cur_digest));
        }
        Cmd::KemKeygen {} => {
            let kp = privacy::kem_keygen();
            println!("sk={}\npk={}", hex::encode(kp.sk), hex::encode(kp.pk));
        }
        Cmd::MakeNote { value, recipient_pk_hex } => {
            let pk_bytes = hex::decode(recipient_pk_hex).expect("pk hex");
            assert_eq!(pk_bytes.len(), 32, "recipient_pk must be 32 bytes");
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&pk_bytes);
            let note = privacy::make_note(value, pk);
            let cm = privacy::note_commitment(&note);
            println!("cm={}", hex::encode(cm));
        }
    }
}