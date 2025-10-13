// File: numiproof-cli/src/main.rs
use clap::{Parser, Subcommand};
use numiproof_air::{FibonacciAir};
use numiproof_proof::{Prover, Verifier, accumulate};
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
    }
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::ProveFib { a0, a1, steps, out, queries } => {
            let air = FibonacciAir::new(a0, a1, steps);
            let prover = Prover { queries };
            let proof = prover.prove_fib(&air);
            let enc = bincode::serialize(&proof).expect("encode");
            fs::write(&out, enc).expect("write");
            println!("wrote {}", out.display());
        }
        Cmd::VerifyFib { proof } => {
            let bytes = fs::read(&proof).expect("read");
            let proof: numiproof_proof::Proof = bincode::deserialize(&bytes).expect("decode");
            let ok = Verifier::verify_fib(&proof);
            println!("{}", if ok { "valid" } else { "invalid" });
        }
        Cmd::Accumulate { current_proof, prev_hex } => {
            let bytes = fs::read(&current_proof).expect("read");
            let proof: numiproof_proof::Proof = bincode::deserialize(&bytes).expect("decode");
            let cur = proof.proof_digest;
            let prev_bytes = prev_hex
                .as_ref()
                .and_then(|h| hex::decode(h).ok());
            let prev = prev_bytes.as_deref();
            let agg = accumulate(prev, &cur);
            println!("{}", hex::encode(agg));
        }
    }
}