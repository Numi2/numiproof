// File: numiproof-air/src/lib.rs
use serde::{Serialize, Deserialize};
use numiproof_field::Fp;

pub mod examples;

pub trait Air {
    type PublicInput: Serialize + for<'de> Deserialize<'de> + Clone;
    fn id(&self) -> &'static str;
    fn trace_len(&self) -> usize;
    fn n_cols(&self) -> usize;
    fn public_input(&self) -> Self::PublicInput;
    fn gen_trace(&self) -> Vec<Vec<Fp>>; // column-major over field elements
    fn check_row(i: usize, row: &[Fp], next: Option<&[Fp]>, pub_inp: &Self::PublicInput) -> bool;
    /// Evaluate constraint polynomials for a given row (and optional next row).
    /// Implementations should return zero when constraints are satisfied.
    fn eval_constraints(&self, i: usize, row: &[Fp], next: Option<&[Fp]>, pub_inp: &Self::PublicInput) -> Vec<Fp>;
}

/// Simple Fibonacci AIR over the Goldilocks field with wrapping arithmetic.
/// Columns are [a_i, a_{i+1}]. The last-row boundary fixes a_i to the expected-first value.
#[derive(Clone, Serialize, Deserialize)]
pub struct FibPublic {
    pub steps: u32,
    pub a0: u64,
    pub a1: u64,
    pub expected_first: u64, // a_steps in field, encoded as u64
}
#[derive(Clone)]
pub struct FibonacciAir {
    pub a0: Fp,
    pub a1: Fp,
    pub steps: usize,
}
impl FibonacciAir {
    pub fn new(a0: u64, a1: u64, steps: usize) -> Self { Self { a0: Fp::new(a0), a1: Fp::new(a1), steps } }
    fn expected_first(a0: Fp, a1: Fp, steps: usize) -> Fp {
        let mut x=a0; let mut y=a1;
        for _ in 0..steps { let z = x + y; x=y; y=z; }
        x
    }
}
impl Air for FibonacciAir {
    type PublicInput = FibPublic;
    fn id(&self) -> &'static str { "fibonacci_v1" }
    fn trace_len(&self) -> usize { self.steps+1 }
    fn n_cols(&self) -> usize { 2 }
    fn public_input(&self) -> Self::PublicInput {
        FibPublic {
            steps: self.steps as u32,
            a0: self.a0.to_u64(),
            a1: self.a1.to_u64(),
            expected_first: Self::expected_first(self.a0, self.a1, self.steps).to_u64(),
        }
    }
    fn gen_trace(&self) -> Vec<Vec<Fp>> {
        let n = self.trace_len();
        let mut c0 = vec![Fp::zero(); n];
        let mut c1 = vec![Fp::zero(); n];
        c0[0] = self.a0; c1[0] = self.a1;
        for i in 0..n-1 {
            c0[i+1] = c1[i];
            c1[i+1] = c0[i] + c1[i];
        }
        vec![c0, c1]
    }
    fn check_row(i: usize, row: &[Fp], next: Option<&[Fp]>, pub_inp: &Self::PublicInput) -> bool {
        if i==0 && (row[0].to_u64()!=pub_inp.a0 || row[1].to_u64()!=pub_inp.a1) { return false; }
        if let Some(nxt) = next {
            if nxt[0] != row[1] { return false; }
            if nxt[1] != row[0] + row[1] { return false; }
        } else {
            // Last row boundary: a_i equals expected_first
            if row[0].to_u64() != pub_inp.expected_first { return false; }
        }
        true
    }
    fn eval_constraints(&self, _i: usize, row: &[Fp], next: Option<&[Fp]>, pub_inp: &Self::PublicInput) -> Vec<Fp> {
        if let Some(nxt) = next {
            // Transition constraints
            let c0 = nxt[0] - row[1];
            let c1 = nxt[1] - (row[0] + row[1]);
            vec![c0, c1]
        } else {
            // Last-row boundary constraint
            let c_end = row[0] - Fp::new(pub_inp.expected_first);
            // Provide two entries to match column count for simple composers
            vec![c_end, Fp::zero()]
        }
    }
}

pub fn row_to_bytes(row: &[Fp]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8*row.len());
    for &x in row { v.extend_from_slice(&x.to_u64().to_le_bytes()); }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fib_trace_and_public_input_consistency() {
        let air = FibonacciAir::new(2, 3, 16);
        let pub_inp = air.public_input();
        assert_eq!(pub_inp.steps as usize, air.steps);
        assert_eq!(pub_inp.a0, air.a0.to_u64());
        assert_eq!(pub_inp.a1, air.a1.to_u64());
        let trace = air.gen_trace();
        assert_eq!(trace.len(), 2);
        assert_eq!(trace[0].len(), air.trace_len());
        assert_eq!(trace[1].len(), air.trace_len());
        // First row equals inputs
        assert_eq!(trace[0][0].to_u64(), pub_inp.a0);
        assert_eq!(trace[1][0].to_u64(), pub_inp.a1);
        // Check last row boundary via check_row
        let last_i = air.trace_len()-1;
        let last_row = [trace[0][last_i], trace[1][last_i]];
        assert!(FibonacciAir::check_row(last_i, &last_row, None, &pub_inp));
    }

    #[test]
    fn check_row_enforces_transition() {
        let air = FibonacciAir::new(1, 1, 8);
        let pub_inp = air.public_input();
        let trace = air.gen_trace();
        for i in 0..air.trace_len()-1 {
            let row = [trace[0][i], trace[1][i]];
            let nxt = [trace[0][i+1], trace[1][i+1]];
            assert!(FibonacciAir::check_row(i, &row, Some(&nxt), &pub_inp));
        }
        // Tamper next row to break constraint
        let i = 2;
        let row = [trace[0][i], trace[1][i]];
        let mut bad_next = [trace[0][i+1], trace[1][i+1]];
        bad_next[1] = bad_next[1] + Fp::one();
        assert!(!FibonacciAir::check_row(i, &row, Some(&bad_next), &pub_inp));
    }
}