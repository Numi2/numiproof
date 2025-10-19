use serde::{Serialize, Deserialize};
use numiproof_field::Fp;
use numiproof_air::Air;

#[derive(Clone, Serialize, Deserialize)]
pub struct ShieldedPublic {
    pub n_in: u32,
    pub n_out: u32,
    pub prev_root: Vec<u8>,
}

#[derive(Clone)]
pub struct ShieldedAir {
    pub in_values: Vec<u64>,
    pub out_values: Vec<u64>,
    pub prev_root: Vec<u8>,
}

impl ShieldedAir {
    pub fn new(in_values: Vec<u64>, out_values: Vec<u64>, prev_root: Vec<u8>) -> Self {
        Self { in_values, out_values, prev_root }
    }
}

impl Air for ShieldedAir {
    type PublicInput = ShieldedPublic;
    fn id(&self) -> &'static str { "shielded_v1" }
    fn trace_len(&self) -> usize { self.in_values.len() + self.out_values.len() + 1 }
    fn n_cols(&self) -> usize { 2 }
    fn public_input(&self) -> Self::PublicInput {
        ShieldedPublic { n_in: self.in_values.len() as u32, n_out: self.out_values.len() as u32, prev_root: self.prev_root.clone() }
    }
    fn gen_trace(&self) -> Vec<Vec<Fp>> {
        let n = self.trace_len();
        let n_in = self.in_values.len();
        let n_out = self.out_values.len();
        let mut c0 = vec![Fp::zero(); n];
        let mut c1 = vec![Fp::zero(); n];
        let sum_in: u128 = self.in_values.iter().map(|&v| v as u128).sum();
        let sum_out: u128 = self.out_values.iter().map(|&v| v as u128).sum();
        c0[0] = Fp::from_u128(sum_in.wrapping_sub(sum_out));
        // fill input rows
        for i in 0..n_in {
            c1[i] = Fp::new(self.in_values[i]);
            c0[i+1] = c0[i] - c1[i];
        }
        // fill output rows
        for j in 0..n_out {
            let i = n_in + j;
            c1[i] = Fp::new(self.out_values[j]);
            c0[i+1] = c0[i] + c1[i];
        }
        // last row already set; boundary should be zero
        vec![c0, c1]
    }
    fn check_row(i: usize, row: &[Fp], next: Option<&[Fp]>, pub_inp: &Self::PublicInput) -> bool {
        if let Some(nxt) = next {
            let n_in = pub_inp.n_in as usize;
            if i < n_in {
                // input row: next_acc = acc - val
                if nxt[0] != row[0] - row[1] { return false; }
            } else {
                // output row: next_acc = acc + val
                if nxt[0] != row[0] + row[1] { return false; }
            }
        } else {
            // last row boundary: accumulator is zero
            if row[0] != Fp::zero() { return false; }
        }
        true
    }
    fn eval_constraints(&self, i: usize, row: &[Fp], next: Option<&[Fp]>, pub_inp: &Self::PublicInput) -> Vec<Fp> {
        if let Some(nxt) = next {
            let n_in = pub_inp.n_in as usize;
            if i < n_in {
                vec![nxt[0] - (row[0] - row[1]), Fp::zero()]
            } else {
                vec![nxt[0] - (row[0] + row[1]), Fp::zero()]
            }
        } else {
            vec![row[0] - Fp::zero(), Fp::zero()]
        }
    }
}


