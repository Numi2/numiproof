use serde::{Serialize, Deserialize};
use numiproof_air::{Air};
use numiproof_field::Fp;
use numiproof_hash::h_many;

#[derive(Clone, Serialize, Deserialize)]
pub struct RecursivePublic {
    pub prev_digest: Vec<u8>,
    pub cur_digest: Vec<u8>,
}

#[derive(Clone)]
pub struct RecursiveAir {
    pub steps: usize,
    pub prev: Vec<u8>,
    pub cur: Vec<u8>,
}

impl RecursiveAir {
    pub fn new(prev: Option<&[u8]>, cur: &[u8], steps: usize) -> Self {
        let prev_vec = prev.map(|p| p.to_vec()).unwrap_or_else(|| vec![]);
        Self { steps, prev: prev_vec, cur: cur.to_vec() }
    }
}

impl Air for RecursiveAir {
    type PublicInput = RecursivePublic;
    fn id(&self) -> &'static str { "recursive_v1" }
    fn trace_len(&self) -> usize { self.steps }
    fn n_cols(&self) -> usize { 1 }
    fn public_input(&self) -> Self::PublicInput {
        let new_digest = if self.prev.is_empty() {
            h_many("accumulator", &[&self.cur]).to_vec()
        } else {
            h_many("accumulator", &[&self.prev, &self.cur]).to_vec()
        };
        RecursivePublic { prev_digest: self.prev.clone(), cur_digest: new_digest }
    }
    fn gen_trace(&self) -> Vec<Vec<Fp>> { vec![vec![Fp::zero(); self.steps]] }
    fn check_row(&self, _i: usize, _row: &[Fp], _next: Option<&[Fp]>, _pub_inp: &Self::PublicInput) -> bool { true }
    fn eval_constraints(&self, _i: usize, _row: &[Fp], _next: Option<&[Fp]>, _pub_inp: &Self::PublicInput) -> Vec<Fp> { vec![Fp::zero()] }
}


