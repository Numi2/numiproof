// Additional AIR examples for production use
use serde::{Serialize, Deserialize};
use crate::Air;
use numiproof_field::Fp;

/// Range check AIR: proves that values are in range [0, 2^bits - 1]
/// Uses decomposition into bit columns
#[derive(Clone, Serialize, Deserialize)]
pub struct RangeCheckPublic {
    pub value: u64,
    pub bits: u32,
}

#[derive(Clone)]
pub struct RangeCheckAir {
    pub value: Fp,
    pub bits: usize,
}

impl RangeCheckAir {
    pub fn new(value: u64, bits: usize) -> Self {
        assert!(bits <= 64);
        assert!(value < (1u64 << bits));
        Self { value: Fp::new(value), bits }
    }
}

impl Air for RangeCheckAir {
    type PublicInput = RangeCheckPublic;
    
    fn id(&self) -> &'static str { "range_check_v1" }
    
    fn trace_len(&self) -> usize { self.bits + 1 }
    
    fn n_cols(&self) -> usize { 3 } // [accumulator, bit, power_of_2]
    
    fn public_input(&self) -> Self::PublicInput {
        RangeCheckPublic {
            value: self.value.to_u64(),
            bits: self.bits as u32,
        }
    }
    
    fn gen_trace(&self) -> Vec<Vec<Fp>> {
        let n = self.trace_len();
        let mut acc = vec![Fp::zero(); n];
        let mut bit = vec![Fp::zero(); n];
        let mut pow2 = vec![Fp::zero(); n];
        
        // Initial accumulator is the value
        acc[0] = self.value;
        
        // Decompose into bits
        let mut remaining = self.value.to_u64();
        let mut power = 1u64;
        
        for i in 0..self.bits {
            let b = remaining & 1;
            bit[i] = Fp::new(b);
            pow2[i] = Fp::new(power);
            
            // Next accumulator: subtract current bit contribution
            if i + 1 < n {
                acc[i + 1] = Fp::new(remaining >> 1);
            }
            
            remaining >>= 1;
            power <<= 1;
        }
        
        // Last row should have accumulator = 0
        acc[self.bits] = Fp::zero();
        
        vec![acc, bit, pow2]
    }
    
    fn check_row(i: usize, row: &[Fp], next: Option<&[Fp]>, pub_inp: &Self::PublicInput) -> bool {
        if i == 0 {
            // First row: accumulator equals value
            if row[0].to_u64() != pub_inp.value {
                return false;
            }
        }
        
        // Check bit is boolean (0 or 1)
        let b = row[1];
        if b != Fp::zero() && b != Fp::one() {
            return false;
        }
        
        if let Some(nxt) = next {
            // Transition: next_acc = (acc - bit) / 2
            let expected_next = (row[0] - row[1]) * Fp::new(2).inv();
            if nxt[0] != expected_next {
                return false;
            }
            
            // Power of 2 doubles each step
            if nxt[2] != row[2] * Fp::new(2) {
                return false;
            }
        } else {
            // Last row: accumulator should be zero
            if row[0] != Fp::zero() {
                return false;
            }
        }
        
        true
    }
    
    fn eval_constraints(&self, i: usize, row: &[Fp], next: Option<&[Fp]>, pub_inp: &Self::PublicInput) -> Vec<Fp> {
        let mut constraints = vec![Fp::zero(); 3];
        
        if i == 0 {
            // Boundary: first accumulator equals value
            constraints[0] = row[0] - Fp::new(pub_inp.value);
        }
        
        // Boolean constraint: bit * (bit - 1) = 0
        let b = row[1];
        constraints[1] = b * (b - Fp::one());
        
        if let Some(nxt) = next {
            // Transition constraint
            constraints[0] = nxt[0] - (row[0] - row[1]) * Fp::new(2).inv();
            constraints[2] = nxt[2] - row[2] * Fp::new(2);
        } else {
            // Boundary: last accumulator is zero
            constraints[0] = row[0];
        }
        
        constraints
    }
}

/// Permutation check AIR: proves that output is a permutation of input
/// Uses running product method (Plonk-style)
#[derive(Clone, Serialize, Deserialize)]
pub struct PermutationPublic {
    pub input_hash: Vec<u8>,
    pub output_hash: Vec<u8>,
    pub length: u32,
}

#[derive(Clone)]
pub struct PermutationAir {
    pub input: Vec<u64>,
    pub output: Vec<u64>,
}

impl PermutationAir {
    pub fn new(input: Vec<u64>, output: Vec<u64>) -> Self {
        assert_eq!(input.len(), output.len());
        Self { input, output }
    }
}

impl Air for PermutationAir {
    type PublicInput = PermutationPublic;
    
    fn id(&self) -> &'static str { "permutation_v1" }
    
    fn trace_len(&self) -> usize { self.input.len() + 1 }
    
    fn n_cols(&self) -> usize { 4 } // [input_val, output_val, product_in, product_out]
    
    fn public_input(&self) -> Self::PublicInput {
        use numiproof_hash::shake256_384;
        
        let input_bytes: Vec<u8> = self.input.iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        let output_bytes: Vec<u8> = self.output.iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        
        PermutationPublic {
            input_hash: shake256_384(&input_bytes).to_vec(),
            output_hash: shake256_384(&output_bytes).to_vec(),
            length: self.input.len() as u32,
        }
    }
    
    fn gen_trace(&self) -> Vec<Vec<Fp>> {
        let n = self.trace_len();
        let mut input_col = vec![Fp::zero(); n];
        let mut output_col = vec![Fp::zero(); n];
        let mut prod_in = vec![Fp::one(); n];
        let mut prod_out = vec![Fp::one(); n];
        
        // Fill values
        for i in 0..self.input.len() {
            input_col[i] = Fp::new(self.input[i]);
            output_col[i] = Fp::new(self.output[i]);
        }
        
        // Compute running products with random challenge (beta)
        // In practice, beta would come from Fiat-Shamir
        let beta = Fp::new(7); // Simplified: fixed challenge
        
        for i in 0..self.input.len() {
            let in_contribution = input_col[i] + beta;
            let out_contribution = output_col[i] + beta;
            
            if i + 1 < n {
                prod_in[i + 1] = prod_in[i] * in_contribution;
                prod_out[i + 1] = prod_out[i] * out_contribution;
            }
        }
        
        vec![input_col, output_col, prod_in, prod_out]
    }
    
    fn check_row(i: usize, row: &[Fp], next: Option<&[Fp]>, _pub_inp: &Self::PublicInput) -> bool {
        if i == 0 {
            // First row: products start at 1
            if row[2] != Fp::one() || row[3] != Fp::one() {
                return false;
            }
        }
        
        if let Some(nxt) = next {
            let beta = Fp::new(7);
            
            // Running product updates
            let expected_prod_in = row[2] * (row[0] + beta);
            let expected_prod_out = row[3] * (row[1] + beta);
            
            if nxt[2] != expected_prod_in || nxt[3] != expected_prod_out {
                return false;
            }
        } else {
            // Last row: products should be equal (permutation check)
            if row[2] != row[3] {
                return false;
            }
        }
        
        true
    }
    
    fn eval_constraints(&self, i: usize, row: &[Fp], next: Option<&[Fp]>, _pub_inp: &Self::PublicInput) -> Vec<Fp> {
        let mut constraints = vec![Fp::zero(); 4];
        
        if i == 0 {
            // Boundary: initial products are 1
            constraints[2] = row[2] - Fp::one();
            constraints[3] = row[3] - Fp::one();
        }
        
        if let Some(nxt) = next {
            let beta = Fp::new(7);
            
            // Running product constraints
            constraints[2] = nxt[2] - row[2] * (row[0] + beta);
            constraints[3] = nxt[3] - row[3] * (row[1] + beta);
        } else {
            // Boundary: final products equal
            constraints[2] = row[2] - row[3];
        }
        
        constraints
    }
}

/// Hash chain AIR: proves correct computation of iterated hash
#[derive(Clone, Serialize, Deserialize)]
pub struct HashChainPublic {
    pub initial: Vec<u8>,
    pub final_hash: Vec<u8>,
    pub iterations: u32,
}

#[derive(Clone)]
pub struct HashChainAir {
    pub initial: Vec<u8>,
    pub iterations: usize,
}

impl HashChainAir {
    pub fn new(initial: Vec<u8>, iterations: usize) -> Self {
        Self { initial, iterations }
    }
    
    fn hash_limbs(limbs: &[Fp; 6]) -> [Fp; 6] {
        use numiproof_hash::shake256_384;
        
        // Convert limbs to bytes
        let mut bytes = Vec::with_capacity(48);
        for limb in limbs.iter() {
            bytes.extend_from_slice(&limb.to_u64().to_le_bytes());
        }
        
        // Hash
        let hash = shake256_384(&bytes);
        
        // Convert back to limbs
        let mut result = [Fp::zero(); 6];
        for i in 0..6 {
            let start = i * 8;
            let mut chunk = [0u8; 8];
            chunk.copy_from_slice(&hash[start..start + 8]);
            result[i] = Fp::new(u64::from_le_bytes(chunk));
        }
        result
    }
}

impl Air for HashChainAir {
    type PublicInput = HashChainPublic;
    
    fn id(&self) -> &'static str { "hash_chain_v1" }
    
    fn trace_len(&self) -> usize { self.iterations + 1 }
    
    fn n_cols(&self) -> usize { 6 } // 6 limbs for 384-bit hash
    
    fn public_input(&self) -> Self::PublicInput {
        use numiproof_hash::shake256_384;
        
        // Compute final hash by iterating
        let mut current = self.initial.clone();
        for _ in 0..self.iterations {
            current = shake256_384(&current).to_vec();
        }
        
        HashChainPublic {
            initial: self.initial.clone(),
            final_hash: current,
            iterations: self.iterations as u32,
        }
    }
    
    fn gen_trace(&self) -> Vec<Vec<Fp>> {
        use numiproof_hash::shake256_384;
        
        let n = self.trace_len();
        let mut cols = vec![vec![Fp::zero(); n]; 6];
        
        // Initial state
        let mut current = self.initial.clone();
        while current.len() < 48 {
            current.push(0);
        }
        
        for step in 0..=self.iterations {
            // Decompose current hash into limbs
            for i in 0..6 {
                let start = i * 8;
                let mut chunk = [0u8; 8];
                if start + 8 <= current.len() {
                    chunk.copy_from_slice(&current[start..start + 8]);
                }
                cols[i][step] = Fp::new(u64::from_le_bytes(chunk));
            }
            
            // Compute next hash for next iteration
            if step < self.iterations {
                current = shake256_384(&current).to_vec();
            }
        }
        
        cols
    }
    
    fn check_row(i: usize, row: &[Fp], next: Option<&[Fp]>, pub_inp: &Self::PublicInput) -> bool {
        if i == 0 {
            // First row: verify initial state
            for j in 0..6 {
                let start = j * 8;
                if start + 8 <= pub_inp.initial.len() {
                    let mut chunk = [0u8; 8];
                    chunk.copy_from_slice(&pub_inp.initial[start..start + 8]);
                    let expected = Fp::new(u64::from_le_bytes(chunk));
                    if row[j] != expected {
                        return false;
                    }
                }
            }
        }
        
        if let Some(nxt) = next {
            // Verify hash transition
            let current_limbs: [Fp; 6] = [row[0], row[1], row[2], row[3], row[4], row[5]];
            let expected_next = Self::hash_limbs(&current_limbs);
            
            for j in 0..6 {
                if nxt[j] != expected_next[j] {
                    return false;
                }
            }
        } else {
            // Last row: verify final hash
            for j in 0..6 {
                let start = j * 8;
                if start + 8 <= pub_inp.final_hash.len() {
                    let mut chunk = [0u8; 8];
                    chunk.copy_from_slice(&pub_inp.final_hash[start..start + 8]);
                    let expected = Fp::new(u64::from_le_bytes(chunk));
                    if row[j] != expected {
                        return false;
                    }
                }
            }
        }
        
        true
    }
    
    fn eval_constraints(&self, i: usize, row: &[Fp], next: Option<&[Fp]>, pub_inp: &Self::PublicInput) -> Vec<Fp> {
        let mut constraints = vec![Fp::zero(); 6];
        
        if i == 0 {
            // Boundary: initial state
            for j in 0..6 {
                let start = j * 8;
                if start + 8 <= pub_inp.initial.len() {
                    let mut chunk = [0u8; 8];
                    chunk.copy_from_slice(&pub_inp.initial[start..start + 8]);
                    let expected = Fp::new(u64::from_le_bytes(chunk));
                    constraints[j] = row[j] - expected;
                }
            }
        }
        
        if let Some(nxt) = next {
            // Transition constraints: next = hash(current)
            let current_limbs: [Fp; 6] = [row[0], row[1], row[2], row[3], row[4], row[5]];
            let expected_next = Self::hash_limbs(&current_limbs);
            
            for j in 0..6 {
                constraints[j] = nxt[j] - expected_next[j];
            }
        } else {
            // Boundary: final hash
            for j in 0..6 {
                let start = j * 8;
                if start + 8 <= pub_inp.final_hash.len() {
                    let mut chunk = [0u8; 8];
                    chunk.copy_from_slice(&pub_inp.final_hash[start..start + 8]);
                    let expected = Fp::new(u64::from_le_bytes(chunk));
                    constraints[j] = row[j] - expected;
                }
            }
        }
        
        constraints
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn range_check_trace_consistency() {
        let air = RangeCheckAir::new(42, 8);
        let pub_inp = air.public_input();
        let trace = air.gen_trace();
        
        assert_eq!(trace.len(), 3);
        assert_eq!(trace[0].len(), 9);
        
        // Verify first row has the value
        assert_eq!(trace[0][0].to_u64(), 42);
        // Verify last row has accumulator = 0
        assert_eq!(trace[0][8], Fp::zero());
        
        // Check bits are boolean
        for i in 0..8 {
            let bit = trace[1][i];
            assert!(bit == Fp::zero() || bit == Fp::one());
        }
    }
    
    #[test]
    fn permutation_check_valid() {
        let input = vec![1, 2, 3, 4, 5];
        let output = vec![5, 3, 1, 4, 2]; // Valid permutation
        let air = PermutationAir::new(input, output);
        let _pub_inp = air.public_input();
        let trace = air.gen_trace();
        
        // Last row should have equal products
        let last = trace[0].len() - 1;
        assert_eq!(trace[2][last], trace[3][last]);
    }
    
    #[test]
    fn hash_chain_consistency() {
        let initial = vec![1, 2, 3, 4];
        let air = HashChainAir::new(initial.clone(), 3);
        let pub_inp = air.public_input();
        let trace = air.gen_trace();
        
        // Verify trace has correct length
        assert_eq!(trace.len(), 6);
        assert_eq!(trace[0].len(), 4); // iterations + 1
        
        // Verify first row matches initial (padded to 48 bytes)
        let mut initial_padded = initial.clone();
        while initial_padded.len() < 48 {
            initial_padded.push(0);
        }
        
        for i in 0..6 {
            let start = i * 8;
            let mut chunk = [0u8; 8];
            chunk.copy_from_slice(&initial_padded[start..start + 8]);
            let expected = Fp::new(u64::from_le_bytes(chunk));
            assert_eq!(trace[i][0], expected, "First row limb {} mismatch", i);
        }
    }
}

