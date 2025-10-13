use numiproof_field::{bit_reverse, root_of_unity, Fp};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Poly {
    /// Coefficients in little-endian order: a_0 + a_1 X + ...
    pub coeffs: Vec<Fp>,
}

impl Poly {
    pub fn new(coeffs: Vec<Fp>) -> Self { Self { coeffs } }
    pub fn degree(&self) -> usize { self.coeffs.len().saturating_sub(1) }
    pub fn eval(&self, x: Fp) -> Fp {
        let mut acc = Fp::zero();
        for &c in self.coeffs.iter().rev() { acc = acc * x + c; }
        acc
    }
}

/// In-place radix-2 decimation-in-time FFT over size n (power of two).
pub fn fft_in_place(a: &mut [Fp], root: Fp) {
    let n = a.len();
    assert!(n.is_power_of_two());
    // bit-reverse permutation
    let bits = n.trailing_zeros();
    for i in 0..n {
        let j = bit_reverse(i, bits);
        if j > i { a.swap(i, j); }
    }
    let mut m = 2usize;
    while m <= n {
        // w_m is primitive m-th root: w^(n/m)
        let w_m = root.pow((n / m) as u128);
        for k in (0..n).step_by(m) {
            let mut w_j = Fp::one();
            for j in 0..(m/2) {
                let t = w_j * a[k + j + m/2];
                let u = a[k + j];
                a[k + j] = u + t;
                a[k + j + m/2] = u - t;
                w_j *= w_m;
            }
        }
        m <<= 1;
    }
}

// Removed: unused helper `bits_for_len` to satisfy clippy dead_code

pub fn ifft_in_place(a: &mut [Fp], root: Fp) {
    // IFFT implemented as FFT with inverse root, then scale by n^{-1}
    let n = a.len();
    let inv_root = root.inv();
    fft_in_place(a, inv_root);
    let inv_n = Fp::new(n as u64).inv();
    for x in a.iter_mut() { *x *= inv_n; }
}

/// Evaluate polynomial on a coset g * <w>, where w is 2^k root and blowup is 2^r.
pub fn lde(coeffs: &[Fp], blowup_log2: u32) -> Vec<Fp> {
    let n = coeffs.len().next_power_of_two();
    let size = n << blowup_log2;
    let k = size.trailing_zeros();
    // Build evaluation vector by zero-padding to n and NTT to size with twiddle factors.
    let mut a = vec![Fp::zero(); size];
    if !coeffs.is_empty() {
        let count = coeffs.len();
        a[..count].copy_from_slice(&coeffs[..count]);
    }
    // Compute root for size
    let w = root_of_unity(k);
    fft_in_place(&mut a, w);
    a
}

/// LDE from base-domain evaluations (size n) to extended evaluations (size n<<blowup).
/// Assumes base domain is the radix-2 subgroup of size n. Pads evaluations by
/// duplicating the last value up to n=power-of-two as needed.
pub fn lde_from_evals(base_evals: &[Fp], blowup_log2: u32) -> Vec<Fp> {
    let n_base = base_evals.len().next_power_of_two();
    let ext_size = n_base << blowup_log2;
    // Copy and pad base evaluations
    let mut evals = vec![Fp::zero(); n_base];
    if !base_evals.is_empty() {
        let count = base_evals.len();
        evals[..count].copy_from_slice(&base_evals[..count]);
        if count < n_base {
            let last = *base_evals.last().unwrap();
            for x in evals[count..n_base].iter_mut() { *x = last; }
        }
    }
    // Inverse FFT on base domain to get coefficients
    let w_base = root_of_unity(n_base.trailing_zeros());
    ifft_in_place(&mut evals, w_base);
    // Zero-pad coefficients to extended size
    let mut coeffs_ext = vec![Fp::zero(); ext_size];
    coeffs_ext[..n_base].copy_from_slice(&evals[..n_base]);
    // FFT to extended domain
    let w_ext = root_of_unity(ext_size.trailing_zeros());
    fft_in_place(&mut coeffs_ext, w_ext);
    coeffs_ext
}

pub fn vanishing_poly_evals(size: usize) -> Vec<Fp> {
    // On evaluation domain of size N with root w and generator 1, vanishes at all points => X^N - 1
    // Return evaluations of z(x) = x^N - 1 on the domain [1, w, w^2, ...]
    assert!(size.is_power_of_two());
    let k = size.trailing_zeros();
    let w = root_of_unity(k);
    let mut evals = Vec::with_capacity(size);
    let mut x = Fp::one();
    for _ in 0..size {
        evals.push(x.pow(size as u128) - Fp::one());
        x *= w;
    }
    evals
}

/// Evaluate z_base(x) = x^{base_size} - 1 over a domain of length `domain_size`.
pub fn vanishing_on_extended(domain_size: usize, base_size: usize) -> Vec<Fp> {
    assert!(domain_size.is_power_of_two());
    let k = domain_size.trailing_zeros();
    let w = root_of_unity(k);
    let mut evals = Vec::with_capacity(domain_size);
    let mut x = Fp::one();
    for _ in 0..domain_size {
        evals.push(x.pow(base_size as u128) - Fp::one());
        x *= w;
    }
    evals
}

/// Evaluate a small-degree polynomial with `coeffs` at each point of a radix-2
/// domain of size `domain_size` (points: 1, w, w^2, ...).
pub fn eval_poly_on_domain(coeffs: &[Fp], domain_size: usize) -> Vec<Fp> {
    assert!(domain_size.is_power_of_two());
    let k = domain_size.trailing_zeros();
    let w = root_of_unity(k);
    let mut xs = Vec::with_capacity(domain_size);
    let mut x = Fp::one();
    for _ in 0..domain_size { xs.push(x); x *= w; }
    xs.into_iter()
        .map(|x| {
            let mut acc = Fp::zero();
            for &c in coeffs.iter().rev() { acc = acc * x + c; }
            acc
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn poly_eval_matches_fft_point() {
        // p(x) = 3 + 2x + x^2
        let p = Poly::new(vec![Fp::new(3), Fp::new(2), Fp::new(1)]);
        let n = 4usize; // pad to 4
        let k = n.trailing_zeros();
        let w = root_of_unity(k);
        let mut evals = vec![Fp::zero(); n];
        evals[..p.coeffs.len()].copy_from_slice(&p.coeffs[..]);
        fft_in_place(&mut evals, w);
        // Check evaluations at first few points
        let mut x = Fp::one();
        for ev in evals.iter().take(n) {
            assert_eq!(p.eval(x), *ev);
            x *= w;
        }
    }
}


