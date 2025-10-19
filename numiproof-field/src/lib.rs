use core::ops::{Add, AddAssign, Sub, SubAssign, Mul, MulAssign, Neg};
use serde::{Deserialize, Serialize};

/// Goldilocks prime modulus (2^64 - 2^32 + 1), widely used for 64-bit FFTs.
pub const MODULUS: u64 = 0xFFFF_FFFF_0000_0001;

#[derive(Copy, Clone, Default, Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct Fp(pub u64);

impl Fp {
    #[inline]
    pub fn new(x: u64) -> Self { Fp(reduce_u128(x as u128)) }

    #[inline]
    pub fn zero() -> Self { Fp(0) }

    #[inline]
    pub fn one() -> Self { Fp(1) }

    #[inline]
    pub fn from_u128(x: u128) -> Self { Fp(reduce_u128(x)) }

    #[inline]
    pub fn to_u64(self) -> u64 { self.0 }

    #[inline]
    pub fn inv(self) -> Self {
        // Fermat's little theorem: a^(p-2)
        self.pow(MODULUS as u128 - 2)
    }

    #[inline]
    pub fn pow(self, mut e: u128) -> Self {
        let mut base = self;
        let mut acc = Fp::one();
        while e > 0 {
            if e & 1 == 1 { acc *= base; }
            base *= base;
            e >>= 1;
        }
        acc
    }
}

#[inline]
fn reduce_u128(x: u128) -> u64 {
    // Correct reduction using native 128-bit remainder; fast enough for tests and correctness-critical.
    (x % (MODULUS as u128)) as u64
}

impl Add for Fp {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        let (s, c) = self.0.overflowing_add(rhs.0);
        let mut r = s;
        if c || r >= MODULUS { r = r.wrapping_sub(MODULUS); }
        Fp(r)
    }
}
impl AddAssign for Fp { #[inline] fn add_assign(&mut self, rhs: Self) { *self = *self + rhs; } }

impl Sub for Fp {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        let (d, b) = self.0.overflowing_sub(rhs.0);
        let r = if b { d.wrapping_add(MODULUS) } else { d };
        Fp(r)
    }
}
impl SubAssign for Fp { #[inline] fn sub_assign(&mut self, rhs: Self) { *self = *self - rhs; } }

impl Mul for Fp {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self::Output { Fp::from_u128((self.0 as u128) * (rhs.0 as u128)) }
}
impl MulAssign for Fp { #[inline] fn mul_assign(&mut self, rhs: Self) { *self = *self * rhs; } }

impl Neg for Fp {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self::Output { if self.0 == 0 { self } else { Fp(MODULUS - self.0) } }
}

/// Compute a principal 2^k root of unity and its table of powers.
pub fn root_of_unity(power: u32) -> Fp {
    // Known 2-adicity for Goldilocks is 32. We derive a principal 2^power root from generator g=7
    // as w = g^((p-1)/2^power). In debug builds we assert the expected order.
    let g = Fp::new(7);
    let exp = ((MODULUS as u128) - 1) >> power;
    let w = g.pow(exp);
    // As a safety net in debug/tests, assert expected order
    debug_assert_eq!(w.pow(1u128 << power), Fp::one());
    w
}

pub fn bit_reverse(mut x: usize, bits: u32) -> usize {
    let mut y = 0usize;
    for _ in 0..bits { y = (y<<1) | (x & 1); x >>= 1; }
    y
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand::rngs::StdRng;
    #[test]
    fn field_add_mul() {
        let a = Fp::new(123);
        let b = Fp::new(456);
        let c = a + b;
        let d = a * b;
        assert_eq!(c - b, a);
        assert_eq!(d * b.inv(), a);
    }

    #[test]
    fn roots_pow_two() {
        let w = root_of_unity(20);
        // w^(2^20) == 1
        assert_eq!(w.pow(1u128<<20), Fp::one());
        // w^(2^19) != 1 (primitive)
        assert_ne!(w.pow(1u128<<19), Fp::one());
    }

    #[test]
    fn reduce_u128_matches_mod() {
        let mut rng = StdRng::seed_from_u64(0xC0FFEE);
        for _ in 0..2000 {
            let hi: u64 = rng.gen();
            let lo: u64 = rng.gen();
            let x = ((hi as u128) << 64) | (lo as u128);
            let r = super::reduce_u128(x);
            let e = (x % (MODULUS as u128)) as u64;
            assert_eq!(r, e);
        }
    }

    #[test]
    fn mul_matches_big_mod() {
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..2000 {
            let a: u64 = rng.gen();
            let b: u64 = rng.gen();
            let fa = Fp::new(a);
            let fb = Fp::new(b);
            let prod = (a as u128) * (b as u128);
            let expected = (prod % (MODULUS as u128)) as u64;
            assert_eq!((fa * fb).0, expected);
        }
    }

    #[test]
    fn inverse_property() {
        let mut rng = StdRng::seed_from_u64(7);
        for _ in 0..2000 {
            let mut a: u64 = rng.gen();
            // avoid zero
            if a % MODULUS == 0 { a = 1; }
            let fa = Fp::new(a);
            assert_eq!(fa * fa.inv(), Fp::one());
        }
    }

    #[test]
    fn pow_identity() {
        let mut rng = StdRng::seed_from_u64(999);
        for _ in 0..512 {
            let a = Fp::new(rng.gen());
            assert_eq!(a.pow(0), Fp::one());
            assert_eq!(a.pow(1), a);
            assert_eq!(a.pow(2), a * a);
        }
    }

    #[test]
    fn roots_across_powers() {
        // Check a range of powers for primitive property
        for power in 8..=28 {
            let w = root_of_unity(power);
            assert_eq!(w.pow(1u128 << power), Fp::one());
            if power > 0 { assert_ne!(w.pow(1u128 << (power-1)), Fp::one()); }
        }
    }

    #[test]
    fn bit_reverse_permutation_roundtrip() {
        for bits in 1..=12 {
            let n = 1usize << bits;
            let mut seen = vec![false; n];
            for i in 0..n {
                let j = bit_reverse(i, bits as u32);
                assert!(j < n);
                seen[j] = true;
            }
            assert!(seen.into_iter().all(|v| v));
        }
    }
}


