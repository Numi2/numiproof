use core::ops::{Add, AddAssign, Sub, SubAssign, Mul, MulAssign, Neg};
use serde::{Deserialize, Serialize};

/// Goldilocks prime: 2^64 - 2^32 + 1
/// Commonly used for 64-bit friendly FFTs.
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
    // Reduction modulo 2^64 - 2^32 + 1 using lazy reduction.
    // Split x into hi:lo 64-bit limbs.
    let lo = x as u64;
    let hi = (x >> 64) as u64;
    // For modulus m = 2^64 - 2^32 + 1, we can use: hi*2^64 ≡ hi*(2^32 - 1) (mod m)
    // So x ≡ lo + hi*(2^32 - 1) = lo + (hi<<32) - hi
    let t = (lo as u128) + ((hi as u128) << 32) - (hi as u128);
    // t may be slightly above/below range; fold once more if needed
    let mut r = t as u64;
    // Because subtraction could underflow in u128 cast to u64, correct using modulus identity
    // Bring into canonical range with at most 2 corrections
    if t >> 64 != 0 {
        // If t overflowed 64 bits, fold again
        let hi2 = (t >> 64) as u64;
        let lo2 = r;
        let t2 = (lo2 as u128) + ((hi2 as u128) << 32) - (hi2 as u128);
        r = t2 as u64;
    }
    // Final conditional reductions
    while r >= MODULUS { r = r.wrapping_sub(MODULUS); }
    r
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
    // Known 2-adicity for Goldilocks is 32. Generator of 2^32 subgroup:
    // Use primitive root 7; w = 7^((p-1)/2^power)
    let g = Fp(7);
    let exp = (MODULUS as u128 - 1) >> power;
    g.pow(exp)
}

pub fn bit_reverse(mut x: usize, bits: u32) -> usize {
    let mut y = 0usize;
    for _ in 0..bits { y = (y<<1) | (x & 1); x >>= 1; }
    y
}

#[cfg(test)]
mod tests {
    use super::*;
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
}


