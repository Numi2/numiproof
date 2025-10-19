// ML-KEM (CRYSTALS-Kyber) - use vetted implementation from pqcrypto-kyber
use pqcrypto_kyber::kyber768 as kyber;
use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _, Ciphertext as _, SharedSecret as _};

pub const PUBLIC_KEY_SIZE: usize = kyber::public_key_bytes();
pub const SECRET_KEY_SIZE: usize = kyber::secret_key_bytes();
pub const CIPHERTEXT_SIZE: usize = kyber::ciphertext_bytes();
pub const SHARED_SECRET_SIZE: usize = 32;

#[derive(Clone)]
pub struct PublicKey { pub bytes: Vec<u8> }

#[derive(Clone)]
pub struct SecretKey { pub bytes: Vec<u8> }

#[derive(Clone)]
pub struct Ciphertext { pub bytes: Vec<u8> }

pub fn keygen() -> (PublicKey, SecretKey) {
    let (pk, sk) = kyber::keypair();
    (
        PublicKey { bytes: pk.as_bytes().to_vec() },
        SecretKey { bytes: sk.as_bytes().to_vec() },
    )
}

pub fn encapsulate(pk: &PublicKey) -> (Ciphertext, Vec<u8>) {
    let pk_obj = kyber::PublicKey::from_bytes(&pk.bytes).expect("invalid kyber pk bytes");
    let (ss, ct) = kyber::encapsulate(&pk_obj);
    (
        Ciphertext { bytes: ct.as_bytes().to_vec() },
        ss.as_bytes().to_vec()
    )
}

pub fn decapsulate(ct: &Ciphertext, sk: &SecretKey) -> Vec<u8> {
    let ct_obj = kyber::Ciphertext::from_bytes(&ct.bytes).expect("invalid kyber ct bytes");
    let sk_obj = kyber::SecretKey::from_bytes(&sk.bytes).expect("invalid kyber sk bytes");
    let ss = kyber::decapsulate(&ct_obj, &sk_obj);
    ss.as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mlkem_keygen() {
        let (pk, sk) = keygen();
        assert_eq!(pk.bytes.len(), PUBLIC_KEY_SIZE);
        assert_eq!(sk.bytes.len(), SECRET_KEY_SIZE);
    }
    
    #[test]
    fn test_mlkem_encaps_decaps() {
        let (pk, sk) = keygen();
        let (ct, ss1) = encapsulate(&pk);
        let ss2 = decapsulate(&ct, &sk);
        assert_eq!(ct.bytes.len(), CIPHERTEXT_SIZE);
        assert_eq!(ss1, ss2, "shared secret mismatch");
    }
}

