use rand::{RngCore, rngs::StdRng, SeedableRng};
use serde::{Serialize, Deserialize};
use numiproof_hash::h_many;

pub mod mlkem;
pub mod air;

#[derive(Clone, Serialize, Deserialize)]
pub struct Keypair {
    pub sk: Vec<u8>,
    pub pk: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Note {
    pub value: u64,
    pub recipient_pk: Vec<u8>,
    pub rho: [u8; 32],
    pub r: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Output {
    pub cm: Vec<u8>,
    pub note: Note,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Input {
    pub nullifier: Vec<u8>,
    pub witness_path: Vec<Vec<u8>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TxV1 {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub ciphertexts: Vec<Vec<u8>>,
}

/// Generate an ML-KEM (Kyber-768) keypair for post-quantum encryption
pub fn kem_keygen() -> Keypair {
    let (pk, sk) = mlkem::keygen();
    Keypair { sk: sk.bytes, pk: pk.bytes }
}

/// Encapsulate a shared secret using ML-KEM; returns ciphertext and 32-byte shared secret
pub fn kem_encapsulate(pk_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let pk = mlkem::PublicKey { bytes: pk_bytes.to_vec() };
    let (ct, ss) = mlkem::encapsulate(&pk);
    (ct.bytes, ss)
}

/// Decapsulate the shared secret using ML-KEM
pub fn kem_decapsulate(ct_bytes: &[u8], sk_bytes: &[u8]) -> Vec<u8> {
    let ct = mlkem::Ciphertext { bytes: ct_bytes.to_vec() };
    let sk = mlkem::SecretKey { bytes: sk_bytes.to_vec() };
    let ss = mlkem::decapsulate(&ct, &sk);
    ss
}

/// Encrypt payload using KEM + XOR stream (simplified; not a full AEAD). For demos only.
pub fn kem_enc(pk_bytes: &[u8], payload: &[u8]) -> Vec<u8> {
    let (ct, ss) = kem_encapsulate(pk_bytes);
    
    // Use shared secret to encrypt payload (simplified: XOR with derived key stream)
    let mut hasher = sha3::Shake256::default();
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    hasher.update(&ss);
    let mut xof = hasher.finalize_xof();
    let mut keystream = vec![0u8; payload.len()];
    xof.read(&mut keystream);
    
    let mut encrypted = payload.to_vec();
    for (i, byte) in encrypted.iter_mut().enumerate() {
        *byte ^= keystream[i];
    }
    
    // Prepend ciphertext length and ciphertext
    let mut result = Vec::new();
    result.extend_from_slice(&(ct.len() as u32).to_le_bytes());
    result.extend_from_slice(&ct);
    result.extend_from_slice(&encrypted);
    result
}

/// Decrypt payload using KEM + XOR stream (simplified; not a full AEAD). For demos only.
pub fn kem_dec(sk_bytes: &[u8], ct_payload: &[u8]) -> Option<Vec<u8>> {
    if ct_payload.len() < 4 { return None; }
    
    // Extract KEM ciphertext
    let ct_len = u32::from_le_bytes(ct_payload[0..4].try_into().ok()?) as usize;
    if ct_payload.len() < 4 + ct_len { return None; }
    
    let kem_ct = &ct_payload[4..4 + ct_len];
    let encrypted_payload = &ct_payload[4 + ct_len..];
    
    // Decapsulate to get shared secret
    let ss = kem_decapsulate(kem_ct, sk_bytes);
    
    // Derive keystream and decrypt
    let mut hasher = sha3::Shake256::default();
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    hasher.update(&ss);
    let mut xof = hasher.finalize_xof();
    let mut keystream = vec![0u8; encrypted_payload.len()];
    xof.read(&mut keystream);
    
    let mut decrypted = encrypted_payload.to_vec();
    for (i, byte) in decrypted.iter_mut().enumerate() {
        *byte ^= keystream[i];
    }
    
    Some(decrypted)
}

pub fn note_commitment(note: &Note) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + note.recipient_pk.len() + 32 + 32);
    buf.extend_from_slice(&note.value.to_le_bytes());
    buf.extend_from_slice(&note.recipient_pk);
    buf.extend_from_slice(&note.rho);
    buf.extend_from_slice(&note.r);
    h_many("note.cm", &[&buf]).to_vec()
}

pub fn nullifier(nsk: &[u8], rho: &[u8; 32]) -> Vec<u8> {
    h_many("note.nf", &[nsk, rho]).to_vec()
}

pub fn make_note(value: u64, recipient_pk: Vec<u8>) -> Note {
    let mut rng = StdRng::from_entropy();
    let mut rho = [0u8; 32];
    let mut r = [0u8; 32];
    rng.fill_bytes(&mut rho);
    rng.fill_bytes(&mut r);
    Note { value, recipient_pk, rho, r }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mlkem_roundtrip() {
        let kp = kem_keygen();
        let payload = b"Hello, post-quantum world!";
        let ct = kem_enc(&kp.pk, payload);
        let decrypted = kem_dec(&kp.sk, &ct).expect("Decryption failed");
        assert_eq!(decrypted, payload);
    }
    
    #[test]
    fn test_note_commitment() {
        let kp = kem_keygen();
        let note = make_note(1000, kp.pk);
        let cm = note_commitment(&note);
        assert_eq!(cm.len(), 48); // SHAKE256-384 output
    }
}

