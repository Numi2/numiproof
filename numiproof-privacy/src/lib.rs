use rand::{RngCore, rngs::StdRng, SeedableRng};
use serde::{Serialize, Deserialize};
use numiproof_hash::{shake256_384, h_many, DIGEST_LEN};

#[derive(Clone, Serialize, Deserialize)]
pub struct Keypair {
    pub sk: [u8; 32],
    pub pk: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Note {
    pub value: u64,
    pub recipient_pk: [u8; 32],
    pub rho: [u8; 32],
    pub r: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Output {
    pub cm: [u8; DIGEST_LEN],
    pub note: Note,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Input {
    pub nullifier: [u8; DIGEST_LEN],
    pub witness_path: Vec<Vec<u8>>, // Merkle path placeholder
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TxV1 {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub ciphertexts: Vec<Vec<u8>>, // KEM-wrapped payloads (placeholder)
}

pub fn kem_keygen() -> Keypair {
    let mut rng = StdRng::from_entropy();
    let mut sk = [0u8; 32];
    rng.fill_bytes(&mut sk);
    let pk = shake256_384(&sk)[..32].try_into().unwrap();
    Keypair { sk, pk }
}

pub fn kem_enc(pk: &[u8; 32], payload: &[u8]) -> Vec<u8> {
    // Placeholder KEM: hash(pk||payload) as a stand-in; replace with ML-KEM
    h_many("kem.enc", &[pk, payload]).to_vec()
}

pub fn kem_dec(_sk: &[u8; 32], ct: &[u8]) -> Option<Vec<u8>> {
    // Placeholder KEM is not decryptable; in real impl, return decrypted payload
    Some(ct.to_vec())
}

pub fn note_commitment(note: &Note) -> [u8; DIGEST_LEN] {
    let mut buf = Vec::with_capacity(8 + 32 + 32 + 32);
    buf.extend_from_slice(&note.value.to_le_bytes());
    buf.extend_from_slice(&note.recipient_pk);
    buf.extend_from_slice(&note.rho);
    buf.extend_from_slice(&note.r);
    h_many("note.cm", &[&buf])
}

pub fn nullifier(nsk: &[u8; 32], rho: &[u8; 32]) -> [u8; DIGEST_LEN] {
    h_many("note.nf", &[nsk, rho])
}

pub fn make_note(value: u64, recipient_pk: [u8; 32]) -> Note {
    let mut rng = StdRng::from_entropy();
    let mut rho = [0u8; 32];
    let mut r = [0u8; 32];
    rng.fill_bytes(&mut rho);
    rng.fill_bytes(&mut r);
    Note { value, recipient_pk, rho, r }
}

