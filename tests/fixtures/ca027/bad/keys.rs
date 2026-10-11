use aes_gcm::{Aes256Gcm, Key, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use sha2::Sha256;

// The example from the project proposal.
fn zero_key() {
    let key = [0u8; 32];
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key)); // expect: CA027 high
}

fn direct_literal() {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(b"an example very very secret key.")); // expect: CA027 medium
}

const API_KEY: [u8; 32] = [7; 32];

fn from_const() {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&API_KEY)); // expect: CA027 high
}

static SECRET: &[u8] = b"correct horse battery staple!!!!";

fn from_static() {
    let mac = Hmac::<Sha256>::new_from_slice(SECRET).unwrap(); // expect: CA027 medium
}

fn mac_literal() {
    let mut mac = Hmac::<Sha256>::new_from_slice(b"my secret and secure key").expect("ok"); // expect: CA027 medium
    mac.update(b"data");
}

fn hex_key() {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let cipher = aes::Aes128::new_from_slice(&key).unwrap(); // expect: CA027 medium
}

fn counting() {
    let cipher = Aes256Gcm::new_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]).unwrap(); // expect: CA027 high
}

fn vec_key() {
    let key = vec![0u8; 32];
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap(); // expect: CA027 high
}

fn ring_hmac() {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"static signing key"); // expect: CA027 medium
}

fn ring_aead() {
    let unbound = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &[0u8; 32]).unwrap(); // expect: CA027 high
}

fn embedded() {
    let cipher = Aes256Gcm::new_from_slice(include_bytes!("../key.bin")).unwrap(); // expect: CA027 medium
}

fn signing() {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]); // expect: CA027 high
}

fn ctr_iv() {
    let c = ctr::Ctr64BE::<aes::Aes128>::new(&key.into(), &[0u8; 16].into()); // expect: CA027 high
}
