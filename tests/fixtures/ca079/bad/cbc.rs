use aes::Aes256;
use cbc::cipher::{BlockEncryptMut, KeyIvInit};

type Aes256CbcEnc = cbc::Encryptor<Aes256>;

fn zero_iv(key: &[u8; 32]) {
    let enc = Aes256CbcEnc::new(key.into(), &[0u8; 16].into()); // expect: CA079 high
}

fn literal_iv(key: &[u8; 32]) {
    let enc = cbc::Encryptor::<Aes256>::new(key.into(), b"0123456789abcdef".into()); // expect: CA079 high
}

const IV: [u8; 16] = [9; 16];

fn const_iv(key: &[u8; 32]) {
    let dec = cbc::Decryptor::<Aes256>::new(key.into(), &IV.into()); // expect: CA079 high
}

fn slices(key: &[u8]) {
    let enc = cbc::Encryptor::<Aes256>::new_from_slices(key, &[0u8; 16]).unwrap(); // expect: CA079 high
}
