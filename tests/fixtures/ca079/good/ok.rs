use aes::Aes256;
use cbc::cipher::{BlockEncryptMut, KeyIvInit};

fn random_iv(key: &[u8; 32]) -> Vec<u8> {
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);
    let enc = cbc::Encryptor::<Aes256>::new(key.into(), &iv.into());
    iv.to_vec()
}

fn iv_from_message(key: &[u8; 32], iv: &[u8; 16]) {
    let dec = cbc::Decryptor::<Aes256>::new(key.into(), iv.into());
}

fn generated(key: &[u8; 32]) {
    let iv = cbc::Encryptor::<Aes256>::generate_iv(&mut OsRng);
    let enc = cbc::Encryptor::<Aes256>::new(key.into(), &iv);
}
