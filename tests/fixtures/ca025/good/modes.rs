use aes_gcm::{Aes256Gcm, KeyInit};
use cbc::Encryptor;

fn gcm(key: &[u8]) {
    let _c = Aes256Gcm::new_from_slice(key).unwrap();
}

fn cbc(key: &[u8], iv: &[u8]) {
    let _c = cbc::Encryptor::<aes::Aes128>::new_from_slices(key, iv).unwrap();
}

// A word that merely contains the letters is not the mode.
fn becky(decker: &str) -> usize {
    decker.len()
}
