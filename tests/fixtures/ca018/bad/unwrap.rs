use aes_gcm::aead::{Aead, AeadInPlace};

fn open(cipher: &Aes256Gcm, nonce: &Nonce, ct: &[u8]) -> Vec<u8> {
    cipher.decrypt(nonce, ct).unwrap() // expect: CA018 medium
}

fn open_expect(cipher: &Aes256Gcm, nonce: &Nonce, ct: &[u8]) -> Vec<u8> {
    cipher.decrypt(nonce, ct).expect("decryption failed") // expect: CA018 medium
}

fn in_place(cipher: &Aes256Gcm, nonce: &Nonce, buf: &mut Vec<u8>) {
    cipher.decrypt_in_place(nonce, b"", buf).unwrap(); // expect: CA018 high
}

fn mac_check(mut mac: Hmac<Sha256>, tag: &[u8]) {
    mac.verify_slice(tag).unwrap(); // expect: CA018 high
}

fn sig(vk: &VerifyingKey, msg: &[u8], sig: &Signature) {
    vk.verify_strict(msg, sig).expect("bad signature"); // expect: CA018 high
}
