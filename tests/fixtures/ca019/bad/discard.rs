fn wild(mut mac: Hmac<Sha256>, tag: &[u8]) {
    let _ = mac.verify_slice(tag); // expect: CA019 high
}

fn bare(cipher: &Aes256Gcm, nonce: &Nonce, buf: &mut Vec<u8>) {
    cipher.decrypt_in_place(nonce, b"", buf); // expect: CA019 high
}

fn ok_dropped(mut mac: Hmac<Sha256>, tag: &[u8]) {
    mac.verify_slice(tag).ok(); // expect: CA019 high
}

fn assign(vk: &VerifyingKey, msg: &[u8], sig: &Signature) {
    _ = vk.verify_strict(msg, sig); // expect: CA019 high
}

fn typed(mut mac: Hmac<Sha256>, tag: &[u8]) {
    let _: Result<(), MacError> = mac.verify_slice(tag); // expect: CA019 high
}

fn generic_name(cipher: &Aes256Gcm, nonce: &Nonce, ct: &[u8]) {
    let _ = cipher.decrypt(nonce, ct); // expect: CA019 medium
}
