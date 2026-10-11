// A fixed nonce with a key derived per message is a legitimate design (the key is
// unique, so the (key, nonce) pair is). Reported at low confidence, hidden by default.
fn derived_key(master: &[u8], salt: &[u8], msg: &[u8]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), master);
    let mut key = [0u8; 32];
    hk.expand(b"enc", &mut key).unwrap();
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    cipher.encrypt(Nonce::from_slice(&[0u8; 12]), msg).unwrap(); // expect: CA028 low
}

// Reuse after a branch: possibly the branch returned, so medium rather than high.
fn after_branch(cipher: &ChaCha20Poly1305, nonce: &Nonce, early: bool, a: &[u8], b: &[u8]) {
    if early {
        return cipher.encrypt(nonce, a).map(|_| ()).unwrap();
    }
    cipher.encrypt(nonce, b).unwrap(); // expect: CA028 medium
}
