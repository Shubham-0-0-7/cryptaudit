// A method named `open` on a file-like type: generic name, medium confidence,
// and a documented false positive.
fn open_file(vault: &Vault) -> Handle {
    vault.open("db").unwrap() // expect: CA018 medium
}

// `unwrap` further down the chain is not the crypto result itself.
fn chained(cipher: &Aes256Gcm, nonce: &Nonce, ct: &[u8]) -> usize {
    cipher.decrypt(nonce, ct).map(|v| v.len()).unwrap()
}
