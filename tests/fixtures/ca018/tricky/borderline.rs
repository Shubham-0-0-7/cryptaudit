// An `open` with one argument opens a file or a device; an AEAD `open` takes a
// nonce and a ciphertext. Not reported.
fn open_file(vault: &Vault) -> Handle {
    vault.open("db").unwrap()
}

// `unwrap` further down the chain is not the crypto result itself.
fn chained(cipher: &Aes256Gcm, nonce: &Nonce, ct: &[u8]) -> usize {
    cipher.decrypt(nonce, ct).map(|v| v.len()).unwrap()
}
