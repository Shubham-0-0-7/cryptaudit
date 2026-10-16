use sha2::{Digest, Sha256};

// A checksum of a file, and a hash of something that is not a password.
fn checksum(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

fn fingerprint(public_key: &[u8]) -> Vec<u8> {
    Sha256::digest(public_key).to_vec()
}

// Names that mention a password without being one.
fn lengths(password_len: usize, password_hash: &[u8], password_field: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(password_hash);
    h.update(password_field.as_bytes());
    h.update(password_len.to_be_bytes());
    h.finalize().to_vec()
}

// A real password hash.
fn argon(password: &[u8], salt: &[u8]) {
    let _ = Argon2::default().hash_password(password, salt);
}
