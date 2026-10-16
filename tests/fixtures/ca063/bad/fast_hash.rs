use sha2::{Digest, Sha256};

fn digest_password(password: &str) -> Vec<u8> {
    Sha256::digest(password.as_bytes()).to_vec() // expect: CA063 medium
}

fn hasher_password(user: &User) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(user.password.as_bytes()); // expect: CA063 medium
    hasher.finalize().to_vec()
}

fn chained(passphrase: &str) -> Vec<u8> {
    Sha512::new().chain_update(passphrase).finalize().to_vec() // expect: CA063 medium
}

fn md5_password(password: &str) -> String {
    format!("{:x}", md5::compute(password)) // expect: CA063 medium
}

fn blake3_password(password: &str) -> blake3::Hash {
    blake3::hash(password.as_bytes()) // expect: CA063 medium
}
