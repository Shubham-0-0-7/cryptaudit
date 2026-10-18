// A protocol library: PostgreSQL's login exchange is defined as MD5 of the password,
// so the crate offers `md5_hash` to clients that must speak it. Low.
pub fn md5_hash(username: &[u8], password: &[u8], salt: [u8; 4]) -> String {
    let mut md5 = Md5::new();
    md5.update(password); // expect: CA063 low
    md5.update(username);
    format!("md5{:x}", md5.finalize())
}

// A private helper that picked the hash for storing passwords is the mistake. Medium.
fn store(password: &str) -> Vec<u8> {
    Sha256::digest(password.as_bytes()).to_vec() // expect: CA063 medium
}

// Public, but not named after a hash: an application API that stores passwords. Medium.
pub fn save_password(password: &str) -> Vec<u8> {
    Sha256::digest(password.as_bytes()).to_vec() // expect: CA063 medium
}
