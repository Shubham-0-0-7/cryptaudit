// "Have I Been Pwned" asks for the first five hex digits of SHA-1(password) on purpose.
// SHA-1 of a password is reported at low confidence so it stays out of the default view.
fn breach_lookup(password: &str) -> String {
    let digest = Sha1::digest(password.as_bytes()); // expect: CA063 low
    format!("{:x}", digest)
}
