use sha2::Sha256;

// Between 10,000 and 100,000: below guidance, but common in older systems. Low.
fn legacy(password: &[u8], salt: &[u8], out: &mut [u8]) {
    pbkdf2_hmac::<Sha256>(password, salt, 50_000, out); // expect: CA062 low
}
