use sha2::Sha256;

const FEW: u32 = 500;

fn pbkdf2_tiny(password: &[u8], salt: &[u8], out: &mut [u8]) {
    pbkdf2_hmac::<Sha256>(password, salt, 100, out); // expect: CA062 high
}

fn pbkdf2_const(password: &[u8], salt: &[u8], out: &mut [u8]) {
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, FEW, out); // expect: CA062 high
}

fn pbkdf2_old(password: &[u8], salt: &[u8], out: &mut [u8]) {
    pbkdf2_hmac::<Sha256>(password, salt, 5_000, out); // expect: CA062 medium
}

fn ring_pbkdf2(password: &[u8], salt: &[u8], out: &mut [u8]) {
    pbkdf2::derive( // expect: CA062 medium
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(1000).unwrap(),
        salt,
        password,
        out,
    );
}

fn bcrypt_cheap(password: &str) {
    let _ = bcrypt::hash(password, 4); // expect: CA062 high
    let _ = bcrypt::hash(password, 8); // expect: CA062 medium
}
