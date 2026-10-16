use sha2::Sha256;

const ROUNDS: u32 = 600_000;

fn strong(password: &[u8], salt: &[u8], out: &mut [u8]) {
    pbkdf2_hmac::<Sha256>(password, salt, ROUNDS, out);
    pbkdf2_hmac::<Sha256>(password, salt, 1_000_000, out);
}

fn from_config(password: &[u8], salt: &[u8], out: &mut [u8], cfg: &Config) {
    // The number is not visible here, so nothing is claimed.
    pbkdf2_hmac::<Sha256>(password, salt, cfg.iterations, out);
}

fn bcrypt_default(password: &str) {
    let _ = bcrypt::hash(password, bcrypt::DEFAULT_COST);
    let _ = bcrypt::hash(password, 12);
}

// One round on top of an already stretched key (the Bitwarden login hash) is a derivation step.
fn one_step(key: &[u8], password: &[u8], out: &mut [u8]) {
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(key, password, 1, out).unwrap();
}
