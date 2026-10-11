use aes_gcm::{Aes256Gcm, Key, KeyInit, aead::OsRng};
use hmac::{Hmac, Mac};
use sha2::Sha256;

fn generated() {
    let key = Aes256Gcm::generate_key(&mut OsRng);
    let cipher = Aes256Gcm::new(&key);
}

fn from_env() -> Result<(), Error> {
    let raw = std::env::var("APP_KEY")?;
    let key = hex::decode(raw)?;
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    Ok(())
}

fn from_param(key: &[u8]) {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
}

fn derived(password: &str, salt: &[u8]) {
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 600_000, &mut key);
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
}

// A zeroed buffer that a KDF or an RNG fills is not a hardcoded key: once the
// local is passed as `&mut key`, it is no longer a constant.
fn rng_filled() {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
}

fn copied_in(source: &[u8]) {
    let mut key = [0u8; 32];
    key.copy_from_slice(source);
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
}

fn filled_by_loop(source: &[u8]) {
    let mut key = vec![0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = source[i];
    }
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
}

// A literal that is not key material.
fn unrelated() {
    let data = [0u8; 32];
    let hash = Sha256::digest(&data);
}

// Test-only code is skipped.
#[cfg(test)]
mod tests {
    fn t() {
        let cipher = Aes256Gcm::new_from_slice(&[0u8; 32]).unwrap();
    }
}
