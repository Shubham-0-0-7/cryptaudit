use aes_gcm::aead::Aead;

fn propagate(cipher: &Aes256Gcm, nonce: &Nonce, ct: &[u8]) -> Result<Vec<u8>, Error> {
    let pt = cipher.decrypt(nonce, ct).map_err(|_| Error::Auth)?;
    Ok(pt)
}

fn branch(mut mac: Hmac<Sha256>, tag: &[u8]) -> bool {
    mac.verify_slice(tag).is_ok()
}

// Setup errors are about a wrong length, not attacker input.
fn setup(key: &[u8]) -> Hmac<Sha256> {
    Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size")
}

fn setup_cipher(key: &[u8]) -> Aes256Gcm {
    Aes256Gcm::new_from_slice(key).unwrap()
}

// unwrap on something that is not a crypto result.
fn parse(s: &str) -> u32 {
    s.parse().unwrap()
}

#[cfg(test)]
mod tests {
    fn t(cipher: &Aes256Gcm, nonce: &Nonce, ct: &[u8]) {
        cipher.decrypt(nonce, ct).unwrap();
    }
}
