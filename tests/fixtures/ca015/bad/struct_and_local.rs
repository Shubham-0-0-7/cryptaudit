struct Session { // expect: CA015 medium
    key: [u8; 32],
    id: u64,
}

pub struct Credentials { // expect: CA015 medium
    username: String,
    password: String,
}

pub struct SecretKey([u8; 32]); // expect: CA015 medium

struct DerivedKeys { // expect: CA015 medium
    enc_key: Vec<u8>,
    mac_key: Vec<u8>,
}

// A Drop impl that does not wipe is no protection.
struct Wallet { // expect: CA015 medium
    seed: [u8; 64],
}

impl Drop for Wallet {
    fn drop(&mut self) {
        println!("dropping wallet");
    }
}

// The eth-keystore-rs shape: a KDF fills a local buffer that is then dropped.
fn derive(password: &[u8], salt: &[u8]) -> Result<(), Error> {
    let mut key = vec![0u8; 32]; // expect: CA015 medium
    pbkdf2::<Hmac<Sha256>>(password, salt, 600_000, key.as_mut_slice());
    let cipher = Aes128Ctr::new(&key[..16], &[0u8; 16]);
    cipher.apply_keystream(&mut buf);
    Ok(())
}

fn rng_filled() -> Result<(), Error> {
    let mut secret = [0u8; 32]; // expect: CA015 medium
    OsRng.fill_bytes(&mut secret);
    sign(&secret)?;
    Ok(())
}

// Moved out of a block into another binding: the outer binding owns it now.
fn through_match(kdf: Kdf) -> Result<(), Error> {
    let key = match kdf { // expect: CA015 medium
        Kdf::Pbkdf2 { c, salt } => {
            let mut key = vec![0u8; 32];
            pbkdf2::<Hmac<Sha256>>(b"pw", &salt, c, key.as_mut_slice());
            key
        }
    };
    use_key(&key);
    Ok(())
}
