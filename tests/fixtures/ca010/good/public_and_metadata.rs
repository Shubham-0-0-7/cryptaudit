// Public material and metadata about keys are not secret.
#[derive(Debug, Clone)]
struct PublicKey([u8; 32]);

#[derive(Debug)]
struct KeyInfo {
    key_id: String,
    public_key: [u8; 32],
    key_len: usize,
    algorithm: String,
}

#[derive(Debug)]
struct Envelope {
    nonce: [u8; 12],
    salt: [u8; 16],
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Debug)]
struct User {
    username: String,
    password_hash: String,
}

#[derive(Debug)]
struct Keyboard {
    layout: String,
    hotkey: char,
}

// Test-only code is skipped by default.
#[cfg(test)]
mod tests {
    #[derive(Debug)]
    struct Fixture {
        secret_key: [u8; 32],
    }
}
