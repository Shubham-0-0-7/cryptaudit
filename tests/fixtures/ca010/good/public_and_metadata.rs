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

// Domain-separation constants: a `&'static str` is fixed at compile time and
// cannot hold a runtime secret. (Real shape from rusty_paseto.)
#[derive(Debug)]
pub struct EncryptionKeySeparator(&'static str);

impl std::fmt::Display for EncryptionKeySeparator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SigningKeyLabel {
    secret_label: &'static str,
}

// A type named public holds public material even when its field is just `key`.
#[derive(Debug, Clone)]
pub struct PasetoPublicKey {
    key: Vec<u8>,
}

#[derive(Debug)]
pub struct VerifyingKeyBytes {
    key: [u8; 32],
}
