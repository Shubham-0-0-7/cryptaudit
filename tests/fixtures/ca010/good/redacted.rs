use secrecy::{SecretBox, SecretString};
use std::fmt;

// secrecy wrappers redact themselves.
#[derive(Debug)]
struct Config {
    api_key: SecretString,
    db_password: SecretBox<String>,
    endpoint: String,
}

// Manual Debug that redacts.
struct Session {
    key: [u8; 32],
    id: u64,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("key", &"[redacted]")
            .field("id", &self.id)
            .finish()
    }
}

// Printing metadata about a secret is fine.
struct Keyring {
    secret_key: Vec<u8>,
}

impl fmt::Display for Keyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Keyring({} bytes)", self.secret_key.len())
    }
}

// No Debug at all.
struct Wallet {
    seed: [u8; 64],
}

// Aliasing something that is not secret must not taint the alias.
struct Account {
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
    name: String,
}

impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let public = self.public_key.to_vec();
        let n = self.secret_key.len();
        let name = self.name.as_bytes();
        write!(f, "Account({:?}, {} secret bytes, {:?})", public, n, name)
    }
}
