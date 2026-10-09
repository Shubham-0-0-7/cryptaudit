use std::fmt;

// Shape of the ecies/rs SecretKey finding: a hand-written Debug that prints raw bytes.
pub struct SecretKey {
    bytes: [u8; 32],
}

impl SecretKey {
    pub fn serialize(&self) -> [u8; 32] {
        self.bytes
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey({:?})", self.serialize()) // expect: CA010 high
    }
}

pub struct Session {
    session_key: Vec<u8>,
    user: String,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("user", &self.user)
            .field("session_key", &self.session_key) // expect: CA010 high
            .finish()
    }
}

pub struct Token {
    access_token: String,
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bearer {}", self.access_token) // expect: CA010 high
    }
}

pub struct HmacKey([u8; 64]);

impl fmt::Debug for HmacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0)) // expect: CA010 high
    }
}

pub struct Signer {
    signing_key: [u8; 32],
}

impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.signing_key, f) // expect: CA010 high
    }
}

// Regression from ecies/rs: the secret reaches the formatter through a local
// binding, and the field is a wrapper type from another crate.
pub struct WrappedSecretKey(k256::SecretKey);

impl fmt::Debug for WrappedSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes: [u8; 32] = self.0.to_bytes().into();
        f.debug_tuple("WrappedSecretKey").field(&bytes).finish() // expect: CA010 high
    }
}

// Same flow, plain `let`, named field.
pub struct Vault {
    master_key: Inner,
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let raw = self.master_key.as_bytes();
        write!(f, "Vault({:?})", raw) // expect: CA010 high
    }
}
