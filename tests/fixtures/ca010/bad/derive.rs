use aes_gcm::{Aes256Gcm, Key};

#[derive(Debug)] // expect: CA010 high
struct Session {
    key: [u8; 32],
    id: u64,
}

#[derive(Clone, Debug)] // expect: CA010 high
struct Credentials {
    username: String,
    password: String,
}

// Newtype: the field has no name, the struct name carries the signal.
#[derive(Debug)] // expect: CA010 high
struct SecretKey([u8; 32]);

#[derive(Debug, Clone)] // expect: CA010 high
pub struct Cipher {
    key: Key<Aes256Gcm>,
}

#[derive(std::fmt::Debug)] // expect: CA010 high
struct ApiClient {
    base_url: String,
    api_key: String,
}

#[derive(Debug)] // expect: CA010 high
enum Auth {
    Basic { user: String, password: String },
    Bearer(String),
    None,
}

#[cfg_attr(feature = "debug", derive(Debug))] // expect: CA010 high
struct Wallet {
    seed: Vec<u8>,
}

#[derive(Debug)] // expect: CA010 high
struct DerivedKeys {
    enc_key: Option<zeroize::Zeroizing<Vec<u8>>>,
    mac_key: Box<[u8]>,
}

// Struct named like a secret, byte field under a neutral name.
#[derive(Debug)] // expect: CA010 high
struct PrivateKey {
    inner: [u8; 32],
}
