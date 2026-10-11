use secrecy::SecretBox;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Zeroize, ZeroizeOnDrop)]
struct Session {
    key: [u8; 32],
    id: u64,
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Credentials {
    username: String,
    password: String,
}

// A Drop impl that wipes.
pub struct SecretKey([u8; 32]);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// Manual impls.
pub struct Wallet {
    seed: [u8; 64],
}

impl Zeroize for Wallet {
    fn zeroize(&mut self) {
        self.seed.zeroize();
    }
}

impl ZeroizeOnDrop for Wallet {}

// Fields wrapped in a wiping type.
struct Keys {
    enc_key: Zeroizing<Vec<u8>>,
    mac_key: SecretBox<[u8; 32]>,
}

// A field of another type in this file that wipes itself.
struct Holder {
    session_key: Session,
}

// Public data and metadata.
struct Info {
    key_id: String,
    public_key: [u8; 32],
    key_len: usize,
}

// Copy types cannot implement Drop: CA011 reports them instead.
#[derive(Clone, Copy)]
struct Raw([u8; 32]);

// Locals.
fn zeroized_after() {
    let mut key = vec![0u8; 32];
    OsRng.fill_bytes(&mut key);
    use_key(&key);
    key.zeroize();
}

fn wrapped() {
    let mut key = Zeroizing::new(vec![0u8; 32]);
    OsRng.fill_bytes(&mut key);
    use_key(&key);
}

fn returned() -> Vec<u8> {
    let mut key = vec![0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

fn returned_in_result() -> Result<Vec<u8>, Error> {
    let mut key = vec![0u8; 32];
    OsRng.fill_bytes(&mut key);
    Ok(key)
}

fn handed_to_struct() -> Keys {
    let mut key = vec![0u8; 32];
    OsRng.fill_bytes(&mut key);
    Keys { enc_key: Zeroizing::new(key), mac_key: todo!() }
}

// Never filled: just a buffer.
fn scratch() {
    let key = vec![0u8; 32];
    let n = key.len();
}

// Not named like a secret.
fn buffer() {
    let mut buf = vec![0u8; 32];
    OsRng.fill_bytes(&mut buf);
}

// Borrowed: the struct does not own the bytes, so the caller wipes them.
// (Real shape from rusty_paseto.)
pub struct PasetoAsymmetricPrivateKey<'a, Version, Purpose> {
    version: PhantomData<Version>,
    purpose: PhantomData<Purpose>,
    key: &'a [u8],
}

// A public key whose field is called `key`.
pub struct PasetoAsymmetricPublicKey {
    key: Vec<u8>,
}

pub struct VerifyingKeyBytes {
    key: [u8; 32],
}

// The assembled ciphertext is public: a buffer called `raw_token`, filled by
// copying nonce, ciphertext and tag. (Real shape from rusty_paseto.)
fn assemble(nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut raw_token = vec![0u8; nonce.len() + ciphertext.len()];
    raw_token[..nonce.len()].copy_from_slice(nonce);
    raw_token[nonce.len()..].copy_from_slice(ciphertext);
    let encoded = base64::encode(&raw_token);
    encoded.into_bytes()
}
