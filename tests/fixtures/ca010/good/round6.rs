// An `Error` variant that holds the message of what went wrong, not the secret.
#[derive(Debug)]
enum Error {
    InvalidJwtSecret(String),
    UnableToReadPassword(String),
}

// A custom derive hides the field and says so with an attribute.
#[derive(core_crypto_macros::Debug)]
struct StoredEncryptionKeyPair {
    #[sensitive]
    sk: Vec<u8>,
    id: String,
}

// The field's own doc comment says it is public.
#[derive(Debug)]
struct Credential {
    /// The public MLS credential, not a secret.
    credential: Vec<u8>,
    name: String,
}
