use std::fmt;

// A map entry: `key` is a lookup key, not key material. Reported, but low
// confidence, so hidden by default.
#[derive(Debug)] // expect: CA010 low
struct Entry {
    key: String,
    value: String,
}

// A lexer token. Struct name is a weak secret word, fields are neutral.
#[derive(Debug, Clone)] // expect: CA010 low
struct Token {
    kind: TokenKind,
    text: String,
}

#[derive(Debug, Clone)]
enum TokenKind {
    Ident,
    Punct,
}

// The field's own type decides what Debug prints. dalek's SigningKey redacts,
// a user type might not. Low confidence.
#[derive(Debug)] // expect: CA010 low
struct Identity {
    signing_key: ed25519_dalek::SigningKey,
}

// Field-level skip attributes from derive_more / derivative.
#[derive(derive_more::Debug)]
struct Skipped {
    #[debug(skip)]
    password: String,
    user: String,
}

#[derive(Derivative)]
#[derivative(Debug)]
struct Ignored {
    #[derivative(Debug = "ignore")]
    secret: Vec<u8>,
}

// Formatting only the public half of a key pair.
struct Keypair {
    secret: [u8; 32],
    public: [u8; 32],
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keypair").field("public", &self.public).finish_non_exhaustive()
    }
}

// Struct defined elsewhere: only the field name is known. Strong name, medium.
impl fmt::Debug for RemoteConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.endpoint, self.client_secret) // expect: CA010 medium
    }
}

// `cfg(any(test, ..))` is not test-only, so this is still scanned.
#[cfg(any(test, feature = "fuzzing"))]
#[derive(Debug)] // expect: CA010 high
struct FuzzInput {
    password: String,
}

// Only `password` leaks. `username` must not be listed just because the
// struct is named `Credentials`.
#[derive(Debug)] // expect: CA010 high
struct LoginCredentials {
    username: String,
    password: String,
    remember_me: bool,
}
