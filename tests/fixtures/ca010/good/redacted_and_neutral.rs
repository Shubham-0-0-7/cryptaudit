// Blind-evaluation false positives.

// derive_more formats the type with a fixed string.
#[derive(Clone, derive_more::Debug)]
#[debug("Key(*******)")]
pub struct Key([u8; 32]);

// A neutral integer field in a secret-sounding type is not a secret.
#[derive(Debug)]
struct Credential {
    expect_selected: Option<isize>,
    use_signing_scheme: Option<u16>,
}

// `pwd` is the working directory in shell tools.
#[derive(Debug)]
struct ReshEntry {
    pwd: String,
    real_pwd: String,
}

// Public protocol parts.
#[derive(Debug)]
pub struct EncapsulatedSecret(pub Vec<u8>);

#[derive(Debug)]
pub struct SelectedCredential {
    ocsp: Vec<u8>,
}
