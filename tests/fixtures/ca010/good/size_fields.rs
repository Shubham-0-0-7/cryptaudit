// Round 3: integers that describe a secret (a length, a count) are not secrets.
#[derive(Debug, Clone, Copy)]
struct Params {
    sk_bytes: u32,
    n_secret: usize,
}

// `credential` is often a public identity (MLS, WebAuthn): a hint, not proof.
#[derive(Debug)]
struct BasicCredential {
    credential_type: u16,
    flags: u8,
}
