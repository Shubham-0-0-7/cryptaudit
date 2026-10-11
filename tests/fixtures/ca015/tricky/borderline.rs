// A weak name: `token` on a lexer type, `key` on a map. Medium at most, and low
// for strings under a weak owner, so hidden by default.
struct Token { // expect: CA015 low
    kind: Kind,
    text: String,
}

// A user type from another file: we cannot see whether it wipes itself, and an
// opaque type is not treated as holding secret bytes.
struct Identity {
    signing_key: ed25519_dalek::SigningKey,
}
