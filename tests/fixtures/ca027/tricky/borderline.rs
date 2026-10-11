// The constant is overwritten through a path the rule cannot see (a helper that
// takes the key by value and returns it), so the literal is reported. This is the
// remaining false-positive shape; confidence stays high because the literal is
// all zeros, which is almost never a real key.
fn through_helper() {
    let key = fill_with_kdf([0u8; 32]);
    let cipher = Aes256Gcm::new_from_slice(&[0u8; 32]).unwrap(); // expect: CA027 high
}

// A plain (not degenerate) literal is only medium.
fn plain_literal() {
    let cipher = Aes256Gcm::new_from_slice(b"0123456789abcdef0123456789abcdeg").unwrap(); // expect: CA027 medium
}
