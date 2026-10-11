// `key` alone is a weak name: a map key being cleared is not a secret wipe.
fn clear_index(mut key: [u8; 8]) {
    key.fill(0); // expect: CA016 medium
}
