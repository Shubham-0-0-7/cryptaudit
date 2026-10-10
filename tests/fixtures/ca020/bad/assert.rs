fn verify(computed_mac: &[u8], expected_mac: &[u8]) {
    assert_eq!(computed_mac, expected_mac); // expect: CA020 high
}

fn verify_ne(tag: &[u8], received_tag: &[u8]) {
    assert_ne!(tag, received_tag); // expect: CA020 medium
}

fn debug(mac: &Hmac<Sha256>, expected: &[u8]) {
    debug_assert_eq!(mac.clone().finalize().into_bytes().as_slice(), expected); // expect: CA020 high
}
