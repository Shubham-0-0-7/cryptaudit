// A generic `tag` on one side only: could be an HTML tag, a git tag, a MAC.
fn generic(tag: &[u8], other: &[u8]) -> bool {
    tag == other // expect: CA021 low
}

// `tag` against `tag`: still unknown, but both sides say tag.
fn both_generic(tag: &[u8], received_tag: &[u8]) -> bool {
    tag == received_tag // expect: CA021 medium
}

// A checksum of a file is public data: `file` marks it as not secret.
fn checksum(file_digest: &[u8], expected: &[u8]) -> bool {
    file_digest == expected
}

// `mac` here is an address (MAC address), not a message authentication code.
// We cannot tell from the name. Reported at medium; documented false positive.
fn mac_address(mac: [u8; 6], other: [u8; 6]) -> bool {
    mac == other // expect: CA021 medium
}
