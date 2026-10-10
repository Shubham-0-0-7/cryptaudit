// Generic `tag` and `digest` names: weak evidence on one side only.
fn weak(tag: &[u8], other: &[u8]) {
    assert_eq!(tag, other); // expect: CA020 low
}

// A checksum of a file is public data: `file` marks it as not secret.
fn weak2(file_digest: &[u8], expected: &[u8]) {
    assert_eq!(file_digest, expected);
}
