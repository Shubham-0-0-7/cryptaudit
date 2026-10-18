// A database key, a lexer token and a public credential: named like secrets by one
// weak word, in types whose own names say nothing, holding variable-length data.
// Low confidence, so hidden from the default view.
struct ScanState { // expect: CA015 low
    key_buf: Vec<u8>,
}

struct Header { // expect: CA015 low
    token: Vec<u8>,
}

struct OldEpochMemberData { // expect: CA015 low
    credential: Vec<u8>,
}

// A buffer called `key` that no KDF and no RNG wrote: probably a database row key.
fn row_key(index: u64) -> Vec<u8> {
    let mut key = vec![0u8; 8];
    key.copy_from_slice(&index.to_be_bytes());
    key
}
