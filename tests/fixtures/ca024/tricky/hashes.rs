// MD5 and SHA-1 are reported at low confidence: a checksum, a cache key or an
// HMAC-SHA1 for TOTP is fine, and the source cannot tell them from a signature.
fn checksum(data: &[u8]) {
    let _digest = Md5::digest(data); // expect: CA024 low
}

fn old_signature_hash(data: &[u8]) {
    let mut hasher = Sha1::new(); // expect: CA024 low
    hasher.update(data);
}

// One finding per function, however often the name is used.
fn twice(data: &[u8]) {
    let mut a = Md5::new(); // expect: CA024 low
    a.update(data);
    let mut b = Md5::new();
    b.update(data);
}
