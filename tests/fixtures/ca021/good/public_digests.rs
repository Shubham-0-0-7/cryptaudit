use sha2::{Digest, Sha256};

// DNSSEC key tag: an identifier, not an authentication tag.
fn matches(sig: &Sig, key: &DnsKey, key_tag: u16) -> bool {
    sig.key_tag == key_tag
}

fn bytes_equal(sig: &Sig, key: &DnsKey) -> bool {
    sig.key_tag == key.key_tag
}
