use hmac::{Hmac, Mac};
use sha2::Sha256;

fn check_stored(key: &[u8], msg: &[u8], expected: &[u8]) -> bool {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(msg);
    mac.finalize().into_bytes().as_slice() == expected // expect: CA021 high
}

fn check_negated(computed: &[u8; 32], expected: &[u8; 32]) -> bool {
    let digest = Sha256::digest(b"data");
    digest.as_slice() != expected // expect: CA021 high
}

// Shape of the eth-keystore-rs finding: both sides named like MACs.
fn keystore(derived_mac: Vec<u8>, keystore: &Keystore) -> Result<(), Error> {
    if derived_mac.as_slice() != keystore.crypto.mac.as_slice() { // expect: CA021 high
        return Err(Error::MacMismatch);
    }
    Ok(())
}

fn named(hmac: &[u8], received: &[u8]) -> bool {
    hmac == received // expect: CA021 medium
}

fn hex_compare(mac: &Hmac<Sha256>, expected_hex: &str) -> bool {
    hex::encode(mac.clone().finalize().into_bytes()) == expected_hex // expect: CA021 high
}

fn in_assert(computed_mac: &[u8], stored_mac: &[u8]) {
    assert!(computed_mac == stored_mac); // expect: CA021 high
}

fn field(msg: &Message, computed: &[u8]) -> bool {
    computed == msg.mac // expect: CA021 medium
}

// A local hasher fed a password: comparing the digest is a real timing leak.
fn verify_password(cleartext: &str, stored: &[u8]) -> bool {
    let mut hasher = Sha1::new();
    hasher.update(cleartext.as_bytes());
    let r = hasher.finalize();
    r.as_slice() == stored // expect: CA021 high
}
