use aes_gcm::{Aes256Gcm, KeyInit};
use sha2::{Digest, Sha256};

fn encrypt(key: &[u8]) {
    let _cipher = Aes256Gcm::new_from_slice(key).unwrap();
}

fn hash(data: &[u8]) {
    let _digest = Sha256::digest(data);
}

// Variables that happen to be called after an algorithm are not the algorithm.
fn names(md5: &str, des: &str) -> usize {
    md5.len() + des.len()
}

// A name that already says it is legacy is a decision, not an oversight.
fn legacy() -> AlgorithmId {
    AlgorithmId::DesEdeForLegacyUseOnly
}
