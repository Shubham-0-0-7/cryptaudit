use chacha20poly1305::{ChaCha20Poly1305, Nonce, aead::Aead};

fn fresh_each_time(cipher: &ChaCha20Poly1305, a: &[u8], b: &[u8]) {
    let n1 = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let c1 = cipher.encrypt(&n1, a).unwrap();
    let n2 = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let c2 = cipher.encrypt(&n2, b).unwrap();
}

fn shadowed(cipher: &ChaCha20Poly1305, a: &[u8], b: &[u8]) {
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let c1 = cipher.encrypt(&nonce, a).unwrap();
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let c2 = cipher.encrypt(&nonce, b).unwrap();
}

fn refilled(cipher: &ChaCha20Poly1305, a: &[u8], b: &[u8]) {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let c1 = cipher.encrypt(Nonce::from_slice(&nonce), a).unwrap();
    OsRng.fill_bytes(&mut nonce);
    let c2 = cipher.encrypt(Nonce::from_slice(&nonce), b).unwrap();
}

fn counter(cipher: &ChaCha20Poly1305, msgs: &[Vec<u8>]) {
    let mut ctr = 0u64;
    let mut nonce = [0u8; 12];
    for m in msgs {
        nonce[4..].copy_from_slice(&ctr.to_be_bytes());
        cipher.encrypt(Nonce::from_slice(&nonce), m.as_slice()).unwrap();
        ctr += 1;
    }
}

fn fresh_in_loop(cipher: &ChaCha20Poly1305, msgs: &[Vec<u8>]) {
    for m in msgs {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        cipher.encrypt(&nonce, m.as_slice()).unwrap();
    }
}

// Different branches never both run.
fn branches(cipher: &ChaCha20Poly1305, nonce: &Nonce, fast: bool, a: &[u8], b: &[u8]) {
    if fast {
        cipher.encrypt(nonce, a).unwrap();
    } else {
        cipher.encrypt(nonce, b).unwrap();
    }
}

fn match_arms(cipher: &ChaCha20Poly1305, nonce: &Nonce, kind: u8, a: &[u8]) {
    match kind {
        0 => cipher.encrypt(nonce, a).unwrap(),
        _ => cipher.encrypt(nonce, a).unwrap(),
    };
}

// Two different ciphers, so two different keys.
fn two_keys(c1: &ChaCha20Poly1305, c2: &ChaCha20Poly1305, nonce: &Nonce, a: &[u8]) {
    c1.encrypt(nonce, a).unwrap();
    c2.encrypt(nonce, a).unwrap();
}

// A single call is fine.
fn once(cipher: &ChaCha20Poly1305, nonce: &Nonce, a: &[u8]) {
    cipher.encrypt(nonce, a).unwrap();
}

// A one-argument `encrypt` is not an AEAD.
fn not_aead(vault: &Vault, a: &[u8]) {
    vault.encrypt(a);
    vault.encrypt(a);
}

#[cfg(test)]
mod tests {
    fn t(cipher: &ChaCha20Poly1305, nonce: &Nonce, a: &[u8]) {
        cipher.encrypt(nonce, a).unwrap();
        cipher.encrypt(nonce, a).unwrap();
    }
}

// The generator itself advances, so each call gives new bytes.
fn advancing_rng(&mut self) {
    let mut nonce = [0u8; 12];
    self.rng.fill_bytes(&mut nonce);
}

// A clone used for something that is not a nonce, IV, salt or key.
fn cloned_for_padding(&self, pad: &mut [u8]) {
    let mut rng = self.rng.clone();
    rng.fill_bytes(pad);
}
