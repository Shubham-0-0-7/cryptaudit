use chacha20poly1305::{ChaCha20Poly1305, Nonce, aead::Aead};

// The example from the project proposal: one nonce, two messages.
fn reuse(cipher: &ChaCha20Poly1305, m1: &[u8], m2: &[u8]) -> Result<(), Error> {
    let nonce = Nonce::from_slice(b"unique nonce");
    let c1 = cipher.encrypt(nonce, m1)?; // expect: CA028 medium
    let c2 = cipher.encrypt(nonce, m2)?; // expect: CA028 medium
    Ok(())
}

fn same_param(cipher: &ChaCha20Poly1305, nonce: &Nonce, a: &[u8], b: &[u8]) {
    let c1 = cipher.encrypt(nonce, a).unwrap();
    let c2 = cipher.encrypt(nonce, b).unwrap(); // expect: CA028 high
}

fn random_but_reused(cipher: &ChaCha20Poly1305, a: &[u8], b: &[u8]) {
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let c1 = cipher.encrypt(&nonce, a).unwrap();
    let c2 = cipher.encrypt(&nonce, b).unwrap(); // expect: CA028 high
}

fn in_place(cipher: &ChaCha20Poly1305, nonce: &Nonce, buf1: &mut Vec<u8>, buf2: &mut Vec<u8>) {
    cipher.encrypt_in_place(nonce, b"", buf1).unwrap();
    cipher.encrypt_in_place(nonce, b"", buf2).unwrap(); // expect: CA028 high
}

fn loop_reuse(cipher: &ChaCha20Poly1305, messages: &[Vec<u8>]) {
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    for m in messages {
        let c = cipher.encrypt(&nonce, m.as_slice()).unwrap(); // expect: CA028 medium
    }
}

fn while_reuse(cipher: &ChaCha20Poly1305, nonce: &Nonce, mut n: u32) {
    while n > 0 {
        cipher.encrypt(nonce, b"x".as_ref()).unwrap(); // expect: CA028 medium
        n -= 1;
    }
}

fn iterator_reuse(cipher: &ChaCha20Poly1305, nonce: &Nonce, msgs: &[Vec<u8>]) {
    let out: Vec<_> = msgs.iter().map(|m| cipher.encrypt(nonce, m.as_slice()).unwrap()).collect(); // expect: CA028 medium
}

fn field_nonce(&self, a: &[u8], b: &[u8]) {
    let c1 = self.cipher.encrypt(&self.nonce, a).unwrap();
    let c2 = self.cipher.encrypt(&self.nonce, b).unwrap(); // expect: CA028 high
}

// The timestamp nonce: the motivating example of the whole project.
fn timestamp(cipher: &ChaCha20Poly1305, msg: &[u8]) {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let mut bytes = [0u8; 12];
    let nonce_bytes = now.to_be_bytes();
    let nonce = Nonce::from_slice(&nonce_bytes[4..]);
    cipher.encrypt(nonce, msg).unwrap(); // expect: CA028 medium
}

fn timestamp_direct(cipher: &ChaCha20Poly1305, msg: &[u8]) {
    let nonce = Nonce::from(Instant::now().elapsed().as_nanos().to_le_bytes()[..12]);
    cipher.encrypt(&nonce, msg).unwrap(); // expect: CA028 medium
}

fn literal_inline(cipher: &ChaCha20Poly1305, msg: &[u8]) {
    cipher.encrypt(Nonce::from_slice(&[0u8; 12]), msg).unwrap(); // expect: CA028 medium
}

const NONCE: [u8; 12] = [1; 12];

fn from_const(cipher: &ChaCha20Poly1305, msg: &[u8]) {
    cipher.encrypt(Nonce::from_slice(&NONCE), msg).unwrap(); // expect: CA028 medium
}

fn ring_style(key: &LessSafeKey, mut buf: Vec<u8>) {
    let nonce = Nonce::assume_unique_for_key([0u8; 12]);
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut buf).unwrap(); // expect: CA028 medium
}
