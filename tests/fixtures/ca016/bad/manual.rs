fn fill(password: &str) {
    let mut key = derive_key(password);
    use_key(&key);
    key.fill(0); // expect: CA016 medium
}

fn named_secret(secret_key: &mut [u8; 32]) {
    secret_key.fill(0); // expect: CA016 high
}

fn iter_for_each(mut password: Vec<u8>) {
    password.iter_mut().for_each(|b| *b = 0); // expect: CA016 high
}

fn for_loop(mut seed: [u8; 32]) {
    for b in seed.iter_mut() { // expect: CA016 high
        *b = 0;
    }
}

fn for_ref(mut private_key: [u8; 32]) {
    for b in &mut private_key { // expect: CA016 high
        *b = 0;
    }
}

fn indexed(mut secret: Vec<u8>) {
    for i in 0..secret.len() { // expect: CA016 high
        secret[i] = 0;
    }
}

fn assign_zeros(mut passphrase: [u8; 16]) {
    passphrase = [0u8; 16]; // expect: CA016 high
}

fn copy_zeros(mut key: [u8; 32]) {
    key.copy_from_slice(&[0u8; 32]); // expect: CA016 medium
}

fn write_bytes(mut session_key: [u8; 32]) {
    unsafe { std::ptr::write_bytes(session_key.as_mut_ptr(), 0, 32) } // expect: CA016 high
}

// The classic place: a hand-written Drop.
struct Holder {
    private_key: [u8; 32],
}

impl Drop for Holder {
    fn drop(&mut self) {
        self.private_key.fill(0); // expect: CA016 high
    }
}
