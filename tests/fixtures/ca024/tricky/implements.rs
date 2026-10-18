// A key-service library that offers 3DES for smart cards that still use it. The type
// and the impl are the primitive's own definition: low.
pub trait Tdes: CryptoClient {
    fn decrypt_tdes(&mut self, key: KeyId, message: &[u8]) {
        self.decrypt(Mechanism::Tdes, key, message) // expect: CA024 low
    }
}

impl MechanismImpl for super::Tdes {
    fn encrypt(&self, request: &Encrypt) {
        let cipher = des::TdesEde3::new(&key); // expect: CA024 low
    }
}

struct Md5Hasher;

mod rc4 {
    pub fn keystream() {
        let c = Rc4::new(&key); // expect: CA024 low
    }
}

// A program that chooses the primitive is still reported.
fn handshake() {
    let c = Rc4::new(&key); // expect: CA024 medium
}

// A wrapper that merely mentions the name in its own name is not the primitive.
fn digest_for_cache(data: &[u8]) {
    let d = Md5::digest(data); // expect: CA024 low
}
