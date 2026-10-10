// Returning the Result to the caller is not a discard.
fn forwarded(mut mac: Hmac<Sha256>, tag: &[u8]) -> Result<(), MacError> {
    mac.verify_slice(tag)
}

// A generic `verify` on an unrelated type, as a bare statement: low.
fn sandbox(checker: &Checker) {
    checker.verify(); // expect: CA019 low
}

// Real shape from RustCrypto/AEADs: a unit-returning stream decrypt, called as
// a bare statement. Nothing to discard, but we cannot tell from the name, so
// it is reported at low confidence (hidden by default).
struct Eax {
    imp: Imp,
}

impl Eax {
    fn decrypt_unauthenticated_hazmat(&mut self, msg: &mut [u8]) {
        self.imp.decrypt(msg); // expect: CA019 low
    }
}
