// Defined elsewhere: only the type name is known. Strong name, medium.
impl PartialEq for RemotePrivateKey { // expect: CA013 medium
    fn eq(&self, other: &Self) -> bool {
        self.bytes() == other.bytes()
    }
}

// Weak name and no definition in this file: a guess, low confidence.
impl PartialEq for Token { // expect: CA013 low
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
    }
}

// Map key, not key material.
#[derive(PartialEq, Eq, Hash)] // expect: CA013 low
struct Entry {
    key: String,
}
