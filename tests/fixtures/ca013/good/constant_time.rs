use subtle::ConstantTimeEq;

pub struct SecretKey([u8; 32]);

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

// Eq alone is a marker trait.
impl Eq for SecretKey {}

// Public and metadata types compare normally.
#[derive(PartialEq, Eq)]
struct PublicKey([u8; 32]);

#[derive(PartialEq)]
struct KeyId(String);

#[derive(PartialEq)]
struct User {
    username: String,
    password_hash: String,
}

// Comparing something unrelated.
struct Point {
    x: u32,
}

impl PartialEq for Point {
    fn eq(&self, other: &Self) -> bool {
        self.x == other.x
    }
}
