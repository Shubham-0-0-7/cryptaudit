#[derive(PartialEq)] // expect: CA013 high
struct SessionKey([u8; 32]);

#[derive(Clone, PartialEq, Eq)] // expect: CA013 low
struct Credentials {
    username: String,
    password: String,
}

#[derive(PartialEq)] // expect: CA013 high
struct MacTag {
    secret_key: [u8; 32],
}

// Shape of the ecies/rs SecretKey finding: manual PartialEq via `==` on bytes.
pub struct SecretKey(k256::SecretKey);

impl PartialEq for SecretKey { // expect: CA013 high
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

pub struct ApiToken {
    access_token: String,
}

impl PartialEq for ApiToken { // expect: CA013 high
    fn eq(&self, other: &Self) -> bool {
        self.access_token == other.access_token
    }
}
