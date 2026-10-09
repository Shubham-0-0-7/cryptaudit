use serde::{Deserialize, Serialize};

#[derive(Serialize)] // expect: CA012 high
struct Config {
    api_key: String,
    endpoint: String,
}

#[derive(Serialize, Deserialize)] // expect: CA012 high
struct Wallet {
    seed: Vec<u8>,
    label: String,
}

#[derive(serde::Serialize)] // expect: CA012 high
struct SessionKey([u8; 32]);

#[derive(Serialize)] // expect: CA012 high
enum Auth {
    Basic { user: String, password: String },
    Anonymous,
}

#[cfg_attr(feature = "serde", derive(Serialize))] // expect: CA012 high
struct Credentials {
    username: String,
    password: String,
}
