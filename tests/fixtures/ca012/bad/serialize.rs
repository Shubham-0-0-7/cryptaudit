use serde::{Deserialize, Serialize};

#[derive(Serialize)] // expect: CA012 low
struct Config {
    api_key: String,
    endpoint: String,
}

#[derive(Serialize, Deserialize)] // expect: CA012 low
struct Wallet {
    seed: Vec<u8>,
    label: String,
}

#[derive(serde::Serialize)] // expect: CA012 low
struct SessionKey([u8; 32]);

#[derive(Serialize)] // expect: CA012 low
enum Auth {
    Basic { user: String, password: String },
    Anonymous,
}

#[cfg_attr(feature = "serde", derive(Serialize))] // expect: CA012 low
struct Credentials {
    username: String,
    password: String,
}
