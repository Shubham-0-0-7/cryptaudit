use serde::{Deserialize, Serialize};

// Deserialize alone cannot leak.
#[derive(Deserialize)]
struct Incoming {
    api_key: String,
}

// Secret field excluded from output.
#[derive(Serialize)]
struct Config {
    #[serde(skip)]
    api_key: String,
    endpoint: String,
}

#[derive(Serialize)]
struct Account {
    #[serde(skip_serializing)]
    password: String,
    name: String,
}

// Custom serialisation is assumed to redact.
#[derive(Serialize)]
struct Vault {
    #[serde(serialize_with = "redact")]
    master_key: Vec<u8>,
}

// Public and metadata fields.
#[derive(Serialize)]
struct KeyInfo {
    key_id: String,
    public_key: Vec<u8>,
    algorithm: String,
}

// Redacting wrapper.
#[derive(Serialize)]
struct Settings {
    api_key: secrecy::SecretString,
}
