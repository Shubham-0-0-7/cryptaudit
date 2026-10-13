use serde::Serialize;

// `skip_deserializing` does not stop serialisation.
#[derive(Serialize)] // expect: CA012 low
struct Config {
    #[serde(skip_deserializing)]
    api_key: String,
}

// A map key, not key material. Low confidence.
#[derive(Serialize)] // expect: CA012 low
struct Entry {
    key: String,
    value: String,
}
