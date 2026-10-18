// A settings record compares its api key when the settings change; nobody guesses it.
#[derive(PartialEq)] // expect: CA013 low
struct Remote {
    search_api_key: String,
    url: String,
}

// A password in a login-parameters record: same reasoning, so low.
#[derive(PartialEq)] // expect: CA013 low
struct LoginParam {
    user: String,
    password: String,
}

// A struct with one field is a newtype around the secret: it is compared like one.
#[derive(PartialEq)] // expect: CA013 high
struct Wrapper {
    api_key: String,
}

#[derive(PartialEq)] // expect: CA013 high
struct SessionKey([u8; 32]);

// A type named like a clear secret stays high even with other fields.
#[derive(PartialEq)] // expect: CA013 high
struct StaticSecret {
    secret: [u8; 32],
    created: u64,
}

// A response type with a number named seed.
#[derive(PartialEq)]
struct CompletionResponse {
    seed: Option<i64>,
}
