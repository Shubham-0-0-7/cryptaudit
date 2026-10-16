// A settings record compares its api key when the settings change; nobody guesses it.
#[derive(PartialEq)] // expect: CA013 low
struct Remote {
    search_api_key: String,
}

// A password or secret string is compared against what a user types.
#[derive(PartialEq)] // expect: CA013 high
struct Account {
    email: String,
    secret: Option<String>,
}

// A key held as raw bytes stays high whatever the type is called.
#[derive(PartialEq)] // expect: CA013 high
struct PushRecord {
    key: Vec<u8>,
}

// A response type with a number named seed.
#[derive(PartialEq)]
struct CompletionResponse {
    seed: Option<i64>,
}
