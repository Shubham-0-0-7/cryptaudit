use std::fmt;

// Where a secret lives, or what it is called, is not the secret.
#[derive(Debug)]
struct Command {
    api_key_variable: String,
    key_file_location: String,
}

#[derive(Debug)]
enum PrivateKeyLocation {
    KeyFile(String),
    EnvironmentVariable(String),
}

#[derive(Debug)]
struct TlsCertificatePaths<'p> {
    cert: &'p str,
    private_key: &'p str,
}

// A sampling seed in a request is a parameter of the call, not key material.
#[derive(Debug)]
struct ChatCompletionRequest {
    model: String,
    seed: Option<i64>,
}

// A database primary key, and the time a password was last changed.
#[derive(Debug)]
struct LoginMeta {
    primary_key: String,
    time_password_changed: i64,
    password_field: String,
}

// A hand-written Debug that throws the value away in a closure.
struct AuthResponse {
    token: Option<String>,
    id: String,
}

impl fmt::Debug for AuthResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthResponse")
            .field("id", &self.id)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}
