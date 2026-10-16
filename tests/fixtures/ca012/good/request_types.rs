use serde::Serialize;

// A request type exists to be sent. Its secret field is the caller's business;
// the type is not itself a secret, so the rule stays quiet at medium and high.
#[derive(Serialize)] // expect: CA012 low
struct PasswordChangeRequest {
    session_token: String,
}

#[derive(Serialize)]
struct TlsCertificatePaths<'p> {
    private_key: &'p str,
}
