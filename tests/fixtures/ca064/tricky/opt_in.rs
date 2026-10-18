// An `insecure` option the caller sets: the code honours a switch it offers. Low.
fn client(insecure: bool) -> reqwest::Client {
    let mut builder = reqwest::Client::builder();
    if insecure {
        builder = builder.danger_accept_invalid_certs(true); // expect: CA064 low
    }
    builder.build().unwrap()
}

// A variable that may be on or off: low, hidden unless asked for.
fn from_config(config: &Config) -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(config.skip_verify) // expect: CA064 low
        .build()
        .unwrap()
}

// Chosen by a setting: the same `NONE` as a constant, but only on one branch. Low.
fn by_setting(verify: bool, b: &mut openssl::ssl::SslConnectorBuilder) {
    if verify {
        b.set_verify(SslVerifyMode::PEER);
    } else {
        b.set_verify(SslVerifyMode::NONE); // expect: CA064 low
    }
}

// A condition about something else: nothing says the caller asked for this. Medium.
fn local_only(url: &str) -> reqwest::Client {
    let mut builder = reqwest::Client::builder();
    if url.starts_with("https://localhost") {
        builder = builder.danger_accept_invalid_certs(true); // expect: CA064 medium
    }
    builder.build().unwrap()
}

// The application that passes a literal is the one that made the mistake. High.
fn hardcoded() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // expect: CA064 high
        .build()
        .unwrap()
}

// A library honouring `tlsAllowInvalidCertificates`, as the MongoDB driver does. Low.
fn mongo_style(allow_invalid_certificates: Option<bool>, b: &mut SslConnectorBuilder) {
    if let Some(true) = allow_invalid_certificates {
        b.set_verify(SslVerifyMode::NONE); // expect: CA064 low
    }
}

// An accept-all verifier installed because a setting said so, as rauthy and reqwest do. Low.
fn rustls_style(pg_tls_no_verify: bool) -> rustls::ClientConfig {
    if pg_tls_no_verify {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoTlsVerifier {})) // expect: CA064 low
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder().with_no_client_auth()
    }
}

// The same verifier installed with nothing deciding it. High.
fn rustls_always() -> rustls::ClientConfig {
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoTlsVerifier {})) // expect: CA064 high
        .with_no_client_auth()
}
