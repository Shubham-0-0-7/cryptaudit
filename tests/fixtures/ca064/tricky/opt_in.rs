// An explicit `--insecure` option: dangerous, but the user chose it. Medium.
fn client(insecure: bool) -> reqwest::Client {
    let mut builder = reqwest::Client::builder();
    if insecure {
        builder = builder.danger_accept_invalid_certs(true); // expect: CA064 medium
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

// Chosen by a setting: the same `NONE` as a constant, but only on one branch. Medium.
fn by_setting(verify: bool, b: &mut openssl::ssl::SslConnectorBuilder) {
    if verify {
        b.set_verify(SslVerifyMode::PEER);
    } else {
        b.set_verify(SslVerifyMode::NONE); // expect: CA064 medium
    }
}
