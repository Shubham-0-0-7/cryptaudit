fn reqwest_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // expect: CA064 high
        .build()
        .unwrap()
}

fn native(builder: &mut native_tls::TlsConnectorBuilder) {
    builder.danger_accept_invalid_certs(true); // expect: CA064 high
}

fn lettre_params() {
    let _ = lettre::transport::smtp::client::TlsParametersBuilder::new("mail".into())
        .dangerous_accept_invalid_certs(true); // expect: CA064 high
}

fn ureq_agent() {
    let _ = ureq::config::Config::builder().tls_config(
        TlsConfig::builder().disable_verification(true).build(), // expect: CA064 high
    );
}

fn isahc_client() {
    let _ = isahc::config::SslOption::DANGER_ACCEPT_INVALID_CERTS; // expect: CA064 high
}

fn curl_handle(easy: &mut curl::easy::Easy) {
    easy.ssl_verify_peer(false).unwrap(); // expect: CA064 high
}

fn openssl_connector(b: &mut openssl::ssl::SslConnectorBuilder) {
    b.set_verify(SslVerifyMode::NONE); // expect: CA064 high
}

fn openssl_callback(b: &mut openssl::ssl::SslConnectorBuilder) {
    b.set_verify_callback(SslVerifyMode::PEER, |_ok, _ctx| true); // expect: CA064 high
}

fn redis_addr() -> redis::ConnectionAddr {
    redis::ConnectionAddr::TcpTls {
        host: "db".into(),
        port: 6380,
        insecure: true, // expect: CA064 high
        tls_params: None,
    }
}

fn rustls_named_verifier() {
    let _ = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(NoCertificateVerification)) // expect: CA064 high
        .with_no_client_auth();
}
