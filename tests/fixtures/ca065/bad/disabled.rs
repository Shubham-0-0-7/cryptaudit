fn native() {
    let _ = native_tls::TlsConnector::builder()
        .danger_accept_invalid_hostnames(true) // expect: CA065 high
        .build();
}

fn reqwest_client() {
    let _ = reqwest::Client::builder()
        .danger_accept_invalid_hostnames(true) // expect: CA065 high
        .build();
}

fn lettre_params() {
    let _ = TlsParametersBuilder::new("mail".into()).dangerous_accept_invalid_hostnames(true); // expect: CA065 high
}

fn isahc_client() {
    let _ = isahc::config::SslOption::DANGER_ACCEPT_INVALID_HOSTS; // expect: CA065 high
}

fn curl_handle(easy: &mut curl::easy::Easy) {
    easy.ssl_verify_host(false).unwrap(); // expect: CA065 high
}

fn openssl_config(c: &mut openssl::ssl::ConnectConfiguration) {
    c.set_verify_hostname(false); // expect: CA065 high
}
