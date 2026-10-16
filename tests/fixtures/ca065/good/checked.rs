fn native() {
    let _ = native_tls::TlsConnector::builder()
        .danger_accept_invalid_hostnames(false)
        .build();
}

fn curl_handle(easy: &mut curl::easy::Easy) {
    easy.ssl_verify_host(true).unwrap();
}

fn openssl_config(c: &mut openssl::ssl::ConnectConfiguration) {
    c.set_verify_hostname(true);
}

// A method of the same name with no argument is not the switch.
fn unrelated(x: &Checker) -> bool {
    x.verify_hostname()
}

// OpenSSL: the name is checked by hand with `add_host`, which is as strict.
fn manual_name_check(c: &mut openssl::ssl::ConnectConfiguration, host: &str) {
    c.param_mut().add_host(host).unwrap();
    c.set_verify_hostname(false);
}
