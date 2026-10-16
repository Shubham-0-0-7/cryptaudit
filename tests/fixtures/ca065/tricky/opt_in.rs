fn client(skip_hostname_check: bool) {
    let mut builder = native_tls::TlsConnector::builder();
    if skip_hostname_check {
        builder.danger_accept_invalid_hostnames(true); // expect: CA065 medium
    }
    let _ = builder.build();
}
