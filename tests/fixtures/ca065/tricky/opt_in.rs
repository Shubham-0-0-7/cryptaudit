// A `skip_hostname_check` option the caller sets: the code honours a switch it offers. Low.
fn client(skip_hostname_check: bool) {
    let mut builder = native_tls::TlsConnector::builder();
    if skip_hostname_check {
        builder.danger_accept_invalid_hostnames(true); // expect: CA065 low
    }
    let _ = builder.build();
}

// A condition about something else: nothing says the caller asked for this. Medium.
fn by_host(host: &str) {
    let mut builder = native_tls::TlsConnector::builder();
    if host.ends_with(".internal") {
        builder.danger_accept_invalid_hostnames(true); // expect: CA065 medium
    }
    let _ = builder.build();
}
