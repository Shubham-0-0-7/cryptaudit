// Validation left on, or switched on explicitly.
fn default_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(false)
        .build()
        .unwrap()
}

fn trusts_a_private_ca(pem: &[u8]) -> reqwest::Client {
    let ca = reqwest::Certificate::from_pem(pem).unwrap();
    reqwest::Client::builder()
        .add_root_certificate(ca)
        .build()
        .unwrap()
}

fn curl_handle(easy: &mut curl::easy::Easy) {
    easy.ssl_verify_peer(true).unwrap();
}

fn openssl_connector(b: &mut openssl::ssl::SslConnectorBuilder) {
    b.set_verify(SslVerifyMode::PEER);
    b.set_verify_callback(SslVerifyMode::PEER, |ok, _ctx| ok);
}

// A verifier that really checks, and a pinning verifier with an ordinary name.
struct PinnedVerifier {
    expected: Vec<u8>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() != self.expected.as_slice() {
            return Err(rustls::Error::General("certificate does not match the pin".into()));
        }
        Ok(ServerCertVerified::assertion())
    }
}

fn pinned() {
    let _ = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(PinnedVerifier { expected: vec![] }))
        .with_no_client_auth();
}
