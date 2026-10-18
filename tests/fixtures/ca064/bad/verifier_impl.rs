// No named verifier is switched on in this file, so the impl itself is reported, at low:
// it is the definition, and the place that installs it is where the choice is made.
struct AcceptAll;

impl rustls::client::danger::ServerCertVerifier for AcceptAll {
    fn verify_server_cert( // expect: CA064 low
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}
