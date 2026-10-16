// Reading the header to *check* the algorithm against an allow-list is fine; only
// passing it straight to `Validation::new` is reported.
fn checked(token: &str) {
    let header = jsonwebtoken::decode_header(token).unwrap();
    if header.alg != Algorithm::ES256 {
        return;
    }
    let _validation = Validation::new(Algorithm::ES256);
}
