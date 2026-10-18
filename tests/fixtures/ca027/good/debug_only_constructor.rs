// Compiled only in test and debug builds, so it can never reach a release.
#[cfg(any(test, debug_assertions))]
fn for_testing() -> Aes256Gcm {
    Aes256Gcm::new_from_slice(b"0123456789abcdef0123456789abcdef").unwrap()
}
