use argon2::{Algorithm, Argon2, Params, Version};

fn owasp_argon2() {
    let params = Params::new(19_456, 2, 1, None).unwrap();
    let _ = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
}
