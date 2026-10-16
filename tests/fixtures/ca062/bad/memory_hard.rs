use argon2::{Algorithm, Argon2, Params, Version};

fn cheap_argon2() {
    let params = Params::new(512, 1, 1, None).unwrap(); // expect: CA062 high
    let _ = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
}

fn small_argon2() {
    let params = argon2::Params::new(4096, 3, 1, None).unwrap(); // expect: CA062 medium
    let _ = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
}
