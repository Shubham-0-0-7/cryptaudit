use log::info;

// `token` and `key` alone are common in non-secret code (lexers, maps).
fn weak_names(token: &str, key: &str) {
    info!("token {}", token); // expect: CA014 low
    info!("key {}", key); // expect: CA014 low
}

// Printing to the terminal is often the point of a command-line tool.
fn cli(password: &str) {
    println!("generated: {}", password); // expect: CA014 low
}

// A weak name that is explicitly encoded stays low.
fn encoded_weak(key: &[u8]) {
    info!("key {}", hex::encode(key)); // expect: CA014 low
}

// A command-line tool may print a generated passphrase on purpose, but a
// leftover debug `eprintln!` looks the same, so it is reported at medium.
fn cli_exposed(new_passphrase: secrecy::SecretString) {
    eprintln!("    {}", new_passphrase.expose_secret()); // expect: CA014 medium
}
