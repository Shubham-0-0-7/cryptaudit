use anyhow::bail;
use log::{error, info, warn};

fn inline_capture(user: &str, password: &str) {
    error!("login failed for {user} with {password}"); // expect: CA014 medium
}

fn positional(password: &str) {
    info!("password = {}", password); // expect: CA014 medium
}

fn encoded(secret_key: &[u8]) {
    info!("derived key = {}", hex::encode(secret_key)); // expect: CA014 high
}

fn field(cfg: &Config) {
    warn!("using {}", cfg.signing_key); // expect: CA014 medium
}

fn tracing_fields(api_key: &str, private_key: &[u8]) {
    tracing::debug!(token = %api_key, "calling the service"); // expect: CA014 medium
    tracing::trace!(?private_key); // expect: CA014 medium
}

fn explicit(token: &secrecy::SecretString) -> anyhow::Result<()> {
    bail!("rejected {}", token.expose_secret()) // expect: CA014 high
}

fn printed(secret_key: &[u8]) {
    println!("{}", hex::encode(secret_key)); // expect: CA014 medium
    dbg!(secret_key); // expect: CA014 medium
}

fn panics(seed: u64) {
    panic!("bad seed {}", seed); // expect: CA014 medium
}

#[tracing::instrument] // expect: CA014 medium
fn login(user: &str, password: &str) {}
