use log::{debug, info};
use secrecy::{ExposeSecret, SecretString};

const KEY_LEN: usize = 32;

fn lengths_and_ids(password: &str, key_id: u32, public_key: &[u8]) {
    info!("password has {} bytes", password.len());
    info!("using key {key_id}");
    debug!("public key {:x?}", public_key);
    info!("key length {}", KEY_LEN);
}

fn redacted(password: SecretString, api_key: SecretString) {
    info!("password = {:?}", password);
    info!("api key = {api_key:?}");
}

fn ciphertext(encrypted_key: &[u8], wrapped_secret_key: &[u8]) {
    debug!("{:x?} {:x?}", encrypted_key, wrapped_secret_key);
}

fn building_strings(user: &str, password: &str) -> String {
    // `format!` and `write!` build values for many legitimate purposes.
    format!("{user}:{password}")
}

fn target_and_parent(user: &str) {
    info!(target: "auth", "user {user} logged in");
}

#[tracing::instrument(skip(password))]
fn login(user: &str, password: &str) {}

#[tracing::instrument(skip_all)]
fn login_all(user: &str, password: &str) {}

#[tracing::instrument]
fn lookup(user: &str, key_id: u32) {}

struct Session {
    token: SecretString,
}

fn field_redacts(s: &Session) {
    info!("session {:?}", s.token);
}

// An integer is an id, a count or an enum discriminant, not key material.
fn ids(api_key_num: i16, seed: u64) {
    warn!("unknown request api: {api_key_num}");
    info!("seeding the RNG from {seed}");
}

// `ApiKey` is an enum built from a number; what a typed value prints is decided
// by its own `Debug`, which CA010 checks.
fn typed(buf: &mut Buf) {
    let api_key = ApiKey::try_from(buf.try_get_i16()?)?;
    debug!("request api {:?}", api_key);
}

fn temp_dir(private_tmp: &str) {
    warn!("failed to remove {}", private_tmp);
}
