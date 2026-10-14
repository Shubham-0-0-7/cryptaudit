use bitwarden_logging::instrument;
use log::{error, info};

const PASSWORD: &str = "password";

// A wrapper crate's `instrument` skips all arguments by default.
#[instrument(err)]
fn unlock(password: String) {}

#[bitwarden_logging::instrument]
fn derive(password: &str) {}

// The names of options are not values.
fn option_names() {
    error!("invalid `--{PASSWORD}`");
}

// Public material derived from a key.
fn public_part(key: &Key) {
    let derived_key = key.public_key();
    info!(?derived_key, "found a backup");
}

// A handle to a key.
fn slot(wrapping_key: SymmetricKeySlotId) {
    info!("unwrapping with {:?}", wrapping_key);
}

fn names(secret_names: Vec<SecretName>) {
    info!(?secret_names, "creating requests");
}
