use rand::rngs::{OsRng, StdRng};
use rand::{Rng, RngCore, SeedableRng, thread_rng};

fn os() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

// ThreadRng is documented as cryptographically secure.
fn thread() -> [u8; 32] {
    let mut rng = thread_rng();
    let key: [u8; 32] = rng.gen();
    key
}

fn std_rng() -> [u8; 12] {
    let mut rng = StdRng::from_entropy();
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    nonce
}

fn random_fn() -> u64 {
    let secret: u64 = rand::random();
    secret
}

// A weak generator for something that is not a secret.
fn shuffle(items: &mut Vec<u32>) {
    let mut rng = SmallRng::from_entropy();
    let index = rng.gen_range(0..items.len());
    let jitter = rng.gen::<f64>();
    items.swap(0, index);
}

fn dice() -> u8 {
    fastrand::u8(1..=6)
}

// Metadata about a secret is not a secret.
fn lengths() -> usize {
    let mut rng = SmallRng::from_entropy();
    let key_len = rng.gen_range(16..64);
    let nonce_size = rng.gen_range(8..16);
    key_len + nonce_size
}
