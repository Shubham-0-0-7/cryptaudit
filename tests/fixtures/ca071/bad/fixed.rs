use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

// A constant seed feeding a key: high.
fn key() -> [u8; 32] {
    let mut rng = StdRng::seed_from_u64(42); // expect: CA071 high
    let key: [u8; 32] = rng.gen();
    key
}

fn from_seed_bytes() -> [u8; 12] {
    let mut rng = StdRng::from_seed([7u8; 32]); // expect: CA071 high
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    nonce
}

const SEED: u64 = 1234;

fn through_const() -> [u8; 16] {
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(SEED); // expect: CA071 high
    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);
    salt
}

fn through_local() -> u64 {
    let seed = 99;
    let mut rng = StdRng::seed_from_u64(seed); // expect: CA071 high
    let secret = rng.gen::<u64>();
    secret
}

// A cryptographic generator seeded with a constant, with no visible use: medium.
fn crypto_rng_no_use() -> StdRng {
    StdRng::seed_from_u64(0) // expect: CA071 medium
}
