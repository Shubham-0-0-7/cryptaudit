use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::time::{SystemTime, UNIX_EPOCH};

fn key() -> [u8; 32] {
    let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut rng = StdRng::seed_from_u64(seed); // expect: CA072 high
    let key: [u8; 32] = rng.gen();
    key
}

fn inline() -> [u8; 12] {
    let mut rng = StdRng::seed_from_u64(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64); // expect: CA072 high
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    nonce
}

fn instant() -> StdRng {
    StdRng::seed_from_u64(Instant::now().elapsed().as_nanos() as u64) // expect: CA072 medium
}
