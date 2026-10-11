use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

fn entropy() -> StdRng {
    StdRng::from_entropy()
}

fn seed_from_caller(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

fn seed_from_os() -> StdRng {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    StdRng::from_seed(seed)
}
