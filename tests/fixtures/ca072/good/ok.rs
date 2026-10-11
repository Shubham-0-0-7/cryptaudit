use rand::SeedableRng;
use rand::rngs::StdRng;

fn entropy() -> StdRng {
    StdRng::from_entropy()
}

// Reading the clock for something else is fine.
fn log_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
