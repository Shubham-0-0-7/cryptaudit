// A weak generator with a constant seed and no visible use for secrets: this is
// what simulations, games and benchmarks look like. Reported at low confidence,
// hidden by default.
fn simulation() -> f64 {
    let mut rng = SmallRng::seed_from_u64(42); // expect: CA071 low
    rng.gen::<f64>()
}

// The same call when the generator makes a key: high, and also CA023 for the
// weak generator.
fn weak_key() -> [u8; 32] {
    let mut rng = SmallRng::seed_from_u64(42); // expect: CA071 high
    let key: [u8; 32] = rng.gen(); // expect: CA023 medium
    key
}
