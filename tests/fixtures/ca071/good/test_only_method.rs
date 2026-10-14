use rand::SeedableRng;
use rand::rngs::StdRng;

struct Allocations {
    rng: StdRng,
}

impl Allocations {
    fn new(rng: &mut StdRng) -> Self {
        Self { rng: StdRng::from_rng(rng) }
    }

    // A test-only constructor is not production code.
    #[cfg(test)]
    fn for_test() -> Self {
        Self::new(&mut StdRng::seed_from_u64(0))
    }
}
