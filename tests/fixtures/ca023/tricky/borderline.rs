// `key` and `token` are also ordinary words (a map key, a lexer token): medium.
fn map_key(rng: &mut SmallRng) -> u32 {
    let mut rng = SmallRng::from_entropy();
    let key = rng.gen::<u32>(); // expect: CA023 medium
    key
}
