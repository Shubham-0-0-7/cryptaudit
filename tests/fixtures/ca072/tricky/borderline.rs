// A time-seeded weak generator used for shuffling: common, not a vulnerability.
fn shuffle(v: &mut Vec<u32>) {
    let mut rng = SmallRng::seed_from_u64(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()); // expect: CA072 low
    v.swap(0, rng.gen_range(0..v.len()));
}
