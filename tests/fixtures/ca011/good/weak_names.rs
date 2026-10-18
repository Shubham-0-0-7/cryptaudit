// `sighash` sits in a type whose name only says `key`: a cache key, not key material.
#[derive(Clone, Copy)] // expect: CA011 low
struct CacheKey {
    sighash: [u8; 32],
    index: u32,
}
