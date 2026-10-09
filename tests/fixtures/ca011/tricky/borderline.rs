// A key *index* is not key material, even though the type name says key.
#[derive(Clone, Copy)]
struct KeyIndex(u32);

// Weak name, integer field: a counter named `token`. Reported at low confidence.
#[derive(Clone, Copy)] // expect: CA011 low
struct Cursor {
    token: u64,
}

// A weak type name wrapping an opaque type is a guess: not reported at all.
#[derive(Clone, Copy)]
struct Key {
    inner: Inner,
}
