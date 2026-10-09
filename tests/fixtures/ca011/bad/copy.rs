#[derive(Clone, Copy)] // expect: CA011 high
struct SessionKey([u8; 32]);

#[derive(Clone, Copy)] // expect: CA011 high
struct Seed {
    seed: [u8; 64],
}

#[derive(Copy, Clone)] // expect: CA011 high
pub struct SigningKey {
    bytes: [u8; 32],
    index: u32,
}

#[derive(Clone, Copy)] // expect: CA011 high
enum Material {
    Raw { master_key: [u8; 32] },
    Empty,
}
