// Only a name with ECB in it, and no constructor: low, hidden by default.
fn header_protection_mask(sample: &[u8]) {
    AES_ecb_encrypt(sample); // expect: CA025 low
}

enum Mode {
    Ecb,
}

fn pick() -> Mode {
    Mode::Ecb // expect: CA025 low
}
