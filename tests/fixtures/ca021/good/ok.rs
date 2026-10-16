use subtle::ConstantTimeEq;

fn constant_time(computed_mac: &[u8], expected_mac: &[u8]) -> bool {
    computed_mac.ct_eq(expected_mac).into()
}

fn library_verify(mut mac: Hmac<Sha256>, tag: &[u8]) -> bool {
    mac.verify_slice(tag).is_ok()
}

// Comparing lengths, or constants, is fine.
fn lengths(tag: &[u8], mac: &[u8]) -> bool {
    tag.len() == 16 && mac.len() == 32
}

fn literal(tag: &str) -> bool {
    tag == "div"
}

fn enum_tag(tag: Tag) -> bool {
    tag == Tag::Open
}

fn option(mac: Option<&[u8]>) -> bool {
    mac == None
}

// The constant-time primitive itself has to use a plain comparison.
fn ct_eq_bytes(computed_mac: &[u8], expected_mac: &[u8]) -> bool {
    let mut diff = 0u8;
    for (a, b) in computed_mac.iter().zip(expected_mac) {
        diff |= a ^ b;
    }
    diff == 0 && computed_mac.len() == expected_mac.len()
}

// Unrelated names.
fn unrelated(a: u32, b: u32, key_id: u32) -> bool {
    a == b && key_id == a
}

// Test-only code is not scanned.
#[cfg(test)]
mod tests {
    fn t(mac: &[u8], other_mac: &[u8]) -> bool {
        mac == other_mac
    }
}

// A generated id compared with another id is not a secret comparison.
fn same_id(gen: &Generator, id: u64) -> bool {
    gen.generate_id() == id
}

// `token` against a locally computed value that is not a code: no `generate`.
fn lexer_token(token: &Token, next: &Token) -> bool {
    token == next
}

// The constant-time version of the totp-rs fix.
fn check_ct(totp: &Totp, token: &str, step_time: u64) -> bool {
    constant_time_eq(totp.generate(step_time).as_bytes(), token.as_bytes())
}
