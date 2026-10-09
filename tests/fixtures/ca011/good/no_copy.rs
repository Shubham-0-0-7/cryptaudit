// Clone without Copy is allowed: the copy is explicit and visible.
#[derive(Clone)]
struct SessionKey([u8; 32]);

// Public and non-secret types may be Copy.
#[derive(Clone, Copy)]
struct PublicKey([u8; 32]);

#[derive(Clone, Copy)]
struct KeyId(u64);

#[derive(Clone, Copy)]
struct Nonce([u8; 12]);

#[derive(Clone, Copy, Debug)]
struct Point {
    x: u32,
    y: u32,
}

// Test-only code is not scanned.
#[cfg(test)]
mod tests {
    #[derive(Clone, Copy)]
    struct Fixture {
        secret_key: [u8; 32],
    }
}
