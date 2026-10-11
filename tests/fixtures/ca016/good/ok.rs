use zeroize::Zeroize;

fn proper(mut key: [u8; 32]) {
    key.zeroize();
}

// Both: the volatile wipe is there, the extra fill is harmless.
fn both(mut key: [u8; 32]) {
    key.fill(0);
    key.zeroize();
}

struct Holder {
    private_key: [u8; 32],
}

impl Drop for Holder {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

// Zeroing something that is not a secret.
fn reset(mut buffer: Vec<u8>, mut counts: [u32; 16]) {
    buffer.fill(0);
    counts.fill(0);
}

fn clear_scratch(mut scratch: [u8; 64]) {
    for b in scratch.iter_mut() {
        *b = 0;
    }
}

// Filling with something other than zero.
fn fill_ones(mut key: [u8; 32]) {
    key.fill(1);
}
