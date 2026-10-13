// Round 3: the buffer is read again after the zeroing, so the stores are not dead.
fn reset_counter(sk: &mut [u8], idx_bytes: usize, seed: &[u8]) {
    for b in sk[..idx_bytes].iter_mut() {
        *b = 0;
    }
    sk[idx_bytes..].copy_from_slice(seed);
}
