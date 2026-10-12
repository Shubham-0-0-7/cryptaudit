// Blind-evaluation false positives: a wrapper macro that wipes, a borrowed
// optional slice, and a `#[repr(C)]` value handed to C.
macro_rules! zeroize_call {
    ($e:expr) => {
        $e.zeroize()
    };
}

fn rekey(old_key: &[u8; 32]) {
    let mut new_key = [0u8; 32];
    new_key.copy_from_slice(old_key);
    use_key(&new_key);
    zeroize_call!(new_key);
}

pub struct Argon2<'key> {
    secret: Option<&'key [u8]>,
}

#[repr(C)]
pub struct x25519_key {
    pub key: [u8; 32],
}
