// Blind-evaluation false positives (snow, rust-openssl).
use chacha20poly1305::{aead::AeadInPlace, ChaCha20Poly1305};

macro_rules! copy_slices {
    ($inslice:expr, $outslice:expr) => {
        $outslice[..$inslice.len()].copy_from_slice(&$inslice[..])
    };
}

// The macro writes the counter into the nonce: it is not a constant.
fn encrypt(cipher: &ChaCha20Poly1305, counter: u64, buf: &mut [u8]) {
    let mut nonce_bytes = [0u8; 12];
    copy_slices!(counter.to_be_bytes(), &mut nonce_bytes[4..]);
    cipher.encrypt_in_place_detached(&nonce_bytes.into(), b"", buf).unwrap();
}

struct Ctx;

impl Ctx {
    fn encrypt(&self, from: &[u8], to: Option<&mut [u8]>) -> usize {
        0
    }

    // `self.encrypt(plaintext, ..)` is the type's own method, not an AEAD call.
    fn encrypt_to_vec(&self, from: &[u8], out: &mut Vec<u8>) {
        let len = self.encrypt(from, None);
        out.resize(len, 0);
        self.encrypt(from, Some(&mut out[..]));
    }
}
