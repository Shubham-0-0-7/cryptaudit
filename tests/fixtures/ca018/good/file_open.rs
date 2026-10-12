// `open` on a file is not an authenticated decryption.
use std::fs::{File, OpenOptions};

fn touch(path: &str) {
    OpenOptions::new().write(true).open(path).unwrap();
    File::open(path).unwrap();
}
