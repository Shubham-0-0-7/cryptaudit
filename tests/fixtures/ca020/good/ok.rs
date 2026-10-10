fn lengths(tag: &[u8], mac: &[u8]) {
    assert_eq!(tag.len(), 16);
    assert_eq!(mac.len(), 32);
}

fn constants(tag: Tag) {
    assert_eq!(tag, Tag::Open);
    assert_eq!(1 + 1, 2);
}

fn unrelated(a: u32, b: u32) {
    assert_eq!(a, b);
}

#[cfg(test)]
mod tests {
    #[test]
    fn roundtrip() {
        let mac = compute();
        assert_eq!(mac, compute());
    }
}
