// `ShoHmacSha256::new(label)` takes a domain-separation label, not a key.
fn derive(randomness: &[u8]) {
    let mut sho = ShoHmacSha256::new(b"Signal_ZKCredential_Presentation_20230410");
    sho.absorb_and_ratchet(randomness);
}
