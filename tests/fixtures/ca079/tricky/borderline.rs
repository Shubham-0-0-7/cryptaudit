// CTR with a constant IV is also wrong, but it is reported as CA027, not CA079.
fn ctr_const_iv(key: &[u8; 16]) {
    let c = ctr::Ctr64BE::<aes::Aes128>::new(key.into(), &[0u8; 16].into()); // expect: CA027 high
}
