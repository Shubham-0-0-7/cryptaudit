use cipher::KeyInit;

fn rc4_stream(key: &[u8]) {
    let _cipher = Rc4::new(key.into()); // expect: CA024 medium
}

fn des_block(key: &[u8]) {
    let _cipher = des::Des::new_from_slice(key).unwrap(); // expect: CA024 medium
}

fn triple_des(key: &[u8]) {
    let _cipher = TdesEde3::new_from_slice(key).unwrap(); // expect: CA024 medium
}

fn openssl_des() {
    let _c = openssl::symm::Cipher::des_ede3_cbc(); // expect: CA024 medium
}
