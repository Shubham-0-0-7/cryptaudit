type Aes128EcbEnc = ecb::Encryptor<aes::Aes128>; // expect: CA025 high

fn openssl_ecb() {
    let _c = openssl::symm::Cipher::aes_128_ecb(); // expect: CA025 high
}

fn block_modes_ecb() {
    type Aes128Ecb = Ecb<Aes128, Pkcs7>; // expect: CA025 high
    let _ = Aes128Ecb::new_from_slices(&[0; 16], &[]); // expect: CA025 low
}
