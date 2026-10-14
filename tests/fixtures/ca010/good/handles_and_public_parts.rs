// A handle addresses a secret held elsewhere; it is not the secret.
#[derive(Debug, Clone)]
pub struct HandleToSecret(Vec<u8>);

#[derive(Debug)]
struct SlotRef {
    key_slot: u32,
    key_handle: Vec<u8>,
}

// `e` is the RSA public exponent, whatever the type is called.
#[derive(Debug, Clone)]
pub struct CoseRsaKey {
    pub n: HumanBinaryData,
    pub e: [u8; 3],
}
