// Round 3: neither an empty tweak nor a text label is a nonce.
fn ff1(ff1: &FF1, input: &Numeral) {
    let _ = ff1.encrypt(&[], input);
}

fn dummy(device: &Device) {
    let _ = device.encrypt("m.dummy", Content::new());
}

fn hpke(node: &Node, crypto: &Crypto, suite: Suite) {
    let _ = node.encrypt(crypto, suite);
}
