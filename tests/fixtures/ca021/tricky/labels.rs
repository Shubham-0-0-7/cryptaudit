// A plural `tags` is a list of labels (routing tags, replica-set tags, HTML tags).
fn same_routing(a: &Frontend, b: &Frontend) -> bool {
    a.tags == b.tags
}

// The same generic name on both sides is two values of one kind compared for equality. Low.
fn same_digest(a: &Cert, b: &Cert) -> bool {
    a.material_digest == b.material_digest // expect: CA021 low
}

fn same_tag(a: &Packet, b: &Packet) -> bool {
    a.tag == b.tag // expect: CA021 low
}

// A tag that arrived against a tag computed here: different names, medium.
fn open(tag: &[u8], received_tag: &[u8]) -> bool {
    tag == received_tag // expect: CA021 medium
}
