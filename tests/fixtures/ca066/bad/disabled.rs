fn decode_without_checking(token: &str) {
    let _ = jsonwebtoken::dangerous_insecure_decode::<Claims>(token); // expect: CA066 high
}

fn no_signature(validation: &mut Validation) {
    validation.insecure_disable_signature_validation(); // expect: CA066 high
}

fn field_off(validation: &mut Validation) {
    validation.validate_signature = false; // expect: CA066 high
}

fn algorithm_from_token(token: &str) {
    let header = jsonwebtoken::decode_header(token).unwrap();
    let _validation = Validation::new(header.alg); // expect: CA066 medium
}
