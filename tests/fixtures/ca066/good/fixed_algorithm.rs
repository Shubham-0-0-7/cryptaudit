fn decode(token: &str, key: &DecodingKey) {
    let validation = Validation::new(Algorithm::RS256);
    let _ = jsonwebtoken::decode::<Claims>(token, key, &validation);
}

fn expiry_off_is_a_different_issue(validation: &mut Validation) {
    validation.validate_exp = false;
    validation.validate_signature = true;
}
