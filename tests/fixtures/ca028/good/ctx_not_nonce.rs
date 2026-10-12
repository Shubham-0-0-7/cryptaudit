// `value.encrypt(ctx, key)`: `ctx` is a key-store context, not a nonce.
fn encrypt_all(values: &[Value], ctx: &mut Ctx, key: KeyId) {
    for value in values {
        value.encrypt(ctx, key);
    }
}
