use subtle::ConstantTimeEq;

fn good(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

// The file uses constant-time comparison elsewhere, so this may be a deliberate
// exception; reported at low confidence.
fn check_old_users(db: &Db, user: &str, password: &str) -> bool {
    let stored = db.password_for(user);
    stored == password // expect: CA029 low
}
