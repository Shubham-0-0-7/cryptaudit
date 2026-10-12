// A derive that only exists in test builds does not leak in production.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct PasswordHistory {
    pub password: String,
}
