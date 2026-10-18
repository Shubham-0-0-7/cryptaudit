use subtle::ConstantTimeEq;

struct Users {
    password: Vec<u8>,
}

impl Users {
    // Constant-time comparison.
    fn check_user(&self, password: &[u8]) -> bool {
        self.password.ct_eq(password).into()
    }

    // Not a check: it records a change.
    fn set_password(&mut self, password: Vec<u8>) {
        if self.password != password {
            self.password = password;
        }
    }

    // Two things the caller passed, compared with each other: a confirmation field.
    fn validate_new_password(&self, password: &str, confirm_password: &str) -> bool {
        password == confirm_password
    }

    // A literal or a constant on the other side.
    fn verify_token(&self, token: &str) -> bool {
        token == "anonymous" || token == ANONYMOUS_TOKEN
    }

    // The name says it is not the secret itself.
    fn check_hash(&self, password_hash: &[u8]) -> bool {
        self.password == password_hash
    }

    // Does not return a decision.
    fn check_and_store(&mut self, password: &[u8]) {
        let same = self.password == password;
        let _ = same;
    }
}
