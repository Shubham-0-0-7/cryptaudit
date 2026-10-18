use std::collections::HashMap;

struct Users {
    users: HashMap<Vec<u8>, Vec<u8>>,
    password: String,
    api_token: String,
}

impl Users {
    // The [crate withheld] shape.
    fn check_user(&self, user_name: &[u8], password: &[u8]) -> bool {
        match self.users.get(user_name) {
            Some(pwd) => pwd == password.as_ref(), // expect: CA029 medium
            None => false,
        }
    }

    fn verify_password(&self, password: &str) -> bool {
        self.password == password // expect: CA029 medium
    }

    fn validate_token(&self, token: &str) -> Result<bool, Error> {
        Ok(token == self.api_token.as_str()) // expect: CA029 medium
    }

    fn is_valid(&self, secret: &[u8]) -> bool {
        let stored = self.lookup();
        secret != stored // expect: CA029 medium
    }
}

fn authenticate(db: &Db, user: &str, password: &str) -> bool {
    let stored = db.password_for(user);
    stored == password // expect: CA029 medium
}
