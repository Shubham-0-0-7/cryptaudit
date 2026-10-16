use std::fmt;

// The closure keeps the value: only a closure that returns a literal redacts.
// Medium, because the field is formatted through a method chain.
struct Session {
    token: Option<String>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("token", &self.token.as_ref().map(|t| t.as_str())) // expect: CA010 medium
            .finish()
    }
}
