//! CA029: a password or token from the caller compared with `==`.
//!
//! CA021 knows MACs by name. A login check has no MAC in it: the function
//! receives `password` and compares it with the stored one. This rule looks for
//! exactly that, in a function that is named like a check.

use std::collections::HashSet;

use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, FnArg, ImplItemFn, ItemFn, Pat, ReturnType, Signature, Type};

use super::{Rule, RuleMeta};
use crate::finding::{Confidence, Finding, Severity};
use crate::secret::{has_constant_time_call, words};
use crate::source::ParsedFile;

pub static META: RuleMeta = RuleMeta {
    id: "CA029",
    name: "password-compared-with-eq",
    severity: Severity::High,
    explain: "\
CA029: password or token from the caller compared with `==`

    fn check_user(&self, name: &[u8], password: &[u8]) -> bool {
        match self.users.get(name) {
            Some(stored) => stored == password,
            None => false,
        }
    }

`==` on two byte strings stops at the first byte that differs. A comparison
that fails on the first byte is a little faster than one that fails on the
tenth. Over a network that difference is tiny, but it can be measured by
repeating the request many times and averaging. An attacker who can submit
unlimited guesses can find the first character by trying every possibility and
keeping the slowest, then the second, and so on. This is a timing attack, and
it works against real login endpoints, API-key checks and token checks.

The fix is a comparison that always takes the same time, whatever the bytes:
`subtle::ConstantTimeEq` (`a.ct_eq(b)`), or, better, store a password hash and
use the hashing library's `verify`.

Reported when all of these hold:
  * the function is named like a check (`check_user`, `verify_token`,
    `authenticate`, `login`, `is_valid`, `matches`);
  * one side of `==` / `!=` is a parameter named `password`, `passwd`,
    `passphrase`, `secret`, `token` or similar: the value the caller presented;
  * the other side is not a parameter, a literal or a constant: it is the
    stored value, looked up or read from `self`.

Not reported: two parameters compared with each other (a \"confirm password\"
form field), a comparison against a literal, a file that already uses a
constant-time comparison (low instead), and names that say `hash`, `len`,
`field`, `name` or similar.

Confidence:
  medium  the pattern above
  low     the same, in a file that also calls `ct_eq` or another constant-time
          comparison somewhere

Known false positives: a function that compares settings it is changing
(`set_password` is not a check, so it is not reported, but `matches` on a config
struct is), and values that are not secret.
",
};

pub struct PasswordEq;

impl Rule for PasswordEq {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, file: &ParsedFile) -> Vec<Finding> {
        let mut v = Visitor {
            file,
            params: Vec::new(),
            checking: Vec::new(),
            ct: has_constant_time_call(&file.source),
            out: Vec::new(),
        };
        v.visit_file(&file.ast);
        v.out
    }
}

/// Function names that say the function decides whether a credential is right.
fn is_check_name(name: &str) -> bool {
    words(name).iter().any(|w| {
        matches!(
            w.as_str(),
            "check"
                | "verify"
                | "validate"
                | "authenticate"
                | "auth"
                | "login"
                | "matches"
                | "compare"
                | "authorize"
                | "authorise"
                | "valid"
                | "correct"
                | "equals"
        )
    })
}

/// A name that holds the credential the caller presented.
fn is_credential_name(name: &str) -> bool {
    let ws = words(name);
    ws.iter().any(|w| {
        matches!(
            w.as_str(),
            "password" | "passwd" | "passphrase" | "passcode" | "secret" | "token" | "apikey"
        )
    }) && !ws.iter().any(|w| {
        matches!(
            w.as_str(),
            "hash"
                | "hashed"
                | "len"
                | "length"
                | "field"
                | "name"
                | "label"
                | "prompt"
                | "policy"
                | "strength"
                | "file"
                | "path"
                | "env"
                | "var"
                | "variable"
                | "url"
                | "id"
                | "type"
                | "kind"
                | "count"
                | "index"
                | "salt"
        )
    })
}

/// Peels references, parentheses and representation changes: `password.as_ref()`,
/// `&password[..]`, `password.as_bytes()`.
fn peel(expr: &Expr) -> &Expr {
    match expr {
        Expr::Reference(r) => peel(&r.expr),
        Expr::Paren(p) => peel(&p.expr),
        Expr::Group(g) => peel(&g.expr),
        Expr::Index(i) => peel(&i.expr),
        Expr::Unary(u) => peel(&u.expr),
        Expr::MethodCall(m)
            if matches!(
                m.method.to_string().as_str(),
                "as_ref"
                    | "as_bytes"
                    | "as_slice"
                    | "as_str"
                    | "to_vec"
                    | "to_string"
                    | "to_owned"
                    | "clone"
                    | "borrow"
                    | "deref"
                    | "expose_secret"
                    | "unwrap"
            ) =>
        {
            peel(&m.receiver)
        }
        other => other,
    }
}

/// The variable at the root of an expression: `password`, `self` in `self.password`.
fn root(expr: &Expr) -> Option<String> {
    match peel(expr) {
        Expr::Path(p) => p.path.get_ident().map(ToString::to_string),
        Expr::Field(f) => root(&f.base),
        Expr::MethodCall(m) => root(&m.receiver),
        _ => None,
    }
}

/// A side that is clearly not a runtime value: a literal, or a constant-like path.
fn is_constant_like(expr: &Expr) -> bool {
    match peel(expr) {
        Expr::Lit(_) => true,
        Expr::Path(p) => {
            let segs = &p.path.segments;
            segs.len() > 1
                || segs.last().is_some_and(|s| {
                    let n = s.ident.to_string();
                    n == "None" || !n.chars().any(char::is_lowercase)
                })
        }
        _ => false,
    }
}

struct Visitor<'a> {
    file: &'a ParsedFile,
    /// Parameter names of the function being visited, innermost last.
    params: Vec<HashSet<String>>,
    /// Whether the function being visited is named like a check.
    checking: Vec<bool>,
    ct: bool,
    out: Vec<Finding>,
}

fn param_names(sig: &Signature) -> HashSet<String> {
    sig.inputs
        .iter()
        .filter_map(|a| match a {
            FnArg::Typed(t) => match &*t.pat {
                Pat::Ident(i) => Some(i.ident.to_string()),
                _ => None,
            },
            FnArg::Receiver(_) => None,
        })
        .collect()
}

/// `bool`, `Result<bool, _>` or `Option<bool>`: the function answers yes or no.
fn returns_decision(sig: &Signature) -> bool {
    let ReturnType::Type(_, ty) = &sig.output else {
        return false;
    };
    let Type::Path(p) = &**ty else {
        return false;
    };
    let Some(last) = p.path.segments.last() else {
        return false;
    };
    match last.ident.to_string().as_str() {
        "bool" => true,
        "Result" | "Option" => {
            matches!(&last.arguments, syn::PathArguments::AngleBracketed(a)
                if a.args.iter().next().is_some_and(|g| matches!(g,
                    syn::GenericArgument::Type(Type::Path(t)) if t.path.is_ident("bool"))))
        }
        _ => false,
    }
}

impl Visitor<'_> {
    fn enter(&mut self, sig: &Signature) {
        self.params.push(param_names(sig));
        self.checking
            .push(is_check_name(&sig.ident.to_string()) && returns_decision(sig));
    }

    fn leave(&mut self) {
        self.params.pop();
        self.checking.pop();
    }
}

impl<'ast> Visit<'ast> for Visitor<'_> {
    fn visit_item_fn(&mut self, f: &'ast ItemFn) {
        self.enter(&f.sig);
        visit::visit_item_fn(self, f);
        self.leave();
    }

    fn visit_impl_item_fn(&mut self, f: &'ast ImplItemFn) {
        self.enter(&f.sig);
        visit::visit_impl_item_fn(self, f);
        self.leave();
    }

    fn visit_expr_binary(&mut self, e: &'ast ExprBinary) {
        if matches!(e.op, BinOp::Eq(_) | BinOp::Ne(_)) && self.checking.last() == Some(&true) {
            let params = self.params.last().cloned().unwrap_or_default();
            let presented = |x: &Expr| {
                root(x).is_some_and(|r| params.contains(&r) && is_credential_name(&r))
                    && matches!(peel(x), Expr::Path(_))
            };
            let stored = |x: &Expr| {
                !is_constant_like(x)
                    && root(x).is_none_or(|r| !params.contains(&r) || r == "self")
                    && !presented(x)
            };
            let hit = (presented(&e.left) && stored(&e.right))
                || (presented(&e.right) && stored(&e.left));
            if hit {
                let name = [&e.left, &e.right]
                    .into_iter()
                    .find(|x| presented(x))
                    .and_then(|x| root(x))
                    .unwrap_or_default();
                let op = if matches!(e.op, BinOp::Eq(_)) {
                    "=="
                } else {
                    "!="
                };
                let confidence = if self.ct {
                    Confidence::Low
                } else {
                    Confidence::Medium
                };
                self.out.push(self.file.finding(
                    &META,
                    confidence,
                    e.op.span(),
                    format!(
                        "`{name}` from the caller is compared with `{op}`, which stops at the first different byte: an attacker who can try many guesses can recover it one character at a time by timing the replies"
                    ),
                    "compare with `subtle::ConstantTimeEq` (`a.ct_eq(b)`), or store a password hash and use the hashing library's `verify`",
                ));
            }
        }
        visit::visit_expr_binary(self, e);
    }
}
