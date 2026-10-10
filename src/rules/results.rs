//! CA018 and CA019: what the code does with the `Result` of a decrypt or verify
//! call. An authentication failure is expected input; it must be handled, and it
//! must not be thrown away.

use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, Pat, Stmt};

use super::{Rule, RuleMeta};
use crate::finding::{Confidence, Finding, Severity};
use crate::source::ParsedFile;

pub static UNWRAP_META: RuleMeta = RuleMeta {
    id: "CA018",
    name: "unwrap-on-crypto-result",
    severity: Severity::Medium,
    explain: "\
CA018: `.unwrap()` / `.expect()` on a decrypt or verify result

    let pt = cipher.decrypt(nonce, ct).unwrap();   // tampered ciphertext -> panic

An authentication failure is an expected outcome: it is the AEAD working
correctly. Turning it into a panic gives anyone who can send input a way to
crash the service by submitting garbage ciphertext.

Fix: propagate the error with `?` or map it to a protocol error.

Confidence:
  high    method names only used for authentication (`verify_slice`,
          `decrypt_in_place_detached`, `verify_strict`)
  medium  generic names (`decrypt`, `verify`, `open`), which a non-crypto
          type may also have
Key and nonce construction (`new_from_slice(..).unwrap()`) is not reported
here: that fails on a wrong length, not on attacker input.
",
};

pub static DISCARD_META: RuleMeta = RuleMeta {
    id: "CA019",
    name: "verification-result-discarded",
    severity: Severity::High,
    explain: "\
CA019: verification or decryption result discarded

    let _ = mac.verify_slice(tag);        // failure silently ignored
    cipher.decrypt_in_place(nonce, aad, &mut buf);
    mac.verify_slice(tag).ok();

The check is present in the source and absent in effect. It reads as verified
code in review, and forged data is accepted.

Fix: propagate the error with `?` or branch on it.

Reported forms: `let _ = <call>;`, `_ = <call>;`, a bare `<call>;`
statement and `<call>.ok();`. `<call>?;` is fine, because the error is
propagated. `if let Ok(_) = verify(..) { .. }` is not reported: it only
proceeds on success.
",
};

/// Methods whose `Result` carries an authentication outcome.
const STRONG: &[&str] = &[
    "verify_slice",
    "verify_strict",
    "verify_truncated_left",
    "verify_truncated_right",
    "verify_signature",
    "verify_tag",
    "decrypt_in_place",
    "decrypt_in_place_detached",
    "open_in_place",
    "open_detached",
    "decrypt_detached",
];

/// Generic names that a non-crypto type may also have.
const GENERIC: &[&str] = &["decrypt", "verify", "open", "unseal"];

fn crypto_result(method: &str) -> Option<Confidence> {
    if STRONG.contains(&method) {
        Some(Confidence::High)
    } else if GENERIC.contains(&method) {
        Some(Confidence::Medium)
    } else {
        None
    }
}

const BARE: &str = "bare statement";

pub struct UnwrapOnCrypto;
pub struct DiscardedVerify;

impl Rule for UnwrapOnCrypto {
    fn meta(&self) -> &'static RuleMeta {
        &UNWRAP_META
    }

    fn check(&self, file: &ParsedFile) -> Vec<Finding> {
        let mut v = UnwrapVisitor {
            file,
            out: Vec::new(),
        };
        v.visit_file(&file.ast);
        v.out
    }
}

impl Rule for DiscardedVerify {
    fn meta(&self) -> &'static RuleMeta {
        &DISCARD_META
    }

    fn check(&self, file: &ParsedFile) -> Vec<Finding> {
        let mut v = DiscardVisitor {
            file,
            out: Vec::new(),
        };
        v.visit_file(&file.ast);
        v.out
    }
}

struct UnwrapVisitor<'a> {
    file: &'a ParsedFile,
    out: Vec<Finding>,
}

impl<'ast> Visit<'ast> for UnwrapVisitor<'_> {
    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        let outer = call.method.to_string();
        if matches!(outer.as_str(), "unwrap" | "expect") {
            if let Expr::MethodCall(inner) = &*call.receiver {
                let name = inner.method.to_string();
                if let Some(confidence) = crypto_result(&name) {
                    self.out.push(self.file.finding(
                        &UNWRAP_META,
                        confidence,
                        call.method.span(),
                        format!(
                            "`.{outer}()` on `{name}(..)`: an authentication failure is expected input, and here it panics"
                        ),
                        "propagate the error with `?` or map it to a protocol error",
                    ));
                }
            }
        }
        visit::visit_expr_method_call(self, call);
    }
}

struct DiscardVisitor<'a> {
    file: &'a ParsedFile,
    out: Vec<Finding>,
}

impl DiscardVisitor<'_> {
    fn report(&mut self, call: &ExprMethodCall, how: &str) {
        let name = call.method.to_string();
        let Some(mut confidence) = crypto_result(&name) else {
            return;
        };
        // A bare `x.decrypt(..);` is often a unit-returning stream function
        // (and `rustc` already warns about an unused `Result`).
        if how == BARE && GENERIC.contains(&name.as_str()) {
            confidence = Confidence::Low;
        }
        self.out.push(self.file.finding(
            &DISCARD_META,
            confidence,
            call.method.span(),
            format!(
                "result of `{name}(..)` is discarded ({how}): a failed check is silently ignored"
            ),
            "propagate the error with `?` or branch on it",
        ));
    }

    /// `call`, or `call.ok()`, as the value being thrown away.
    fn check_discarded(&mut self, expr: &Expr, how: &str) {
        let Expr::MethodCall(call) = expr else { return };
        if call.method == "ok" {
            if let Expr::MethodCall(inner) = &*call.receiver {
                self.report(inner, &format!("`.ok()`, {how}"));
            }
        } else {
            self.report(call, how);
        }
    }
}

fn is_wild(pat: &Pat) -> bool {
    match pat {
        Pat::Wild(_) => true,
        Pat::Type(t) => is_wild(&t.pat),
        _ => false,
    }
}

impl<'ast> Visit<'ast> for DiscardVisitor<'_> {
    fn visit_stmt(&mut self, stmt: &'ast Stmt) {
        match stmt {
            Stmt::Local(local) => {
                if let Some(init) = &local.init {
                    if is_wild(&local.pat) {
                        self.check_discarded(&init.expr, "`let _ =`");
                    }
                }
            }
            Stmt::Expr(expr, Some(_)) => self.check_discarded(expr, BARE),
            _ => {}
        }
        visit::visit_stmt(self, stmt);
    }

    fn visit_expr_assign(&mut self, e: &'ast syn::ExprAssign) {
        if matches!(&*e.left, Expr::Infer(_)) {
            self.check_discarded(&e.right, "`_ =`");
        }
        visit::visit_expr_assign(self, e);
    }
}
