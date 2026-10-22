//! CA020 and CA021: MAC, tag and digest values compared with a non-constant-time
//! operator. Both rules share one question: "does this expression hold a MAC?".

use std::collections::HashMap;

use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, ExprBinary, ItemFn, Macro, Token};

use super::{Rule, RuleMeta};
use crate::finding::{Confidence, Finding, Severity};
use crate::secret::{is_excluded, words};
use crate::source::ParsedFile;

pub static EQ_META: RuleMeta = RuleMeta {
    id: "CA021",
    name: "mac-compared-with-eq",
    severity: Severity::High,
    explain: "\
CA021: MAC, tag or digest compared with `==` / `!=`

Slice and array equality stops at the first differing byte. When the left
side is a MAC computed from attacker-supplied data, the time the check takes
tells the attacker how many leading bytes of their guess were right, so the
tag can be recovered one byte at a time.

    if computed.finalize().as_slice() == expected { .. }
    if derived_mac.as_slice() != keystore.mac.as_slice() { .. }

Fix: `subtle::ConstantTimeEq::ct_eq`, or the crate's own verifier such as
`Mac::verify_slice`.

Confidence:
  high    one side is the output of `.finalize()`, `.digest()` or similar
  medium  both sides are named like MACs (`derived_mac`, `stored_hmac`), or
          one side is named `mac`/`hmac`
  low     only a generic name such as `tag` or `digest`; two such names are
          medium only if they differ (`tag` against `received_tag`: a computed
          value against a presented one), and `self.tag == other.tag` is low.
          A plural `tags` is a list of labels and is not considered
A second shape is a one-time code: a value produced by `generate`, `compute`
or `calculate` compared with a parameter named `token`, `code`, `otp` or
`signature`. That is medium confidence, and it needs both halves.

    if self.generate(step_time) == token { .. }   // totp-rs before 1.1.0

Comparisons against a literal or an enum/const path (`tag == \"div\"`,
`kind == Tag::Open`) are never reported, and neither are the bodies of
functions named like `ct_eq` or `constant_time_*`.

Known false positives: `tag` or `digest` used for something that is not a
MAC, such as an HTML tag or a git tag.
",
};

pub static ASSERT_META: RuleMeta = RuleMeta {
    id: "CA020",
    name: "assert-eq-on-mac",
    severity: Severity::Medium,
    explain: "\
CA020: `assert_eq!` / `assert_ne!` on a MAC or tag

Two defects at once. The comparison is not constant time (see CA021), and on
failure the panic message prints both the expected and the actual tag, which
hands the attacker the correct value.

    assert_eq!(computed_mac, expected_mac);

Fix: compare with `ct_eq` and turn the result into an error that does not
include either value. Test code is not scanned by default.
",
};

pub struct MacEq;
pub struct MacAssert;

impl Rule for MacEq {
    fn meta(&self) -> &'static RuleMeta {
        &EQ_META
    }

    fn check(&self, file: &ParsedFile) -> Vec<Finding> {
        let mut v = EqVisitor {
            file,
            env: Env::new(),
            ct_depth: 0,
            out: Vec::new(),
        };
        v.visit_file(&file.ast);
        v.out
    }
}

impl Rule for MacAssert {
    fn meta(&self) -> &'static RuleMeta {
        &ASSERT_META
    }

    fn check(&self, file: &ParsedFile) -> Vec<Finding> {
        let mut v = AssertVisitor {
            file,
            env: Env::new(),
            ct_depth: 0,
            out: Vec::new(),
        };
        v.visit_file(&file.ast);
        v.out
    }
}

/// How we know an expression holds a MAC. Ordered weakest to strongest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Evidence {
    /// Named `tag` or `digest`: common outside cryptography.
    Weak,
    /// Named `mac` or `hmac`.
    Strong,
    /// Produced by `.finalize()`, `.digest()` and similar.
    Api,
}

/// Methods that return a MAC or digest.
const API_METHODS: &[&str] = &[
    "finalize",
    "finalize_fixed",
    "finalize_reset",
    "finalize_fixed_reset",
    "digest",
    "compute_tag",
    "calculate_tag",
    "generate_tag",
    "compute_mac",
];

/// Methods that change representation but keep the value.
const PASS_THROUGH: &[&str] = &[
    "as_slice",
    "as_ref",
    "as_bytes",
    "as_mut",
    "to_vec",
    "to_bytes",
    "into_bytes",
    "into",
    "clone",
    "borrow",
    "deref",
    "to_owned",
    "as_array",
    "to_hex",
    "encode_hex",
    "to_base64",
    "unwrap",
    "expect",
];

/// Functions that re-encode their first argument.
const ENCODERS: &[&str] = &["encode", "to_hex", "encode_hex", "to_string"];

fn name_evidence(name: &str) -> Option<Evidence> {
    if is_excluded(name) {
        return None;
    }
    let ws = words(name);
    let has = |list: &[&str]| ws.iter().any(|w| list.contains(&w.as_str()));
    if has(&["mac", "hmac", "cmac", "poly1305", "ghash"]) {
        Some(Evidence::Strong)
    } else if has(&["tag", "digest"]) && !has(&["key"]) {
        // `key_tag` is a DNSSEC identifier, not an authentication tag. A plural
        // `tags` is a list of labels (HTML, replica-set, routing tags), never one MAC.
        Some(Evidence::Weak)
    } else {
        None
    }
}

fn evidence(expr: &Expr, env: &Env) -> Option<Evidence> {
    match expr {
        Expr::Reference(e) => evidence(&e.expr, env),
        Expr::Paren(e) => evidence(&e.expr, env),
        Expr::Group(e) => evidence(&e.expr, env),
        Expr::Unary(e) => evidence(&e.expr, env),
        Expr::Try(e) => evidence(&e.expr, env),
        Expr::Cast(e) => evidence(&e.expr, env),
        Expr::Index(e) => evidence(&e.expr, env),
        Expr::Field(e) => match &e.member {
            syn::Member::Named(n) => name_evidence(&n.to_string()),
            syn::Member::Unnamed(_) => evidence(&e.base, env),
        },
        Expr::Path(p) => {
            let ident = p.path.get_ident()?.to_string();
            // A local bound from a MAC-producing call keeps that evidence.
            env.get(&ident).copied().max(name_evidence(&ident))
        }
        Expr::MethodCall(c) => {
            let method = c.method.to_string();
            if API_METHODS.contains(&method.as_str()) {
                // `sha.finalize()` is an unkeyed hash of data the attacker may
                // already know, not a MAC.
                if is_unkeyed_hasher(&c.receiver) {
                    Some(Evidence::Weak)
                } else {
                    Some(Evidence::Api)
                }
            } else if PASS_THROUGH.contains(&method.as_str()) {
                evidence(&c.receiver, env)
            } else if ENCODERS.contains(&method.as_str()) {
                c.args.first().and_then(|a| evidence(a, env))
            } else {
                // `compute_hmac(..)`: the method name itself may say it.
                match name_evidence(&method) {
                    Some(Evidence::Strong) => Some(Evidence::Strong),
                    _ => None,
                }
            }
        }
        Expr::Call(c) => {
            let Expr::Path(f) = &*c.func else { return None };
            let last = f.path.segments.last()?.ident.to_string();
            if API_METHODS.contains(&last.as_str()) {
                // `Sha256::digest(data)` hashes data the attacker may already know
                // (a certificate, a download), so it is not a MAC; `Hmac::finalize(mac)` is.
                let hash_fn = f.path.segments.len() >= 2 && {
                    let ty = f.path.segments[f.path.segments.len() - 2]
                        .ident
                        .to_string()
                        .to_lowercase();
                    [
                        "sha",
                        "md5",
                        "md4",
                        "blake",
                        "ripemd",
                        "whirlpool",
                        "digest",
                    ]
                    .iter()
                    .any(|h| ty.starts_with(h))
                };
                Some(if hash_fn {
                    Evidence::Weak
                } else {
                    Evidence::Api
                })
            } else if ENCODERS.contains(&last.as_str()) {
                c.args.first().and_then(|a| evidence(a, env))
            } else {
                match name_evidence(&last) {
                    Some(Evidence::Strong) => Some(Evidence::Strong),
                    _ => None,
                }
            }
        }
        _ => None,
    }
}

/// `self.sha`: a hash state kept in a struct field, fed with data as it streams
/// past (a downloaded file, an attachment). A local `hasher` is not covered: it
/// is often fed a password, and comparing that hash is a real timing leak.
fn is_unkeyed_hasher(receiver: &Expr) -> bool {
    match receiver {
        Expr::Field(f) => match &f.member {
            syn::Member::Named(n) => {
                let ws = words(&n.to_string());
                let has = |list: &[&str]| ws.iter().any(|w| list.contains(&w.as_str()));
                has(&[
                    "sha", "sha1", "sha2", "sha3", "sha256", "sha512", "md5", "blake", "blake2",
                    "blake3",
                ]) && !has(&["mac", "hmac", "cmac"])
            }
            syn::Member::Unnamed(_) => false,
        },
        Expr::Reference(r) => is_unkeyed_hasher(&r.expr),
        Expr::Paren(p) => is_unkeyed_hasher(&p.expr),
        _ => false,
    }
}

/// Locals whose value came from a MAC-producing expression, by name.
type Env = HashMap<String, Evidence>;

/// Records `let x = <expr with evidence>;` so a later `x == y` is understood.
fn record_local(env: &mut Env, local: &syn::Local) {
    let pat = match &local.pat {
        syn::Pat::Type(t) => &*t.pat,
        other => other,
    };
    if let (Some(init), syn::Pat::Ident(bound)) = (&local.init, pat) {
        // Only calls to MAC APIs promote a name; a name alone adds nothing.
        if let Some(Evidence::Api) = evidence(&init.expr, env) {
            env.insert(bound.ident.to_string(), Evidence::Api);
        }
    }
}

/// A side that is clearly not a runtime MAC: a literal, or a path to a constant
/// or enum variant (`Tag::Open`, `None`).
fn is_constant_like(expr: &Expr) -> bool {
    match expr {
        Expr::Lit(_) => true,
        Expr::Reference(e) => is_constant_like(&e.expr),
        Expr::Paren(e) => is_constant_like(&e.expr),
        Expr::Path(p) => {
            p.path.segments.len() > 1
                || p.path
                    .get_ident()
                    .is_some_and(|i| i.to_string().starts_with(|c: char| c.is_uppercase()))
        }
        _ => false,
    }
}

/// Confidence of a comparison between two expressions, or `None` if it is not
/// a MAC comparison.
fn compare_confidence(a: &Expr, b: &Expr, env: &Env) -> Option<Confidence> {
    if is_constant_like(a) || is_constant_like(b) {
        return None;
    }
    let (ea, eb) = (evidence(a, env), evidence(b, env));
    let Some(best) = ea.max(eb) else {
        // No MAC evidence: a freshly computed code against a presented one.
        return is_code_check(a, b).then_some(Confidence::Medium);
    };
    let both = ea.is_some() && eb.is_some();
    Some(match best {
        Evidence::Api => Confidence::High,
        Evidence::Strong if both => Confidence::High,
        Evidence::Strong => Confidence::Medium,
        // The same generic name on both sides (`self.tag == other.tag`) is two values
        // of one kind being compared for equality, not a presented tag against a
        // computed one.
        Evidence::Weak if both && terminal_name(a) != terminal_name(b) => Confidence::Medium,
        Evidence::Weak => Confidence::Low,
    })
}

/// The last name in a field access or path: `tag` in `self.tag`, `received` in `received`.
fn terminal_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Reference(e) => terminal_name(&e.expr),
        Expr::Paren(e) => terminal_name(&e.expr),
        Expr::Unary(e) => terminal_name(&e.expr),
        Expr::MethodCall(c) if PASS_THROUGH.contains(&c.method.to_string().as_str()) => {
            terminal_name(&c.receiver)
        }
        Expr::Field(f) => match &f.member {
            syn::Member::Named(n) => Some(n.to_string()),
            syn::Member::Unnamed(_) => None,
        },
        Expr::Path(p) => p.path.get_ident().map(ToString::to_string),
        _ => None,
    }
}

/// A code worked out locally compared with one the user sent.
fn is_code_check(a: &Expr, b: &Expr) -> bool {
    computed_code(a) && presented_code(b) || computed_code(b) && presented_code(a)
}

/// `self.generate(t)`, `compute_code(..)`: a code worked out locally, to be
/// checked against what the user sent.
fn computed_code(expr: &Expr) -> bool {
    let name = match expr {
        Expr::Reference(e) => return computed_code(&e.expr),
        Expr::Paren(e) => return computed_code(&e.expr),
        Expr::Try(e) => return computed_code(&e.expr),
        Expr::MethodCall(c) => {
            let m = c.method.to_string();
            if PASS_THROUGH.contains(&m.as_str()) || matches!(m.as_str(), "to_string" | "as_str") {
                return computed_code(&c.receiver);
            }
            m
        }
        Expr::Call(c) => match &*c.func {
            Expr::Path(f) => match f.path.segments.last() {
                Some(seg) => seg.ident.to_string(),
                None => return false,
            },
            _ => return false,
        },
        _ => return false,
    };
    let ws = words(&name);
    ws.iter()
        .any(|w| matches!(w.as_str(), "generate" | "compute" | "calculate"))
        && !ws.iter().any(|w| {
            matches!(
                w.as_str(),
                "id" | "uuid" | "nonce" | "key" | "salt" | "random"
            )
        })
}

/// A parameter or field named like a code the user typed or sent.
fn presented_code(expr: &Expr) -> bool {
    let name = match expr {
        Expr::Reference(e) => return presented_code(&e.expr),
        Expr::Paren(e) => return presented_code(&e.expr),
        Expr::MethodCall(c) if PASS_THROUGH.contains(&c.method.to_string().as_str()) => {
            return presented_code(&c.receiver);
        }
        Expr::Path(p) => match p.path.get_ident() {
            Some(i) => i.to_string(),
            None => return false,
        },
        Expr::Field(f) => match &f.member {
            syn::Member::Named(n) => n.to_string(),
            syn::Member::Unnamed(_) => return false,
        },
        _ => return false,
    };
    !is_excluded(&name)
        && words(&name).iter().any(|w| {
            matches!(
                w.as_str(),
                "token" | "code" | "otp" | "totp" | "hotp" | "passcode" | "signature" | "sig"
            )
        })
}

/// A crate that implements `PartialEq` with `ct_eq` (orion, `subtle`-based newtypes)
/// compares its own tag types in constant time, so `tag_a == tag_b` between two
/// such values is fine. Only an explicit conversion to raw bytes is still suspect.
fn ct_adjusted(file: &ParsedFile, a: &Expr, b: &Expr, c: Confidence) -> Confidence {
    if file.ct_partialeq && !(shows_raw_bytes(a) || shows_raw_bytes(b)) {
        c.min(Confidence::Low)
    } else {
        c
    }
}

fn shows_raw_bytes(expr: &Expr) -> bool {
    match expr {
        Expr::Reference(e) => shows_raw_bytes(&e.expr),
        Expr::Paren(e) => shows_raw_bytes(&e.expr),
        Expr::Unary(e) => shows_raw_bytes(&e.expr),
        Expr::Try(e) => shows_raw_bytes(&e.expr),
        Expr::Index(_) => true,
        Expr::MethodCall(c) => {
            matches!(
                c.method.to_string().as_str(),
                "as_slice" | "as_ref" | "as_bytes" | "to_bytes" | "into_bytes" | "to_vec"
            ) || shows_raw_bytes(&c.receiver)
        }
        _ => false,
    }
}

fn is_constant_time_fn(name: &str) -> bool {
    name.contains("ct_eq") || name.contains("constant_time") || name.starts_with("ct_")
}

struct EqVisitor<'a> {
    file: &'a ParsedFile,
    env: Env,
    ct_depth: usize,
    out: Vec<Finding>,
}

impl<'ast> Visit<'ast> for EqVisitor<'_> {
    fn visit_item_fn(&mut self, f: &'ast ItemFn) {
        let ct = is_constant_time_fn(&f.sig.ident.to_string());
        self.ct_depth += usize::from(ct);
        self.env.clear();
        visit::visit_item_fn(self, f);
        self.ct_depth -= usize::from(ct);
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        visit::visit_local(self, local);
        record_local(&mut self.env, local);
    }

    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        let ct = is_constant_time_fn(&f.sig.ident.to_string());
        self.ct_depth += usize::from(ct);
        self.env.clear();
        visit::visit_impl_item_fn(self, f);
        self.ct_depth -= usize::from(ct);
    }

    fn visit_expr_binary(&mut self, e: &'ast ExprBinary) {
        if self.ct_depth == 0 && matches!(e.op, BinOp::Eq(_) | BinOp::Ne(_)) {
            if let Some(confidence) = compare_confidence(&e.left, &e.right, &self.env)
                .map(|c| ct_adjusted(self.file, &e.left, &e.right, c))
            {
                let op = if matches!(e.op, BinOp::Eq(_)) {
                    "=="
                } else {
                    "!="
                };
                let code = evidence(&e.left, &self.env).is_none()
                    && evidence(&e.right, &self.env).is_none()
                    && is_code_check(&e.left, &e.right);
                let message = if code {
                    format!(
                        "one-time code or token compared with `{op}`, which is not constant time: an attacker can guess it digit by digit"
                    )
                } else {
                    format!(
                        "MAC or digest compared with `{op}`, which is not constant time: an attacker can recover the tag byte by byte"
                    )
                };
                self.out.push(self.file.finding(
                    &EQ_META,
                    confidence,
                    e.op.span(),
                    message,
                    "compare with `subtle::ConstantTimeEq::ct_eq`, or use `Mac::verify_slice`",
                ));
            }
        }
        visit::visit_expr_binary(self, e);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        // `assert!(computed == expected)` is parsed as tokens, not expressions.
        if is_macro(mac, &["assert", "debug_assert"]) {
            if let Ok(args) = mac.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated) {
                if let Some(first) = args.first() {
                    self.visit_expr(first);
                }
            }
        }
    }
}

struct AssertVisitor<'a> {
    file: &'a ParsedFile,
    env: Env,
    ct_depth: usize,
    out: Vec<Finding>,
}

impl<'ast> Visit<'ast> for AssertVisitor<'_> {
    fn visit_item_fn(&mut self, f: &'ast ItemFn) {
        let ct = is_constant_time_fn(&f.sig.ident.to_string());
        self.ct_depth += usize::from(ct);
        self.env.clear();
        visit::visit_item_fn(self, f);
        self.ct_depth -= usize::from(ct);
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        visit::visit_local(self, local);
        record_local(&mut self.env, local);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        if self.ct_depth > 0
            || !is_macro(
                mac,
                &[
                    "assert_eq",
                    "assert_ne",
                    "debug_assert_eq",
                    "debug_assert_ne",
                ],
            )
        {
            return;
        }
        let Ok(args) = mac.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated) else {
            return;
        };
        let (Some(a), Some(b)) = (args.first(), args.iter().nth(1)) else {
            return;
        };
        if let Some(confidence) =
            compare_confidence(a, b, &self.env).map(|c| ct_adjusted(self.file, a, b, c))
        {
            let name = mac
                .path
                .segments
                .last()
                .map_or(String::new(), |s| s.ident.to_string());
            self.out.push(self.file.finding(
                &ASSERT_META,
                confidence,
                mac.path.span(),
                format!(
                    "`{name}!` on a MAC or tag: not constant time, and the panic message prints both values"
                ),
                "compare with `ct_eq` and return an error that does not include either value",
            ));
        }
    }
}

fn is_macro(mac: &Macro, names: &[&str]) -> bool {
    mac.path
        .segments
        .last()
        .is_some_and(|s| names.contains(&s.ident.to_string().as_str()))
}
