//! CA062, CA063: passwords stored or stretched too cheaply.
//!
//! CA062 reads the cost parameter (iterations, bcrypt cost, scrypt `log_n`, Argon2
//! memory) when it is a literal or a constant in the same file. CA063 looks for a
//! general-purpose hash applied to a value named like a password.

use std::collections::HashMap;

use proc_macro2::{Span, TokenStream, TokenTree};
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, ExprMethodCall, ItemConst, ItemFn, Lit, Local, Pat};

use super::{Rule, RuleMeta};
use crate::finding::{Confidence, Finding, Severity};
use crate::secret::{is_excluded, words};
use crate::source::ParsedFile;

pub static COST_META: RuleMeta = RuleMeta {
    id: "CA062",
    name: "weak-password-hash-cost",
    severity: Severity::Medium,
    explain: "\
CA062: password hashing with a work factor that is too low

    pbkdf2_hmac::<Sha256>(password, &salt, 1_000, &mut key);
    bcrypt::hash(password, 4)?;

If a website's password database leaks, the attacker does not read the
passwords; they have a list of hashes. They then guess: hash \"123456\", hash
\"password1\", and compare. Password-hashing functions (PBKDF2, bcrypt, scrypt,
Argon2) exist to make each guess expensive on purpose, by repeating work or
using a lot of memory. The setting that controls how expensive is the *work
factor*. A work factor chosen years ago, or chosen to make tests fast, lets an
attacker with a graphics card try billions of guesses per second.

Today's guidance (OWASP Password Storage Cheat Sheet) is at least:
  PBKDF2-HMAC-SHA256   600,000 iterations
  bcrypt               cost 10 (the `bcrypt` crate defaults to 12)
  scrypt               N = 2^17 (`log_n` 17), r = 8, p = 1
  Argon2id             19 MiB of memory (`m_cost` 19456), t = 2, p = 1

Detected, when the number is a literal or a constant in the same file:
  PBKDF2   `pbkdf2_hmac`, `pbkdf2_hmac_array`, `pbkdf2`, `pbkdf2::derive`
  bcrypt   `bcrypt::hash`, `hash_with_salt`, `hash_with_result`
  scrypt   `scrypt::Params::new(log_n, ..)`
  Argon2   `argon2::Params::new(m_cost, ..)`

Confidence:
  high    far below any guidance: under 1,000 PBKDF2 iterations, bcrypt cost 5
          or less, scrypt `log_n` under 10, Argon2 memory under 1 MiB
  medium  well below it: under 10,000 iterations, bcrypt cost under 10,
          scrypt `log_n` under 14, Argon2 memory under 8 MiB
  low     PBKDF2 between 10,000 and 100,000 iterations. Hidden unless
          `--min-confidence low` is given.

Fix: raise the number, and store it with the hash so it can be raised again
later. For new code prefer Argon2id.

A count of 1 is not reported: it is a one-step derivation from a key that was
already stretched, not a password hash.

Known false positives: a value that is not a password (a high-entropy key
that only needs stretching to the right length), and formats that fix the
number (WPA2 uses PBKDF2-HMAC-SHA1 with 4096 iterations).
",
};

pub static FAST_META: RuleMeta = RuleMeta {
    id: "CA063",
    name: "fast-hash-of-password",
    severity: Severity::High,
    explain: "\
CA063: password hashed with a general-purpose hash

    let stored = Sha256::digest(password.as_bytes());

SHA-256, SHA-512, MD5 and BLAKE3 are built to be fast: a modern graphics card
computes billions of SHA-256 hashes per second. That is what you want for a
checksum and the opposite of what you want for a password. If the database
leaks, the attacker can test every common password, every word in a
dictionary and every short combination in minutes. There is also no salt, so
two users with the same password have the same hash and one precomputed
table (a \"rainbow table\") cracks everyone at once.

Passwords need a slow, salted, purpose-built function: Argon2id, scrypt,
bcrypt, or PBKDF2 with a large iteration count.

Detected: `Sha256::digest(password)`, `hasher.update(password)` on a SHA-2,
SHA-3, MD5 or BLAKE2 hasher, `md5::compute(password)`, `blake3::hash(password)`,
`sha256::digest(password)`, ring `digest::digest(&SHA256, password)`, and
openssl `hash(MessageDigest::sha256(), password)`, where the input is named
`password`, `passwd`, `passphrase` or `pwd`.

Confidence:
  medium  the input is named like a password
  low     SHA-1 (the k-anonymity range lookup of \"Have I Been Pwned\" hashes the
          password with SHA-1 on purpose), or the file also uses Argon2, bcrypt,
          scrypt or PBKDF2, which suggests this is a pre-hash or a lookup key

Fix: `argon2::Argon2::default().hash_password(password, &salt)`.

Known false positives: a hash of the password for a breach-lookup service, a
pre-hash for a protocol such as SRP or OPAQUE, or a cache key that never leaves
memory.
",
};

pub struct WeakCost;
pub struct FastPasswordHash;

impl Rule for WeakCost {
    fn meta(&self) -> &'static RuleMeta {
        &COST_META
    }
    fn check(&self, file: &ParsedFile) -> Vec<Finding> {
        scan(file, COST_META.id)
    }
}

impl Rule for FastPasswordHash {
    fn meta(&self) -> &'static RuleMeta {
        &FAST_META
    }
    fn check(&self, file: &ParsedFile) -> Vec<Finding> {
        scan(file, FAST_META.id)
    }
}

fn scan(file: &ParsedFile, rule: &'static str) -> Vec<Finding> {
    let mut consts = ConstInts::default();
    consts.visit_file(&file.ast);
    let mut v = Visitor {
        file,
        rule,
        ints: consts.0,
        hashers: Vec::new(),
        out: Vec::new(),
    };
    v.visit_file(&file.ast);
    v.out
}

#[derive(Default)]
struct ConstInts(HashMap<String, u128>);

impl<'ast> Visit<'ast> for ConstInts {
    fn visit_item_const(&mut self, item: &'ast ItemConst) {
        if let Some(v) = int_value(&item.expr, &HashMap::new()) {
            self.0.insert(item.ident.to_string(), v);
        }
        visit::visit_item_const(self, item);
    }
}

/// The integer an expression evaluates to, if it is a literal or a constant seen
/// in this file, possibly wrapped in `NonZeroU32::new(..).unwrap()`, a cast or
/// `.into()`.
fn int_value(expr: &Expr, env: &HashMap<String, u128>) -> Option<u128> {
    match expr {
        Expr::Lit(l) => match &l.lit {
            Lit::Int(i) => i.base10_parse::<u128>().ok(),
            _ => None,
        },
        Expr::Paren(p) => int_value(&p.expr, env),
        Expr::Group(g) => int_value(&g.expr, env),
        Expr::Cast(c) => int_value(&c.expr, env),
        Expr::Reference(r) => int_value(&r.expr, env),
        Expr::Path(p) => p
            .path
            .get_ident()
            .and_then(|i| env.get(&i.to_string()).copied()),
        Expr::MethodCall(c)
            if matches!(
                c.method.to_string().as_str(),
                "unwrap" | "expect" | "try_into" | "into" | "get"
            ) =>
        {
            int_value(&c.receiver, env)
        }
        Expr::Call(c) => {
            let Expr::Path(f) = &*c.func else {
                return None;
            };
            let last = f.path.segments.last()?.ident.to_string();
            if matches!(last.as_str(), "new" | "try_from" | "from") {
                int_value(c.args.first()?, env)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Hash functions that are fast on purpose.
fn hash_type(name: &str) -> Option<&'static str> {
    let n = name.to_lowercase().replace('_', "");
    let known = [
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha512256",
        "sha3",
        "sha3224",
        "sha3256",
        "sha3384",
        "sha3512",
        "md5",
        "md4",
        "blake2b",
        "blake2s",
        "blake2b512",
        "blake2s256",
        "blake3",
        "ripemd160",
        "ripemd",
        "whirlpool",
    ];
    known.iter().find(|k| **k == n).copied()
}

fn idents_in(tokens: TokenStream, out: &mut Vec<String>) {
    for tt in tokens {
        match tt {
            TokenTree::Ident(i) => out.push(i.to_string()),
            TokenTree::Group(g) => idents_in(g.stream(), out),
            _ => {}
        }
    }
}

/// The identifier in `expr` that names a password, if any: `password`,
/// `&self.password`, `user.passphrase.as_bytes()`.
fn password_ident(expr: &Expr) -> Option<String> {
    let mut idents = Vec::new();
    idents_in(expr.to_token_stream(), &mut idents);
    idents.into_iter().find(|i| {
        !is_excluded(i)
            && words(i).iter().any(|w| {
                matches!(
                    w.as_str(),
                    "password" | "passwd" | "passphrase" | "pwd" | "passwords"
                )
            })
            && !words(i).iter().any(|w| w == "hashed")
    })
}

struct Visitor<'a> {
    file: &'a ParsedFile,
    rule: &'static str,
    ints: HashMap<String, u128>,
    /// Locals bound from `Sha256::new()` and friends: `(name, hash type)`.
    hashers: Vec<(String, &'static str)>,
    out: Vec<Finding>,
}

impl Visitor<'_> {
    fn report(
        &mut self,
        meta: &'static RuleMeta,
        confidence: Confidence,
        span: Span,
        message: String,
        help: &str,
    ) {
        if meta.id == self.rule {
            self.out
                .push(self.file.finding(meta, confidence, span, message, help));
        }
    }

    fn uses_real_kdf(&self) -> bool {
        ["argon2", "bcrypt", "scrypt", "pbkdf2"]
            .iter()
            .any(|k| self.file.source.contains(k))
    }

    fn fast_hash(&mut self, hash: &str, input: &Expr, span: Span) {
        let Some(name) = password_ident(input) else {
            return;
        };
        let confidence = if hash == "sha1" || self.uses_real_kdf() {
            Confidence::Low
        } else {
            Confidence::Medium
        };
        self.report(
            &FAST_META,
            confidence,
            span,
            format!(
                "`{name}` is hashed with {}: a fast hash lets an attacker who gets the hashes try billions of guesses per second, and nothing here salts it",
                hash.to_uppercase()
            ),
            "use a password-hashing function: `argon2::Argon2::default().hash_password(..)`, scrypt or bcrypt",
        );
    }

    fn cost(
        &mut self,
        what: &str,
        value: u128,
        high_below: u128,
        medium_below: u128,
        low_below: u128,
        span: Span,
    ) {
        // One round is not password stretching, it is a fixed derivation step (the
        // Bitwarden login hash does exactly one on top of an already stretched key).
        if value <= 1 {
            return;
        }
        let confidence = if value < high_below {
            Confidence::High
        } else if value < medium_below {
            Confidence::Medium
        } else if value < low_below {
            Confidence::Low
        } else {
            return;
        };
        self.report(
            &COST_META,
            confidence,
            span,
            format!(
                "{what}: too low to slow down an attacker who has stolen the password hashes"
            ),
            "raise it to at least the current guidance (PBKDF2-SHA256 600,000 iterations, bcrypt cost 10, scrypt log_n 17, Argon2 19 MiB), and store it with the hash",
        );
    }
}

impl<'ast> Visit<'ast> for Visitor<'_> {
    fn visit_item_fn(&mut self, f: &'ast ItemFn) {
        let saved = std::mem::take(&mut self.hashers);
        visit::visit_item_fn(self, f);
        self.hashers = saved;
    }

    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        let saved = std::mem::take(&mut self.hashers);
        visit::visit_impl_item_fn(self, f);
        self.hashers = saved;
    }

    fn visit_local(&mut self, local: &'ast Local) {
        if let (Some(init), Pat::Ident(p)) = (&local.init, &local.pat) {
            if let Some(h) = constructed_hasher(&init.expr) {
                self.hashers.push((p.ident.to_string(), h));
            }
        }
        visit::visit_local(self, local);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Expr::Path(func) = &*call.func {
            let segs: Vec<String> = func
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            let last = segs.last().cloned().unwrap_or_default();
            let span = func
                .path
                .segments
                .last()
                .map_or(call.span(), |s| s.ident.span());
            let arg = |i: usize| call.args.iter().nth(i);

            // CA063: `Sha256::digest(password)`, `md5::compute(password)`, `blake3::hash(password)`.
            let hashed = match last.as_str() {
                "digest" | "hash" | "compute" | "hash_password" if segs.len() >= 2 => {
                    let owner = &segs[segs.len() - 2];
                    hash_type(owner).map(|h| (h, arg(0)))
                }
                _ => None,
            };
            if let Some((h, Some(input))) = hashed {
                self.fast_hash(h, input, span);
            }
            // ring: `digest::digest(&digest::SHA256, password)`.
            if last == "digest" && segs.iter().any(|s| s == "digest") {
                if let (Some(Expr::Reference(r)), Some(input)) = (arg(0), arg(1)) {
                    if let Expr::Path(alg) = &*r.expr {
                        if let Some(h) = alg
                            .path
                            .segments
                            .last()
                            .and_then(|s| hash_type(&s.ident.to_string()))
                        {
                            self.fast_hash(h, input, span);
                        }
                    }
                }
            }
            // openssl: `hash(MessageDigest::sha256(), password)`.
            if last == "hash" {
                if let Some(Expr::Call(inner)) = arg(0) {
                    if let Expr::Path(p) = &*inner.func {
                        let segs: Vec<String> = p
                            .path
                            .segments
                            .iter()
                            .map(|s| s.ident.to_string())
                            .collect();
                        if segs.first().is_some_and(|s| s == "MessageDigest") {
                            if let (Some(h), Some(input)) =
                                (segs.last().and_then(|s| hash_type(s)), arg(1))
                            {
                                self.fast_hash(h, input, span);
                            }
                        }
                    }
                }
            }

            // CA062.
            let src = &self.file.source;
            let owner = segs.len().checked_sub(2).map(|i| segs[i].as_str());
            match (owner, last.as_str()) {
                (_, "pbkdf2_hmac" | "pbkdf2_hmac_array" | "pbkdf2") => {
                    if let Some(n) = arg(2).and_then(|e| int_value(e, &self.ints)) {
                        self.cost(
                            &format!("PBKDF2 with {n} iterations"),
                            n,
                            1_000,
                            10_000,
                            100_000,
                            span,
                        );
                    }
                }
                (Some("pbkdf2"), "derive") => {
                    if let Some(n) = arg(1).and_then(|e| int_value(e, &self.ints)) {
                        self.cost(
                            &format!("PBKDF2 with {n} iterations"),
                            n,
                            1_000,
                            10_000,
                            100_000,
                            span,
                        );
                    }
                }
                (Some("bcrypt"), "hash" | "hash_with_salt" | "hash_with_result") => {
                    if let Some(n) = arg(1).and_then(|e| int_value(e, &self.ints)) {
                        self.cost(&format!("bcrypt cost {n}"), n, 6, 10, 10, span);
                    }
                }
                (Some("Params" | "ScryptParams"), "new")
                    if src.contains("scrypt") && !src.contains("argon2") =>
                {
                    if let Some(n) = arg(0).and_then(|e| int_value(e, &self.ints)) {
                        self.cost(&format!("scrypt log_n {n}"), n, 10, 14, 14, span);
                    }
                }
                (Some("Params"), "new") if src.contains("argon2") && !src.contains("scrypt") => {
                    if let Some(n) = arg(0).and_then(|e| int_value(e, &self.ints)) {
                        self.cost(
                            &format!("Argon2 with {n} KiB of memory"),
                            n,
                            1_024,
                            8_192,
                            8_192,
                            span,
                        );
                    }
                }
                _ => {}
            }
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        // `format!("{:x}", md5::compute(password))`: look inside the arguments.
        if let Ok(args) = mac
            .parse_body_with(syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated)
        {
            for arg in &args {
                self.visit_expr(arg);
            }
        }
        visit::visit_macro(self, mac);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        // `hasher.update(password)` / `Sha256::new().chain_update(password)`.
        if matches!(
            call.method.to_string().as_str(),
            "update" | "chain_update" | "chain" | "input" | "input_str"
        ) {
            let hash = hasher_of(&call.receiver, &self.hashers);
            if let (Some(h), Some(input)) = (hash, call.args.first()) {
                self.fast_hash(h, input, call.method.span());
            }
        }
        visit::visit_expr_method_call(self, call);
    }
}

/// `Sha256::new()`, `Sha256::default()`, `Sha256::new_with_prefix(..)`, with any
/// `.chain_update(..)` calls after it.
fn constructed_hasher(expr: &Expr) -> Option<&'static str> {
    match expr {
        Expr::Call(c) => {
            let Expr::Path(f) = &*c.func else {
                return None;
            };
            let segs: Vec<String> = f
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            let last = segs.last()?;
            if segs.len() >= 2 && matches!(last.as_str(), "new" | "default" | "new_with_prefix") {
                hash_type(&segs[segs.len() - 2])
            } else {
                None
            }
        }
        Expr::MethodCall(m) => constructed_hasher(&m.receiver),
        Expr::Paren(p) => constructed_hasher(&p.expr),
        _ => None,
    }
}

/// The hash a receiver expression refers to: a hasher local, or a fresh hasher chain.
fn hasher_of(expr: &Expr, hashers: &[(String, &'static str)]) -> Option<&'static str> {
    match expr {
        Expr::Path(p) => {
            let name = p.path.get_ident()?.to_string();
            hashers
                .iter()
                .rev()
                .find(|(n, _)| *n == name)
                .map(|(_, h)| *h)
        }
        other => constructed_hasher(other),
    }
}
