//! Shared by the key, IV, nonce and RNG-seed rules: is an expression a
//! compile-time constant byte string?

use std::collections::HashMap;

use quote::ToTokens;
use syn::visit::{self, Visit};
use syn::{Expr, ExprLit, Lit};

/// A constant, and how guessable it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Konst {
    /// Some literal: `b"my secret key"`, `[1, 2, 3, ..]`, `hex!("..")`.
    Plain,
    /// All one byte or a counting sequence: `[0u8; 32]`, `[7; 16]`, `[0, 1, 2, ..]`.
    Degenerate,
}

/// Names bound to constants: module-level `const`/`static` items, and locals.
pub type ConstEnv = HashMap<String, Konst>;

/// Methods that change the representation of a value but not its content.
const PASS: &[&str] = &[
    "as_ref",
    "as_slice",
    "as_bytes",
    "into_bytes",
    "to_vec",
    "to_owned",
    "clone",
    "into",
    "borrow",
    "deref",
    "unwrap",
    "expect",
    "as_array",
    "to_be_bytes",
    "to_le_bytes",
];

/// Constructors that wrap their first argument: `Key::from_slice(x)`.
const WRAPPERS: &[&str] = &[
    "from_slice",
    "clone_from_slice",
    "from",
    "assume_unique_for_key",
    "try_assume_unique_for_key",
];

/// Functions that decode a string literal into bytes: `hex::decode("..")`.
const DECODERS: &[&str] = &["decode", "from_hex", "decode_hex", "from_base64"];

pub fn literal_bytes(expr: &Expr, env: &ConstEnv) -> Option<Konst> {
    match expr {
        Expr::Reference(e) => literal_bytes(&e.expr, env),
        Expr::Paren(e) => literal_bytes(&e.expr, env),
        Expr::Group(e) => literal_bytes(&e.expr, env),
        Expr::Unary(e) => literal_bytes(&e.expr, env),
        Expr::Cast(e) => literal_bytes(&e.expr, env),
        Expr::Index(e) => literal_bytes(&e.expr, env),
        Expr::Lit(ExprLit { lit, .. }) => match lit {
            Lit::ByteStr(b) => Some(classify(&b.value())),
            Lit::Str(_) => Some(Konst::Plain),
            _ => None,
        },
        Expr::Array(a) => {
            let bytes: Option<Vec<u8>> = a.elems.iter().map(int_value).collect();
            Some(classify(&bytes?))
        }
        Expr::Repeat(r) => {
            int_value(&r.expr)?;
            Some(Konst::Degenerate)
        }
        Expr::Macro(m) => {
            let name = m.mac.path.segments.last()?.ident.to_string();
            match name.as_str() {
                "hex" | "include_bytes" | "include_str" => Some(Konst::Plain),
                "vec" => {
                    // `vec![0u8; 32]` and `vec![1, 2, 3]`: parse the body as an array.
                    let tokens = &m.mac.tokens;
                    let array: Expr = syn::parse_str(&format!("[{tokens}]")).ok()?;
                    literal_bytes(&array, env)
                }
                _ => None,
            }
        }
        Expr::MethodCall(c) => {
            let method = c.method.to_string();
            if PASS.contains(&method.as_str()) {
                literal_bytes(&c.receiver, env)
            } else if DECODERS.contains(&method.as_str()) && first_is_str(c.args.first()) {
                Some(Konst::Plain)
            } else {
                None
            }
        }
        Expr::Call(c) => {
            let Expr::Path(f) = &*c.func else { return None };
            let last = f.path.segments.last()?.ident.to_string();
            if DECODERS.contains(&last.as_str()) && first_is_str(c.args.first()) {
                Some(Konst::Plain)
            } else if WRAPPERS.contains(&last.as_str()) {
                literal_bytes(c.args.first()?, env)
            } else {
                None
            }
        }
        Expr::Path(p) => env.get(&p.path.get_ident()?.to_string()).copied(),
        _ => None,
    }
}

fn first_is_str(arg: Option<&Expr>) -> bool {
    matches!(
        arg,
        Some(Expr::Lit(ExprLit {
            lit: Lit::Str(_),
            ..
        }))
    )
}

/// Value of an integer or byte literal, as one byte.
fn int_value(expr: &Expr) -> Option<u8> {
    match expr {
        Expr::Lit(ExprLit { lit, .. }) => match lit {
            Lit::Int(i) => i.base10_parse::<u64>().ok().map(|v| v as u8),
            Lit::Byte(b) => Some(b.value()),
            _ => None,
        },
        Expr::Unary(u) => int_value(&u.expr),
        Expr::Cast(c) => int_value(&c.expr),
        _ => None,
    }
}

fn classify(bytes: &[u8]) -> Konst {
    let constant = bytes.windows(2).all(|w| w[0] == w[1]);
    let counting = bytes.windows(2).all(|w| w[1] == w[0].wrapping_add(1));
    if bytes.len() < 2 || constant || counting {
        Konst::Degenerate
    } else {
        Konst::Plain
    }
}

/// Collects `const` and `static` items bound to constant byte strings, anywhere in a file.
#[derive(Default)]
pub struct ConstCollector {
    pub env: ConstEnv,
}

impl<'ast> Visit<'ast> for ConstCollector {
    fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
        if let Some(k) = literal_bytes(&item.expr, &self.env) {
            self.env.insert(item.ident.to_string(), k);
        }
        visit::visit_item_const(self, item);
    }

    fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
        if let Some(k) = literal_bytes(&item.expr, &self.env) {
            self.env.insert(item.ident.to_string(), k);
        }
        visit::visit_item_static(self, item);
    }
}

/// Does the expression read the clock?
pub fn mentions_time(expr: &impl ToTokens) -> bool {
    let t = expr.to_token_stream().to_string().to_lowercase();
    [
        "systemtime",
        "instant ::",
        "instant::",
        "unix_epoch",
        "timestamp",
        "utc :: now",
        "local :: now",
        "as_nanos",
        "as_millis",
        "as_micros",
        "elapsed",
    ]
    .iter()
    .any(|needle| t.contains(needle))
}

/// Last identifiers of a path, without generic arguments: `Hmac::<Sha256>::new` -> `[Hmac, new]`.
pub fn path_idents(path: &syn::Path) -> Vec<String> {
    path.segments.iter().map(|s| s.ident.to_string()).collect()
}

/// Methods that read a value without changing it.
const READ_ONLY: &[&str] = &[
    "as_ref",
    "as_slice",
    "as_bytes",
    "to_vec",
    "clone",
    "len",
    "is_empty",
    "iter",
    "into",
    "borrow",
    "deref",
    "to_owned",
    "get",
    "first",
    "last",
    "to_be_bytes",
    "to_le_bytes",
    "eq",
    "ne",
];

/// The local variable an expression reads or writes: `key` for `key`, `key[..16]`, `&mut key`.
pub fn root_var(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Path(p) => p.path.get_ident().map(ToString::to_string),
        Expr::Field(f) => {
            let base = root_var(&f.base)?;
            Some(format!("{base}.{}", f.member.to_token_stream()))
        }
        Expr::Index(i) => root_var(&i.expr),
        Expr::Reference(r) => root_var(&r.expr),
        Expr::Paren(p) => root_var(&p.expr),
        Expr::Unary(u) => root_var(&u.expr),
        _ => None,
    }
}

/// Drops a local from the constant environment once it may have been overwritten:
/// `kdf(&mut key)`, `rng.fill_bytes(&mut key)`, `key.copy_from_slice(..)`, `key[0] = 1`.
pub struct Invalidate<'a> {
    pub env: &'a mut ConstEnv,
}

impl<'ast> Visit<'ast> for Invalidate<'_> {
    fn visit_expr_reference(&mut self, e: &'ast syn::ExprReference) {
        if e.mutability.is_some() {
            if let Some(n) = root_var(&e.expr) {
                self.env.remove(&n);
            }
        }
        visit::visit_expr_reference(self, e);
    }

    fn visit_expr_assign(&mut self, e: &'ast syn::ExprAssign) {
        if let Some(n) = root_var(&e.left) {
            self.env.remove(&n);
        }
        visit::visit_expr_assign(self, e);
    }

    fn visit_expr_method_call(&mut self, c: &'ast syn::ExprMethodCall) {
        if !READ_ONLY.contains(&c.method.to_string().as_str()) {
            if let Some(n) = root_var(&c.receiver) {
                self.env.remove(&n);
            }
        }
        visit::visit_expr_method_call(self, c);
    }
}
