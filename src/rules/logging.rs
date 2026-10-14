//! CA014: a secret passed to a logging, printing or error-message macro.
//!
//! CA010 finds types whose `Debug` prints a secret. This finds the call that
//! prints it: `info!("key = {key:?}")`, `println!("{}", password)`, and the
//! quieter `#[instrument]` on a function that takes a password.

use std::collections::{HashMap, HashSet};

use proc_macro2::{Spacing, Span, TokenStream, TokenTree};
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ImplItemFn, ItemFn, ItemStruct, Lit, Macro, Pat, Type};

use super::{Rule, RuleMeta};
use crate::finding::{Confidence, Finding, Severity};
use crate::secret::{
    Strength, TypeClass, classify_name, classify_type, is_ciphertext_name, is_public_name,
    is_size_name, words,
};
use crate::source::ParsedFile;

pub static META: RuleMeta = RuleMeta {
    id: "CA014",
    name: "secret-in-log",
    severity: Severity::High,
    explain: "\
CA014: secret passed to a logging or printing macro

    info!(\"derived key = {}\", hex::encode(key));
    error!(\"login failed for {user} with {password}\");
    println!(\"{:?}\", secret_key);
    #[tracing::instrument]
    fn login(user: &str, password: &str) { .. }      // records `password`

Logs outlive the process. They are copied to aggregators, shown on dashboards,
attached to bug reports and read by people who should never see a key. A secret
that reaches a log line is a secret you no longer control, and rotating it is
the only fix.

Checked macros: `log` and `tracing` (`error!`, `warn!`, `info!`, `debug!`,
`trace!`, `event!`), `print!`/`println!`, `eprint!`/`eprintln!`, `dbg!`,
`panic!` and friends, and `anyhow!`/`bail!`/`ensure!`. Both `{}` arguments and
inline `{name}` captures are read, and so are tracing fields (`key = ?secret`,
`%token`). `format!` and `write!` are not checked: they build strings for many
legitimate purposes.

`#[instrument]` records every argument. It is reported for a secret-named
parameter unless the attribute has `skip(name)` or `skip_all`.

Not reported: `secret.len()` and other calls that do not show the value, names
that say public or ciphertext (`public_key`, `encrypted_key`, `key_id`), values
whose type already redacts `Debug` (`secrecy::SecretString`), constants, and
integers (an id, a count, an enum number; a seed is only secret when it feeds a
key, which this rule cannot see). A value built by `Type::new`, `from`,
`try_from` or `parse` is skipped too: what it prints is decided by that type's
own `Debug`, which CA010 checks.

Confidence:
  medium  the name is clearly a secret (`password`, `secret_key`, `api_key`)
  low     the name is only `key` or `token`, which are common in non-secret code
  Raised one step when the value is explicitly exposed (`expose_secret()`,
  `hex::encode(key)`), and lowered one step for `print!`/`println!`, where the
  output is often meant for the user.

Fix: log a fixed message, an identifier or a length, never the value. Hold
secrets in `secrecy::SecretString` / `SecretBox`, whose `Debug` prints
`[REDACTED]`.

Known false positives: a command-line tool that prints a generated password on
purpose, and a variable called `token` or `key` that is not a secret.
",
};

pub struct SecretInLog;

/// Where `instrument` was imported from, by the first segment of each `use` path.
#[derive(Default)]
struct InstrumentImports(Vec<String>);

impl<'ast> Visit<'ast> for InstrumentImports {
    fn visit_item_use(&mut self, u: &'ast syn::ItemUse) {
        fn walk(tree: &syn::UseTree, first: Option<String>, out: &mut Vec<String>) {
            match tree {
                syn::UseTree::Path(p) => {
                    let first = first.unwrap_or_else(|| p.ident.to_string());
                    walk(&p.tree, Some(first), out);
                }
                syn::UseTree::Name(n) if n.ident == "instrument" => {
                    out.extend(first);
                }
                syn::UseTree::Rename(r) if r.ident == "instrument" => {
                    out.extend(first);
                }
                syn::UseTree::Group(g) => {
                    for t in &g.items {
                        walk(t, first.clone(), out);
                    }
                }
                _ => {}
            }
        }
        walk(&u.tree, None, &mut self.0);
        visit::visit_item_use(self, u);
    }
}

impl Rule for SecretInLog {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, file: &ParsedFile) -> Vec<Finding> {
        let mut fields = FieldTypes::default();
        fields.visit_file(&file.ast);
        let mut imports = InstrumentImports::default();
        imports.visit_file(&file.ast);
        let mut v = LogVisitor {
            file,
            instrument_from: imports.0,
            fields: fields.0,
            locals: HashMap::new(),
            seen: HashSet::new(),
            out: Vec::new(),
        };
        v.visit_file(&file.ast);
        v.out
    }
}

/// Struct field name -> the type classes it is declared with, anywhere in the file.
#[derive(Default)]
struct FieldTypes(HashMap<String, Vec<TypeClass>>);

impl<'ast> Visit<'ast> for FieldTypes {
    fn visit_item_struct(&mut self, s: &'ast ItemStruct) {
        for f in &s.fields {
            if let Some(name) = &f.ident {
                self.0
                    .entry(name.to_string())
                    .or_default()
                    .push(classify_type(&f.ty));
            }
        }
        visit::visit_item_struct(self, s);
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Sink {
    Log,
    /// `print!` and `eprint!` families: often meant for the person at the terminal.
    Terminal,
    Stderr,
    Panic,
    Error,
}

impl Sink {
    fn of(name: &str) -> Option<Sink> {
        Some(match name {
            "error" | "warn" | "info" | "debug" | "trace" | "event" | "log" => Sink::Log,
            "print" | "println" | "eprint" | "eprintln" => Sink::Terminal,
            "dbg" => Sink::Stderr,
            "panic" | "unreachable" | "unimplemented" | "todo" => Sink::Panic,
            "anyhow" | "bail" | "ensure" | "format_err" | "eyre" => Sink::Error,
            _ => return None,
        })
    }

    fn lands_in(self) -> &'static str {
        match self {
            Sink::Log => "the logs",
            Sink::Terminal => "the terminal output",
            Sink::Stderr => "standard error",
            Sink::Panic => "the panic message",
            Sink::Error => "an error message that is usually logged",
        }
    }
}

/// What a macro argument shows.
struct Target {
    name: String,
    /// The value is explicitly turned into text or bytes (`expose_secret()`, `hex::encode`).
    explicit: bool,
    /// The explicit exposure alone is evidence, whatever the name (`expose_secret`).
    exposes_secret: bool,
    /// The value is a struct field, so its type is looked up by field name.
    field: bool,
}

/// Methods that give the same value back in another shape.
const PASS_THROUGH: &[&str] = &[
    "as_slice",
    "as_ref",
    "as_bytes",
    "as_str",
    "to_vec",
    "to_owned",
    "to_string",
    "clone",
    "borrow",
    "deref",
    "unwrap",
    "expect",
    "as_deref",
    "display",
];

const EXPOSE: &[&str] = &["expose_secret", "expose", "unsecure", "reveal"];
const ENCODERS: &[&str] = &["encode", "encode_hex", "to_hex", "encode_upper"];

fn target_of(expr: &Expr) -> Option<Target> {
    match expr {
        Expr::Reference(e) => target_of(&e.expr),
        Expr::Paren(e) => target_of(&e.expr),
        Expr::Group(e) => target_of(&e.expr),
        Expr::Unary(e) => target_of(&e.expr),
        Expr::Path(p) => {
            let ident = p.path.get_ident()?.to_string();
            (!is_constant_name(&ident)).then_some(Target {
                name: ident,
                explicit: false,
                exposes_secret: false,
                field: false,
            })
        }
        Expr::Field(f) => {
            let syn::Member::Named(n) = &f.member else {
                // `self.0`: the field has no name, the base may.
                return target_of(&f.base);
            };
            Some(Target {
                name: n.to_string(),
                explicit: false,
                exposes_secret: false,
                field: true,
            })
        }
        Expr::MethodCall(c) => {
            let method = c.method.to_string();
            if EXPOSE.contains(&method.as_str()) {
                let mut t = target_of(&c.receiver).unwrap_or(Target {
                    name: String::new(),
                    explicit: true,
                    exposes_secret: true,
                    field: false,
                });
                t.explicit = true;
                t.exposes_secret = true;
                Some(t)
            } else if PASS_THROUGH.contains(&method.as_str()) {
                target_of(&c.receiver)
            } else {
                None
            }
        }
        Expr::Call(c) => {
            let Expr::Path(f) = &*c.func else { return None };
            let last = f.path.segments.last()?.ident.to_string();
            if ENCODERS.contains(&last.as_str()) {
                let mut t = target_of(c.args.first()?)?;
                t.explicit = true;
                Some(t)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// The type class of `let x = <expr>`, when the initialiser says: an integer read
/// (`buf.try_get_i16()?`, `n as u32`, `v.len()`), or a constructor call on a named
/// type (`ApiKey::try_from(n)?`), whose own `Debug` decides what it prints.
fn infer_class(expr: &Expr) -> Option<TypeClass> {
    match expr {
        Expr::Try(e) => infer_class(&e.expr),
        Expr::Await(e) => infer_class(&e.base),
        Expr::Paren(e) => infer_class(&e.expr),
        Expr::Cast(c) => match &*c.ty {
            Type::Path(p)
                if p.path
                    .get_ident()
                    .is_some_and(|i| is_int_name(&i.to_string())) =>
            {
                Some(TypeClass::Int)
            }
            _ => None,
        },
        Expr::MethodCall(c) => {
            let m = c.method.to_string();
            let int_read = ["get_", "try_get_", "read_"].iter().any(|p| {
                m.strip_prefix(p).is_some_and(|rest| {
                    is_int_name(rest) || rest.ends_with("_le") || rest.ends_with("_be")
                })
            });
            if int_read || matches!(m.as_str(), "len" | "count") {
                Some(TypeClass::Int)
            } else if matches!(
                m.as_str(),
                "map_err" | "unwrap" | "expect" | "ok_or" | "ok_or_else" | "unwrap_or_default"
            ) {
                infer_class(&c.receiver)
            } else {
                None
            }
        }
        Expr::Call(c) => {
            let Expr::Path(f) = &*c.func else { return None };
            let segs = &f.path.segments;
            if segs.len() < 2 {
                return None;
            }
            let ty = segs[segs.len() - 2].ident.to_string();
            let ctor = segs[segs.len() - 1].ident.to_string();
            // `Self::token_from_login(..)` could return anything; only plain
            // conversions and constructors say the result is a value of `ty`.
            if ty == "Self"
                || !(matches!(ctor.as_str(), "new" | "from" | "try_from" | "parse")
                    || ctor.starts_with("from_"))
            {
                return None;
            }
            ty.chars()
                .next()
                .is_some_and(char::is_uppercase)
                .then_some(TypeClass::Opaque(ty))
        }
        _ => None,
    }
}

fn is_int_name(s: &str) -> bool {
    let s = s
        .strip_suffix("_le")
        .or_else(|| s.strip_suffix("_be"))
        .unwrap_or(s);
    matches!(
        s,
        "u8" | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "usize"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "isize"
    )
}

fn mentions_public(tokens: TokenStream) -> bool {
    tokens.into_iter().any(|tt| match tt {
        TokenTree::Ident(i) => is_public_name(&i.to_string()),
        TokenTree::Group(g) => mentions_public(g.stream()),
        _ => false,
    })
}

/// `KEY_LEN`, `DEFAULT_PASSWORD`: a constant, not a runtime secret.
fn is_constant_name(name: &str) -> bool {
    name.chars().any(char::is_alphabetic)
        && name
            .chars()
            .all(|c| c.is_uppercase() || c.is_ascii_digit() || c == '_')
}

struct LogVisitor<'a> {
    file: &'a ParsedFile,
    /// First path segment of every `use ..instrument` in the file.
    instrument_from: Vec<String>,
    fields: HashMap<String, Vec<TypeClass>>,
    /// Declared type classes of the current function's parameters and typed lets.
    locals: HashMap<String, TypeClass>,
    seen: HashSet<(usize, usize, String)>,
    out: Vec<Finding>,
}

impl LogVisitor<'_> {
    fn type_of(&self, t: &Target) -> Option<TypeClass> {
        if t.field {
            let classes = self.fields.get(&t.name)?;
            // One redacting declaration is enough: the name is shared across types.
            return classes
                .iter()
                .find(|c| matches!(c, TypeClass::Redacting | TypeClass::Static))
                .cloned()
                .or_else(|| classes.first().cloned());
        }
        self.locals.get(&t.name).cloned()
    }

    fn confidence(&self, t: &Target, sink: Sink) -> Option<Confidence> {
        let class = self.type_of(t);
        // `SymmetricKeySlotId`, `KeyHandle`: a handle to a key, not the key.
        if let Some(TypeClass::Opaque(ty)) = &class {
            if words(ty).iter().any(|w| {
                matches!(
                    w.as_str(),
                    "id" | "ids" | "slot" | "handle" | "index" | "ref"
                )
            }) {
                return None;
            }
        }
        if !t.exposes_secret && matches!(class, Some(TypeClass::Redacting | TypeClass::Static)) {
            return None;
        }
        // An integer is an id, a count or an enum discriminant (`api_key` in a Kafka
        // header); a seed is only a secret when it feeds one, which this rule cannot see.
        if !t.exposes_secret && class == Some(TypeClass::Int) {
            return None;
        }
        // Whether a value of some other type leaks is decided by that type's own
        // `Debug`, which CA010 checks where the type is defined. Only an explicit
        // encode or `expose_secret()` shows it was meant as text.
        if !t.exposes_secret && !t.explicit && matches!(class, Some(TypeClass::Opaque(_))) {
            return None;
        }
        let strength = if t.name.is_empty() || is_ciphertext_name(&t.name) {
            None
        } else {
            classify_name(&t.name)
        };
        if class == Some(TypeClass::Int) && is_size_name(&t.name) {
            return None;
        }
        let mut level: i32 = match strength {
            Some(Strength::Strong) => 2,
            Some(Strength::Weak) => 1,
            None if t.exposes_secret => 1,
            None => return None,
        };
        // Encoding a `key` proves nothing (map keys are encoded too); encoding a
        // clearly secret name, or calling `expose_secret()`, does.
        if t.exposes_secret || (t.explicit && strength == Some(Strength::Strong)) {
            level += 1;
        }
        // The type says it is a secret, and the code takes it out on purpose.
        if t.exposes_secret && class == Some(TypeClass::Redacting) {
            level = level.max(3);
        }
        if sink == Sink::Terminal {
            level -= 1;
        }
        match level {
            i32::MIN..=0 => None,
            1 => Some(Confidence::Low),
            2 => Some(Confidence::Medium),
            _ => Some(Confidence::High),
        }
    }

    fn report(&mut self, t: &Target, sink: Sink, mac: &str, span: Span) {
        let Some(confidence) = self.confidence(t, sink) else {
            return;
        };
        let start = span.start();
        let name = if t.name.is_empty() {
            "a secret".to_string()
        } else {
            format!("`{}`", t.name)
        };
        if !self.seen.insert((start.line, start.column, t.name.clone())) {
            return;
        }
        self.out.push(self.file.finding(
            &META,
            confidence,
            span,
            if mac == "instrument" {
                format!(
                    "{name} is recorded by `#[instrument]`, so the value ends up in {}",
                    sink.lands_in()
                )
            } else {
                format!(
                    "{name} is passed to `{mac}!`, so the value ends up in {}",
                    sink.lands_in()
                )
            },
            "log a fixed message, an identifier or a length instead; hold secrets in `secrecy::SecretString`, whose `Debug` prints [REDACTED]",
        ));
    }

    fn record_params(&mut self, sig: &syn::Signature) {
        self.locals.clear();
        for arg in &sig.inputs {
            if let syn::FnArg::Typed(t) = arg {
                if let Pat::Ident(p) = &*t.pat {
                    self.locals
                        .insert(p.ident.to_string(), classify_type(&t.ty));
                }
            }
        }
    }

    /// `#[instrument]` records every parameter by `Debug`.
    fn check_instrument(&mut self, attrs: &[syn::Attribute], sig: &syn::Signature) {
        let Some(attr) = attrs.iter().find(|a| {
            a.path()
                .segments
                .last()
                .is_some_and(|s| s.ident == "instrument")
        }) else {
            return;
        };
        // `bitwarden_logging::instrument` and similar wrappers usually skip all
        // arguments by default, so only `tracing::instrument` is reported.
        let path = &attr.path().segments;
        let is_tracing = if path.len() > 1 {
            path.first().is_some_and(|s| s.ident == "tracing")
        } else if self.instrument_from.is_empty() {
            // Reached through a glob import or a prelude: almost always `tracing`.
            true
        } else {
            self.instrument_from.iter().all(|f| f == "tracing")
        };
        if !is_tracing {
            return;
        }
        let tokens = attr.meta.to_token_stream();
        let mut skipped = HashSet::new();
        let mut skip_all = false;
        collect_skips(tokens, &mut skipped, &mut skip_all);
        if skip_all {
            return;
        }
        for arg in &sig.inputs {
            let syn::FnArg::Typed(t) = arg else { continue };
            let Pat::Ident(p) = &*t.pat else { continue };
            let name = p.ident.to_string();
            if skipped.contains(&name) {
                continue;
            }
            let target = Target {
                name,
                explicit: false,
                exposes_secret: false,
                field: false,
            };
            self.report(&target, Sink::Log, "instrument", attr.span());
        }
    }
}

/// Reads `skip(a, b)` and `skip_all` out of an `#[instrument(..)]` attribute.
fn collect_skips(tokens: TokenStream, skipped: &mut HashSet<String>, skip_all: &mut bool) {
    let mut iter = tokens.into_iter().peekable();
    while let Some(tt) = iter.next() {
        match tt {
            TokenTree::Ident(i) if i == "skip_all" => *skip_all = true,
            TokenTree::Ident(i) if i == "skip" => {
                if let Some(TokenTree::Group(g)) = iter.peek() {
                    for t in g.stream() {
                        if let TokenTree::Ident(name) = t {
                            skipped.insert(name.to_string());
                        }
                    }
                }
            }
            TokenTree::Group(g) => collect_skips(g.stream(), skipped, skip_all),
            _ => {}
        }
    }
}

/// Splits macro arguments on top-level commas.
fn split_args(tokens: TokenStream) -> Vec<Vec<TokenTree>> {
    let mut out = vec![Vec::new()];
    for tt in tokens {
        match &tt {
            TokenTree::Punct(p) if p.as_char() == ',' => out.push(Vec::new()),
            _ => out.last_mut().expect("never empty").push(tt),
        }
    }
    out.retain(|a| !a.is_empty());
    out
}

fn is_punct(tt: &TokenTree, c: char, spacing: Spacing) -> bool {
    matches!(tt, TokenTree::Punct(p) if p.as_char() == c && p.spacing() == spacing)
}

fn skip_sigils(mut a: &[TokenTree]) -> &[TokenTree] {
    while a
        .first()
        .is_some_and(|t| is_punct(t, '?', Spacing::Alone) || is_punct(t, '%', Spacing::Alone))
    {
        a = &a[1..];
    }
    a
}

/// Drops `target: "x"` arguments, tracing sigils (`?`, `%`) and `name =` prefixes.
/// Returns `None` for an argument that carries no value (`target:`, `parent:`).
fn strip_prefix(a: &[TokenTree]) -> Option<&[TokenTree]> {
    if a.len() >= 3 && matches!(a[0], TokenTree::Ident(_)) && is_punct(&a[1], ':', Spacing::Alone) {
        return None;
    }
    let mut a = skip_sigils(a);
    if a.len() >= 3 && matches!(a[0], TokenTree::Ident(_)) && is_punct(&a[1], '=', Spacing::Alone) {
        a = &a[2..];
    }
    Some(skip_sigils(a))
}

/// `{key}` and `{key:?}` inside a format string.
fn inline_captures(fmt: &str) -> Vec<String> {
    let chars: Vec<char> = fmt.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '{' {
            if chars.get(i + 1) == Some(&'{') {
                i += 2;
                continue;
            }
            let end = chars[i + 1..].iter().position(|&c| c == '}');
            if let Some(len) = end {
                let inner: String = chars[i + 1..i + 1 + len].iter().collect();
                let name = inner.split(':').next().unwrap_or("").trim();
                let is_ident = name
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_alphabetic() || c == '_')
                    && name.chars().all(|c| c.is_alphanumeric() || c == '_');
                if is_ident {
                    out.push(name.to_string());
                }
                i += len + 1;
            }
        }
        i += 1;
    }
    out
}

impl<'ast> Visit<'ast> for LogVisitor<'_> {
    fn visit_item_fn(&mut self, f: &'ast ItemFn) {
        self.record_params(&f.sig);
        self.check_instrument(&f.attrs, &f.sig);
        visit::visit_item_fn(self, f);
    }

    fn visit_impl_item_fn(&mut self, f: &'ast ImplItemFn) {
        self.record_params(&f.sig);
        self.check_instrument(&f.attrs, &f.sig);
        visit::visit_impl_item_fn(self, f);
    }

    fn visit_local(&mut self, l: &'ast syn::Local) {
        if let Pat::Type(t) = &l.pat {
            if let Pat::Ident(p) = &*t.pat {
                self.locals
                    .insert(p.ident.to_string(), classify_type(&t.ty));
            }
        } else if let (Pat::Ident(p), Some(init)) = (&l.pat, &l.init) {
            // `let derived_key = key.public_key();` holds public material.
            if mentions_public(init.expr.to_token_stream()) {
                self.locals.insert(p.ident.to_string(), TypeClass::Static);
            }
            if let Some(class) = infer_class(&init.expr) {
                self.locals.entry(p.ident.to_string()).or_insert(class);
            }
            // `let key = SecretString::new(..)` redacts.
            if let Expr::Call(c) = &*init.expr {
                if let Expr::Path(f) = &*c.func {
                    let ty = f.path.segments.first().map(|s| s.ident.to_string());
                    if ty.is_some_and(|t| {
                        matches!(
                            t.as_str(),
                            "Secret" | "SecretString" | "SecretBox" | "SecretVec"
                        )
                    }) {
                        self.locals
                            .insert(p.ident.to_string(), TypeClass::Redacting);
                    }
                }
            }
        }
        visit::visit_local(self, l);
    }

    fn visit_macro(&mut self, m: &'ast Macro) {
        let Some(name) = m.path.segments.last().map(|s| s.ident.to_string()) else {
            return;
        };
        let Some(sink) = Sink::of(&name) else {
            return;
        };
        let call_span = m.path.span();
        for arg in split_args(m.tokens.clone()) {
            let Some(value) = strip_prefix(&arg) else {
                continue;
            };
            if value.is_empty() {
                continue;
            }
            let stream: TokenStream = value.iter().cloned().collect();
            let Ok(expr) = syn::parse2::<Expr>(stream) else {
                continue;
            };
            if let Expr::Lit(l) = &expr {
                if let Lit::Str(s) = &l.lit {
                    for captured in inline_captures(&s.value()) {
                        if is_constant_name(&captured) {
                            continue;
                        }
                        let t = Target {
                            name: captured,
                            explicit: false,
                            exposes_secret: false,
                            field: false,
                        };
                        self.report(&t, sink, &name, call_span);
                    }
                }
                continue;
            }
            if let Some(t) = target_of(&expr) {
                self.report(&t, sink, &name, expr.span());
            }
        }
    }
}
