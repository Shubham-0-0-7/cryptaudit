use std::collections::HashMap;

use proc_macro2::Span;
use quote::ToTokens;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Attribute, Expr, ExprCall, ExprField, ExprMethodCall, Field, Fields, Ident, ItemEnum, ItemImpl,
    ItemStruct, Macro, Member, Meta, Path, Token, Type,
};

use super::{Rule, RuleMeta};
use crate::finding::{Confidence, Finding, Severity};
use crate::secret::{
    Strength, TypeClass, classify_name, classify_type, classify_type_name, is_ciphertext_name,
    is_excluded, is_place_name, is_public_name, is_record_name, is_size_name,
};
use crate::source::ParsedFile;

pub struct DebugLeak;

static META: RuleMeta = RuleMeta {
    id: "CA010",
    name: "secret-in-debug",
    severity: Severity::High,
    explain: EXPLAIN,
};

const EXPLAIN: &str = "\
CA010: secret printed by a Debug or Display impl

`#[derive(Debug)]` generates an impl that prints every field. On a struct
holding key material, any `{:?}` of that struct, in a log line, a panic
message or an error, writes the raw key bytes out:

    #[derive(Debug)]
    struct Session { key: [u8; 32], id: u64 }

    tracing::info!(\"session: {:?}\", session);   // key bytes in the log

The same applies to a hand-written Debug or Display impl that formats a
secret field, or formats `self.to_bytes()` on a secret type.

Fix: implement Debug by hand and redact the field, or wrap it in
`secrecy::SecretBox`, whose Debug prints `[REDACTED]`:

    impl fmt::Debug for Session {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct(\"Session\")
                .field(\"key\", &\"[redacted]\")
                .field(\"id\", &self.id)
                .finish()
        }
    }

Confidence:
  high    a secret-named field holding bytes, a string or an integer
  medium  a struct named like a secret (`SecretKey`) with a byte field
          under a neutral name, or a string field
  low     a field whose type is another named type: whether it leaks
          depends on that type's own Debug impl
Fields of `secrecy` types, and fields marked `#[debug(skip)]` or
`#[derivative(Debug = \"ignore\")]`, are not reported. A hand-written Debug
that passes the value through a closure returning a literal
(`.map(|_| \"[REDACTED]\")`) is not reported either. Types named for a place
(`*Paths`, `*Location`) and integers named `seed` in a `*Request`, `*Response`,
`*Args` or `*Opts` type are skipped: they describe where a secret is, or a
sampling setting, not the secret.

Known false positives: `key: Vec<u8>` in a struct where `key` is a map key
rather than key material.
";

const HELP_DERIVE: &str =
    "implement Debug by hand and redact these fields, or wrap them in `secrecy::SecretBox`";
const HELP_IMPL: &str = "print a placeholder such as \"[redacted]\" instead of the secret";

impl Rule for DebugLeak {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, file: &ParsedFile) -> Vec<Finding> {
        let mut items = Items::default();
        items.visit_file(&file.ast);

        let mut out = Vec::new();
        for hit in derive_hits(&items, "Debug", skipped_by_attr) {
            let message = format!(
                "`#[derive(Debug)]` on `{}` prints secret {}",
                hit.ty,
                hit.fields_phrase()
            );
            if let Some(confidence) = hit.confidence() {
                out.push(file.finding(&META, confidence, hit.span, message, HELP_DERIVE));
            }
        }

        let structs: HashMap<String, &ItemStruct> = items
            .structs
            .iter()
            .rev()
            .map(|s| (s.ident.to_string(), *s))
            .collect();
        for imp in &items.impls {
            out.extend(check_manual_impl(file, imp, &structs));
        }
        out
    }
}

#[derive(Default)]
pub(super) struct Items<'ast> {
    pub structs: Vec<&'ast ItemStruct>,
    pub enums: Vec<&'ast ItemEnum>,
    pub impls: Vec<&'ast ItemImpl>,
}

impl<'ast> Visit<'ast> for Items<'ast> {
    fn visit_item_struct(&mut self, i: &'ast ItemStruct) {
        self.structs.push(i);
        visit::visit_item_struct(self, i);
    }
    fn visit_item_enum(&mut self, i: &'ast ItemEnum) {
        self.enums.push(i);
        visit::visit_item_enum(self, i);
    }
    fn visit_item_impl(&mut self, i: &'ast ItemImpl) {
        self.impls.push(i);
        visit::visit_item_impl(self, i);
    }
}

/// A struct or enum that derives a given trait and has secret-bearing fields.
pub(super) struct DeriveHit {
    /// Span of the trait name inside `#[derive(..)]`.
    pub span: Span,
    pub ty: String,
    /// `(field label, confidence)`. Enum fields are labelled `Variant::field`.
    pub leaks: Vec<(String, Confidence)>,
    /// True if at least one leaking field holds raw bytes (a key array, a `Vec<u8>`),
    /// as opposed to a string or a number.
    pub bytes: bool,
}

impl DeriveHit {
    pub fn confidence(&self) -> Option<Confidence> {
        self.leaks.iter().map(|(_, c)| *c).max()
    }

    /// "field `key`" or "fields `a`, `b`".
    pub fn fields_phrase(&self) -> String {
        let fields = self
            .leaks
            .iter()
            .map(|(l, _)| format!("`{l}`"))
            .collect::<Vec<_>>()
            .join(", ");
        let noun = if self.leaks.len() == 1 {
            "field"
        } else {
            "fields"
        };
        format!("{noun} {fields}")
    }
}

/// Finds types that `#[derive(<derive>)]` and have at least one secret-bearing
/// field. `skip` says which fields the derive ignores.
pub(super) fn derive_hits(items: &Items, derive: &str, skip: fn(&Field) -> bool) -> Vec<DeriveHit> {
    let mut out = Vec::new();
    for s in &items.structs {
        if is_public_name(&s.ident.to_string()) || is_place_name(&s.ident.to_string()) {
            continue;
        }
        if let Some(span) = derive_span(&s.attrs, derive) {
            if derive == "Debug" && has_custom_debug_attr(&s.attrs) {
                continue;
            }
            let name = s.ident.to_string();
            let leaks = leaking_fields(classify_type_name(&name), &s.fields, skip);
            let leaks = drop_request_ints(&name, &s.fields, leaks);
            if !leaks.is_empty() {
                out.push(DeriveHit {
                    span,
                    ty: name,
                    bytes: leaks_bytes(&s.fields, &leaks),
                    leaks,
                });
            }
        }
    }
    for e in &items.enums {
        if is_public_name(&e.ident.to_string()) || is_place_name(&e.ident.to_string()) {
            continue;
        }
        if let Some(span) = derive_span(&e.attrs, derive) {
            let enum_strength = classify_type_name(&e.ident.to_string());
            let mut leaks = Vec::new();
            let mut bytes = false;
            for v in &e.variants {
                let strength = enum_strength.max(classify_name(&v.ident.to_string()));
                let found = leaking_fields(strength, &v.fields, skip);
                let found = drop_request_ints(&e.ident.to_string(), &v.fields, found);
                bytes |= leaks_bytes(&v.fields, &found);
                for (label, conf) in found {
                    leaks.push((format!("{}::{label}", v.ident), conf));
                }
            }
            if !leaks.is_empty() {
                out.push(DeriveHit {
                    span,
                    ty: e.ident.to_string(),
                    bytes,
                    leaks,
                });
            }
        }
    }
    out
}

/// In a request, response or arguments type, a number named like a secret
/// (`seed`, a sampling parameter) is a setting, not key material.
fn drop_request_ints(
    ty: &str,
    fields: &Fields,
    leaks: Vec<(String, Confidence)>,
) -> Vec<(String, Confidence)> {
    if !is_record_name(ty) {
        return leaks;
    }
    leaks
        .into_iter()
        .filter(|(label, _)| {
            fields
                .iter()
                .enumerate()
                .find(|(i, f)| {
                    f.ident.as_ref().map_or(i.to_string(), ToString::to_string) == *label
                })
                .is_none_or(|(_, f)| classify_type(&f.ty) != TypeClass::Int)
        })
        .collect()
}

/// Does any of the leaking fields hold raw bytes?
fn leaks_bytes(fields: &Fields, leaks: &[(String, Confidence)]) -> bool {
    fields.iter().enumerate().any(|(i, f)| {
        let label = f.ident.as_ref().map_or(i.to_string(), ToString::to_string);
        leaks.iter().any(|(l, _)| *l == label) && classify_type(&f.ty) == TypeClass::Bytes
    })
}

/// Returns the span of `name` in `#[derive(.., name)]` or
/// `#[cfg_attr(.., derive(.., name))]`.
pub(super) fn derive_span(attrs: &[Attribute], name: &str) -> Option<Span> {
    let find_debug = |paths: &Punctuated<Path, Token![,]>| -> Option<Span> {
        paths.iter().find_map(|p| {
            let last = p.segments.last()?;
            (last.ident == name).then(|| last.ident.span())
        })
    };
    for attr in attrs {
        if attr.path().is_ident("derive") {
            if let Ok(paths) = attr.parse_args_with(Punctuated::parse_terminated) {
                if let Some(span) = find_debug(&paths) {
                    return Some(span);
                }
            }
        } else if attr.path().is_ident("cfg_attr") {
            let Ok(metas) = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            else {
                continue;
            };
            // `cfg_attr(test, derive(Debug))` only exists in test builds.
            if metas.first().is_some_and(crate::source::cfg_requires_test) {
                continue;
            }
            for meta in metas.iter().skip(1) {
                if let Meta::List(list) = meta {
                    if list.path.is_ident("derive") {
                        if let Ok(paths) = list.parse_args_with(Punctuated::parse_terminated) {
                            if let Some(span) = find_debug(&paths) {
                                return Some(span);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

pub(super) fn leaking_fields(
    owner: Option<Strength>,
    fields: &Fields,
    skip: fn(&Field) -> bool,
) -> Vec<(String, Confidence)> {
    let owner = fallback_owner(owner, fields);
    fields
        .iter()
        .enumerate()
        .filter(|(_, f)| !skip(f))
        .filter_map(|(i, f)| {
            let label = f.ident.as_ref().map_or(i.to_string(), ToString::to_string);
            field_confidence(owner, f.ident.as_ref(), &f.ty).map(|c| (label, c))
        })
        .collect()
}

/// The owner's name only speaks for neutral fields when no field is secret by
/// its own name: `SecretKey { inner }` leaks `inner`, but in
/// `Credentials { username, password }` only `password` is the secret.
pub(super) fn fallback_owner(owner: Option<Strength>, fields: &Fields) -> Option<Strength> {
    let named_secret = fields
        .iter()
        .filter_map(|f| f.ident.as_ref())
        .any(|i| classify_name(&i.to_string()).is_some());
    if named_secret { None } else { owner }
}

/// `#[debug(skip)]` (derive_more), `#[derivative(Debug = "ignore")]`, `#[educe(Debug(ignore))]`.
fn skipped_by_attr(field: &Field) -> bool {
    field.attrs.iter().any(|a| {
        let tokens = a.to_token_stream().to_string().to_lowercase();
        // `#[debug("<redacted>")]` (derive_more) replaces the output with a fixed string.
        tokens.contains("debug")
            && (tokens.contains("skip") || tokens.contains("ignore") || tokens.contains('"'))
    })
}

/// How confident we are that formatting this field prints secret material.
///
/// `owner` is the strength of the enclosing struct or variant name, used when
/// the field name itself is neutral (`struct SecretKey([u8; 32])`).
pub(super) fn field_confidence(
    owner: Option<Strength>,
    name: Option<&Ident>,
    ty: &Type,
) -> Option<Confidence> {
    use Confidence::{High, Low, Medium};
    use Strength::{Strong, Weak};
    use TypeClass::{Bytes, Int, Opaque, Redacting, Str};

    let class = classify_type(ty);
    if class == Redacting || class == TypeClass::Static {
        return None;
    }
    let by_name = match name {
        Some(ident) => {
            let n = ident.to_string();
            if is_excluded(&n) || is_ciphertext_name(&n) {
                return None;
            }
            if class == Int && is_size_name(&n) {
                return None;
            }
            // `e` is the RSA public exponent: nothing to inherit from the owner.
            if n == "e" {
                return None;
            }
            classify_name(&n)
        }
        None => None,
    };
    match (by_name, &class) {
        (Some(Strong), Bytes | Str | Int) => Some(High),
        (Some(Weak), Bytes) => Some(High),
        (Some(Weak), Str | Int) => Some(Low),
        (Some(_), Opaque(_)) => Some(Low),
        (Some(_), Redacting | TypeClass::Static) => None,
        (None, _) => match (owner, &class) {
            (Some(Strong), Bytes) => Some(High),
            // The owner's name alone does not make a named integer or string a
            // secret (`Credential { expect_selected: Option<isize> }`); only an
            // unnamed field (`Seed(u64)`) inherits it.
            (Some(Strong), Int) if name.is_some() => None,
            (Some(Strong), Str) if name.is_some() => Some(Low),
            // `AccessToken(u32)` is an id more often than a secret number.
            (Some(Strong), Int) => Some(Low),
            (Some(Strong), Str) => Some(Medium),
            (Some(Weak), Bytes) if name.is_none() => Some(High),
            (Some(Weak), Bytes) => Some(Medium),
            (Some(Weak), Int) if name.is_some() => None,
            (Some(Weak), Str | Int) => Some(Low),
            _ => None,
        },
    }
}

const FMT_TRAITS: &[&str] = &["Debug", "Display", "LowerHex", "UpperHex"];

fn check_manual_impl(
    file: &ParsedFile,
    imp: &ItemImpl,
    structs: &HashMap<String, &ItemStruct>,
) -> Vec<Finding> {
    let Some((_, trait_path, _)) = &imp.trait_ else {
        return Vec::new();
    };
    let Some(trait_name) = trait_path.segments.last().map(|s| s.ident.to_string()) else {
        return Vec::new();
    };
    if !FMT_TRAITS.contains(&trait_name.as_str()) {
        return Vec::new();
    }
    let Type::Path(self_ty) = &*imp.self_ty else {
        return Vec::new();
    };
    let Some(self_name) = self_ty.path.segments.last().map(|s| s.ident.to_string()) else {
        return Vec::new();
    };
    if is_public_name(&self_name) || is_place_name(&self_name) {
        return Vec::new();
    }
    let def = structs.get(&self_name);
    let type_strength = classify_type_name(&self_name);
    let owner = match def {
        Some(d) => fallback_owner(type_strength, &d.fields),
        None => type_strength,
    };

    let mut formatted = FormattedExprs::default();
    formatted.visit_item_impl(imp);
    let mut aliases = Aliases::default();
    aliases.visit_item_impl(imp);
    let mut hits = SelfHits {
        tainted: aliases.tainted,
        ..SelfHits::default()
    };
    for expr in &formatted.exprs {
        hits.visit_expr(expr);
    }

    let mut seen = Vec::new();
    let mut out = Vec::new();
    for (span, hit) in hits.hits {
        let (label, confidence) = match &hit {
            Hit::Field(member) => {
                let label = format!("self.{}", member.to_token_stream());
                let confidence = match def.and_then(|d| find_field(d, member)) {
                    Some((ident, field)) => field_confidence(owner, ident, &field.ty),
                    None => name_only_confidence(owner, member),
                };
                (label, confidence)
            }
            Hit::FieldBytes(member, method) => {
                let label = format!("self.{}.{method}()", member.to_token_stream());
                // The field is turned into raw bytes: its type no longer matters,
                // only whether the field or the type is named like a secret.
                let by_field = match member {
                    Member::Named(name) if is_excluded(&name.to_string()) => None,
                    Member::Named(name) => classify_name(&name.to_string()),
                    Member::Unnamed(_) => None,
                };
                let confidence = match by_field.max(owner) {
                    Some(Strength::Strong) => Some(Confidence::High),
                    Some(Strength::Weak) => Some(Confidence::Medium),
                    None => None,
                };
                (label, confidence)
            }
            Hit::SelfBytes(method) => {
                let confidence = match type_strength {
                    Some(Strength::Strong) => Some(Confidence::High),
                    Some(Strength::Weak) => Some(Confidence::Medium),
                    None => None,
                };
                (format!("self.{method}()"), confidence)
            }
        };
        let Some(confidence) = confidence else {
            continue;
        };
        if seen.contains(&label) {
            continue;
        }
        let message = format!("`impl {trait_name} for {self_name}` formats secret `{label}`");
        out.push(file.finding(&META, confidence, span, message, HELP_IMPL));
        seen.push(label);
    }
    out
}

pub(super) fn find_field<'a>(
    def: &'a ItemStruct,
    member: &Member,
) -> Option<(Option<&'a Ident>, &'a Field)> {
    match member {
        Member::Named(name) => def
            .fields
            .iter()
            .find(|f| f.ident.as_ref() == Some(name))
            .map(|f| (f.ident.as_ref(), f)),
        Member::Unnamed(index) => def
            .fields
            .iter()
            .nth(index.index as usize)
            .map(|f| (None, f)),
    }
}

/// Used when the struct is defined in another file and the field type is unknown.
fn name_only_confidence(owner: Option<Strength>, member: &Member) -> Option<Confidence> {
    let strength = match member {
        Member::Named(name) => {
            let n = name.to_string();
            if is_excluded(&n) {
                return None;
            }
            classify_name(&n)
        }
        Member::Unnamed(_) => owner,
    };
    match strength? {
        Strength::Strong => Some(Confidence::Medium),
        Strength::Weak => Some(Confidence::Low),
    }
}

const FORMAT_MACROS: &[&str] = &[
    "write",
    "writeln",
    "format",
    "format_args",
    "print",
    "println",
    "eprint",
    "eprintln",
    "panic",
];
/// Builder methods whose arguments end up in the formatted output.
const FORMAT_METHODS: &[&str] = &["field", "entry", "entries", "key", "value", "write_str"];

/// Collects expressions whose value is written to the formatter.
#[derive(Default)]
struct FormattedExprs {
    exprs: Vec<Expr>,
}

impl FormattedExprs {
    fn push(&mut self, expr: &Expr) {
        let is_str_literal = matches!(expr, Expr::Lit(l) if matches!(l.lit, syn::Lit::Str(_)));
        if !is_str_literal {
            self.exprs.push(expr.clone());
        }
    }
}

impl<'ast> Visit<'ast> for FormattedExprs {
    fn visit_macro(&mut self, mac: &'ast Macro) {
        let Some(name) = mac.path.segments.last().map(|s| s.ident.to_string()) else {
            return;
        };
        if !FORMAT_MACROS.contains(&name.as_str()) {
            return;
        }
        let Ok(args) = mac.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated) else {
            return;
        };
        // `write!(f, ..)`: the first argument is the formatter.
        let skip = usize::from(name == "write" || name == "writeln");
        for arg in args.iter().skip(skip) {
            self.push(arg);
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        let method = call.method.to_string();
        if FORMAT_METHODS.contains(&method.as_str()) {
            for arg in &call.args {
                self.push(arg);
            }
        } else if method == "fmt" {
            // `self.key.fmt(f)`
            self.push(&call.receiver);
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        // `fmt::Debug::fmt(&self.key, f)`
        if let Expr::Path(func) = &*call.func {
            if func.path.segments.last().is_some_and(|s| s.ident == "fmt") {
                if let Some(first) = call.args.first() {
                    self.push(first);
                }
            }
        }
        visit::visit_expr_call(self, call);
    }
}

#[derive(Clone)]
enum Hit {
    /// `self.key`, `self.0`
    Field(Member),
    /// `self.0.to_bytes()`, `self.key.expose_secret()`: a field turned into raw bytes.
    FieldBytes(Member, String),
    /// `self.to_bytes()` and similar on the impl's own type.
    SelfBytes(String),
}

/// Methods whose result reveals nothing about the secret.
const SAFE_METHODS: &[&str] = &[
    "len",
    "is_empty",
    "is_some",
    "is_none",
    "capacity",
    "count",
    "public_key",
    "verifying_key",
    "public",
    "to_public",
    "pubkey",
    "fingerprint",
    "id",
    "key_id",
];
/// Methods that expose the raw bytes of `self`.
const BYTES_METHODS: &[&str] = &[
    "to_bytes",
    "as_bytes",
    "to_vec",
    "as_slice",
    "as_ref",
    "serialize",
    "to_be_bytes",
    "to_le_bytes",
    "expose_secret",
    "secret_bytes",
    "to_hex",
    "encode",
];

/// Finds reads of `self`'s fields, or of `self`'s bytes, inside a formatted expression.
#[derive(Default)]
struct SelfHits {
    hits: Vec<(Span, Hit)>,
    /// Locals bound from a secret read of `self`: `let bytes = self.0.to_bytes();`
    tainted: HashMap<String, Hit>,
}

fn is_self(expr: &Expr) -> bool {
    matches!(expr, Expr::Path(p) if p.path.is_ident("self"))
}

impl<'ast> Visit<'ast> for SelfHits {
    fn visit_expr_field(&mut self, e: &'ast ExprField) {
        if is_self(&e.base) {
            self.hits.push((e.span(), Hit::Field(e.member.clone())));
        } else {
            visit::visit_expr_field(self, e);
        }
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if let Some(ident) = path.path.get_ident() {
            if let Some(hit) = self.tainted.get(&ident.to_string()) {
                self.hits.push((path.span(), hit.clone()));
            }
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        let method = call.method.to_string();
        // `self.token.as_ref().map(|_| "[REDACTED]")`: the closure throws the value away.
        if call.args.iter().any(is_redacting_closure) {
            return;
        }
        if SAFE_METHODS.contains(&method.as_str()) {
            for arg in &call.args {
                self.visit_expr(arg);
            }
            return;
        }
        if BYTES_METHODS.contains(&method.as_str()) {
            if is_self(&call.receiver) {
                self.hits.push((call.span(), Hit::SelfBytes(method)));
                return;
            }
            if let Expr::Field(field) = &*call.receiver {
                if is_self(&field.base) {
                    let hit = Hit::FieldBytes(field.member.clone(), method);
                    self.hits.push((call.span(), hit));
                    return;
                }
            }
        }
        visit::visit_expr_method_call(self, call);
    }
}

/// `|_| "[REDACTED]"`: a closure whose body is a string literal, so whatever it is
/// given never reaches the output.
fn is_redacting_closure(arg: &Expr) -> bool {
    fn literal(e: &Expr) -> bool {
        match e {
            Expr::Lit(l) => matches!(l.lit, syn::Lit::Str(_)),
            Expr::Paren(p) => literal(&p.expr),
            Expr::Block(b) => match b.block.stmts.as_slice() {
                [syn::Stmt::Expr(e, None)] => literal(e),
                _ => false,
            },
            _ => false,
        }
    }
    matches!(arg, Expr::Closure(c) if literal(&c.body))
}

/// Follows `let x = <secret read of self>;` so that `x` is treated as secret
/// where it is later formatted. One level of aliasing per `let`, in source order.
#[derive(Default)]
struct Aliases {
    tainted: HashMap<String, Hit>,
}

impl<'ast> Visit<'ast> for Aliases {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        let pat = match &local.pat {
            syn::Pat::Type(typed) => &*typed.pat,
            other => other,
        };
        if let (Some(init), syn::Pat::Ident(bound)) = (&local.init, pat) {
            let mut hits = SelfHits {
                tainted: self.tainted.clone(),
                ..SelfHits::default()
            };
            hits.visit_expr(&init.expr);
            if let Some((_, hit)) = hits.hits.into_iter().next() {
                self.tainted.insert(bound.ident.to_string(), hit);
            }
        }
        visit::visit_local(self, local);
    }
}

/// `#[debug("Key(*****)")]` on the type: derive_more formats it with a fixed string.
fn has_custom_debug_attr(attrs: &[Attribute]) -> bool {
    attrs
        .iter()
        .any(|a| a.path().is_ident("debug") && a.to_token_stream().to_string().contains('"'))
}
