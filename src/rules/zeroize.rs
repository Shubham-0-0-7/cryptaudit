//! CA015 and CA016: secrets that are never wiped, or wiped in a way the
//! optimiser is allowed to delete.

use std::collections::{HashMap, HashSet};

use proc_macro2::Span;
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, ItemFn, ItemStruct, Lit};

use super::bytes::{macro_idents, root_var};
use super::ca010::{Items, derive_span, fallback_owner, field_confidence};
use super::{Rule, RuleMeta};
use crate::finding::{Confidence, Finding, Severity};
use crate::secret::{TypeClass, classify_name, classify_type, is_public_name, is_token_only};
use crate::source::ParsedFile;

pub static MISSING_META: RuleMeta = RuleMeta {
    id: "CA015",
    name: "secret-not-zeroized",
    severity: Severity::Medium,
    explain: "\
CA015: secret that is never zeroized

Rust moves a key through many owners: function arguments, struct fields, closure
captures, vector elements. Every place it is dropped without being wiped leaves the
bytes in freed memory, where a core dump, a swap file, a cold-boot read or a
later heap disclosure can find them.

Two shapes are reported.

1. A struct that holds a secret-named field of bytes or a string, with no
   `#[derive(Zeroize)]` / `#[derive(ZeroizeOnDrop)]`, no `impl Zeroize` or
   `impl ZeroizeOnDrop`, and no `impl Drop` that wipes it:

       struct Session { key: [u8; 32], id: u64 }

2. A local buffer that a KDF or an RNG fills (`pbkdf2(.., &mut key)`,
   `rng.fill_bytes(&mut key)`) and that is then dropped, not returned, and never
   wiped:

       let mut key = vec![0u8; 32];
       pbkdf2::<Hmac<Sha256>>(password, &salt, 600_000, key.as_mut_slice());
       let cipher = Aes128Ctr::new(&key[..16], &iv);
       // `key` is freed here with its bytes intact

Fix: `#[derive(Zeroize, ZeroizeOnDrop)]`, or hold the value in
`zeroize::Zeroizing<..>` or `secrecy::SecretBox<..>`.

Confidence is at most medium: the name heuristic is the main source of false
positives.

Known false positives: a field named like a secret that is public data, and
buffers whose ownership is handed to a callee that wipes them.
",
};

pub static MANUAL_META: RuleMeta = RuleMeta {
    id: "CA016",
    name: "manual-zeroing",
    severity: Severity::Medium,
    explain: "\
CA016: secret wiped by hand, which the optimiser may delete

    let mut key = derive_key(password);
    use_key(&key);
    key.fill(0);          // the compiler may remove this store

After the write `key` is never read again, so the store is dead and LLVM is
allowed to remove it. The developer sees defensive code; the binary contains none.
This is why the `zeroize` crate uses volatile writes and a compiler fence.

Detected on a secret-named binding: `.fill(0)`, `.iter_mut().for_each(|b| *b = 0)`,
a loop that stores `0` into each element, `x = [0u8; N]`, `copy_from_slice(&[0; N])`
and `ptr::write_bytes(.., 0, ..)`.

Fix: `use zeroize::Zeroize; key.zeroize();`

Not reported when `.zeroize()` is also called on the same variable.
",
};

pub struct MissingZeroize;
pub struct ManualZeroing;

impl Rule for MissingZeroize {
    fn meta(&self) -> &'static RuleMeta {
        &MISSING_META
    }

    fn check(&self, file: &ParsedFile) -> Vec<Finding> {
        let mut items = Items::default();
        items.visit_file(&file.ast);
        let protected = protected_types(&items);

        let mut out = Vec::new();
        for s in &items.structs {
            if let Some(f) = struct_finding(file, s, &protected) {
                out.push(f);
            }
        }
        let mut v = LocalVisitor {
            file,
            locals: HashMap::new(),
            tail_moved: Vec::new(),
            out: Vec::new(),
        };
        v.visit_file(&file.ast);
        out.extend(v.out);
        out
    }
}

impl Rule for ManualZeroing {
    fn meta(&self) -> &'static RuleMeta {
        &MANUAL_META
    }

    fn check(&self, file: &ParsedFile) -> Vec<Finding> {
        let mut v = ManualVisitor {
            file,
            zeroized: HashSet::new(),
            idents: HashMap::new(),
            out: Vec::new(),
        };
        v.visit_file(&file.ast);
        v.out
    }
}

// ---- CA015, struct form -------------------------------------------------

/// Types in this file that wipe themselves.
fn protected_types(items: &Items) -> HashSet<String> {
    let mut out = HashSet::new();
    for s in &items.structs {
        if ["Zeroize", "ZeroizeOnDrop"]
            .iter()
            .any(|d| derive_span(&s.attrs, d).is_some())
        {
            out.insert(s.ident.to_string());
        }
    }
    for e in &items.enums {
        if ["Zeroize", "ZeroizeOnDrop"]
            .iter()
            .any(|d| derive_span(&e.attrs, d).is_some())
        {
            out.insert(e.ident.to_string());
        }
    }
    for imp in &items.impls {
        let Some((_, trait_path, _)) = &imp.trait_ else {
            continue;
        };
        let Some(trait_name) = trait_path.segments.last().map(|s| s.ident.to_string()) else {
            continue;
        };
        let wipes = match trait_name.as_str() {
            "Zeroize" | "ZeroizeOnDrop" | "DefaultIsZeroes" => true,
            "Drop" => {
                let body = imp.to_token_stream().to_string().to_lowercase();
                body.contains("zeroize") || body.contains("volatile") || body.contains("fill (0")
            }
            _ => false,
        };
        if !wipes {
            continue;
        }
        if let syn::Type::Path(p) = &*imp.self_ty {
            if let Some(seg) = p.path.segments.last() {
                out.insert(seg.ident.to_string());
            }
        }
    }
    out
}

fn struct_finding(
    file: &ParsedFile,
    s: &ItemStruct,
    protected: &HashSet<String>,
) -> Option<Finding> {
    let name = s.ident.to_string();
    if protected.contains(&name)
        || is_repr_c(&s.attrs)
        || derive_span(&s.attrs, "Copy").is_some()
        || is_public_name(&name)
    {
        return None;
    }
    let owner = fallback_owner(classify_name(&name), &s.fields);
    let mut leaks: Vec<(String, Confidence)> = Vec::new();
    for (i, f) in s.fields.iter().enumerate() {
        // A borrowed slice is not owned: the caller decides how it is wiped.
        if !matches!(classify_type(&f.ty), TypeClass::Bytes | TypeClass::Str) || is_borrowed(&f.ty)
        {
            continue;
        }
        let ty = f.ty.to_token_stream().to_string();
        if ty.contains("Zeroizing") || ty.contains("Secret") || mentions_protected(&ty, protected) {
            continue;
        }
        if let Some(c) = field_confidence(owner, f.ident.as_ref(), &f.ty) {
            let label = f.ident.as_ref().map_or(i.to_string(), ToString::to_string);
            leaks.push((label, c));
        }
    }
    let confidence = leaks.iter().map(|(_, c)| *c).max()?.min(Confidence::Medium);
    let fields = leaks
        .iter()
        .map(|(l, _)| format!("`{l}`"))
        .collect::<Vec<_>>()
        .join(", ");
    Some(file.finding(
        &MISSING_META,
        confidence,
        s.ident.span(),
        format!(
            "`{name}` holds secret {fields} but is never zeroized: no `Zeroize`/`ZeroizeOnDrop` derive, and no `Drop` that wipes it"
        ),
        "add `#[derive(Zeroize, ZeroizeOnDrop)]`, or hold the value in `zeroize::Zeroizing`",
    ))
}

fn mentions_protected(ty: &str, protected: &HashSet<String>) -> bool {
    protected.iter().any(|p| ty.contains(p.as_str()))
}

// ---- CA015, local form ---------------------------------------------------

struct Local {
    span: Span,
    /// A KDF or RNG wrote into it.
    filled: bool,
    zeroized: bool,
    /// Ownership was handed on: returned, passed by value, put in a struct.
    moved: bool,
}

struct LocalVisitor<'a> {
    file: &'a ParsedFile,
    locals: HashMap<String, Local>,
    /// Filled buffers that left a block as its value (`{ ..; key }`), in order.
    tail_moved: Vec<String>,
    out: Vec<Finding>,
}

const READ_ONLY: &[&str] = &[
    "as_ref", "as_slice", "as_bytes", "to_vec", "clone", "len", "is_empty", "iter", "into",
    "borrow", "deref", "to_owned", "get", "first", "last", "eq", "ne",
];

/// A value that looks like a byte buffer being created: `vec![0u8; n]`, `[0u8; N]`,
/// `Vec::new()`, `Vec::with_capacity(n)`.
fn is_buffer_init(expr: &Expr) -> bool {
    match expr {
        Expr::Repeat(_) | Expr::Array(_) => true,
        Expr::Macro(m) => m.mac.path.is_ident("vec"),
        Expr::Call(c) => match &*c.func {
            Expr::Path(p) => {
                let segs: Vec<_> = p
                    .path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect();
                matches!(segs.as_slice(), [.., t, f]
                    if t == "Vec" && (f == "new" || f == "with_capacity"))
            }
            _ => false,
        },
        Expr::MethodCall(c) => matches!(c.method.to_string().as_str(), "to_vec"),
        _ => false,
    }
}

impl<'ast> Visit<'ast> for LocalVisitor<'_> {
    fn visit_item_fn(&mut self, f: &'ast ItemFn) {
        self.fn_scope(|s| visit::visit_item_fn(s, f));
    }

    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        self.fn_scope(|s| visit::visit_impl_item_fn(s, f));
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        let mark = self.tail_moved.len();
        visit::visit_local(self, local);
        let pat = match &local.pat {
            syn::Pat::Type(t) => &*t.pat,
            other => other,
        };
        let (syn::Pat::Ident(bound), Some(init)) = (pat, &local.init) else {
            return;
        };
        let name = bound.ident.to_string();
        if classify_name(&name).is_none() || is_token_only(&name) {
            return;
        }
        // A fresh buffer, or a filled one that flowed out of a block into this binding.
        let inherited = self.tail_moved.len() > mark && !is_buffer_init(&init.expr);
        if !is_buffer_init(&init.expr) && !inherited {
            return;
        }
        self.locals.insert(
            name,
            Local {
                span: bound.ident.span(),
                filled: inherited,
                zeroized: false,
                moved: false,
            },
        );
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        visit::visit_block(self, block);
        // The block's value is handed to whoever uses the block.
        if let Some(syn::Stmt::Expr(tail, None)) = block.stmts.last() {
            let mut names = Vec::new();
            collect_paths(tail, &mut names);
            for n in names {
                if let Some(l) = self.locals.get_mut(&n) {
                    if l.filled && !l.moved {
                        self.tail_moved.push(n.clone());
                    }
                    l.moved = true;
                }
            }
        }
    }

    fn visit_expr_reference(&mut self, e: &'ast syn::ExprReference) {
        if e.mutability.is_some() {
            if let Some(n) = root_var(&e.expr) {
                if let Some(l) = self.locals.get_mut(&n) {
                    l.filled = true;
                }
            }
        }
        visit::visit_expr_reference(self, e);
    }

    fn visit_expr_method_call(&mut self, c: &'ast ExprMethodCall) {
        let method = c.method.to_string();
        if let Some(n) = root_var(&c.receiver) {
            if let Some(l) = self.locals.get_mut(&n) {
                if method == "zeroize" {
                    l.zeroized = true;
                } else if !READ_ONLY.contains(&method.as_str()) && method != "fill" {
                    l.filled = true;
                }
            }
        }
        for arg in &c.args {
            self.hand_off(arg);
        }
        visit::visit_expr_method_call(self, c);
    }

    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        // `zeroize_call!(buf)`: a wrapper macro that wipes what it is given.
        let name = m
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        if ["zeroize", "wipe", "scrub"]
            .iter()
            .any(|w| name.contains(w))
        {
            for n in macro_idents(m) {
                if let Some(l) = self.locals.get_mut(&n) {
                    l.zeroized = true;
                }
            }
        }
    }

    fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
        for arg in &c.args {
            self.hand_off(arg);
        }
        visit::visit_expr_call(self, c);
    }

    fn visit_expr_return(&mut self, e: &'ast syn::ExprReturn) {
        if let Some(v) = &e.expr {
            self.hand_off(v);
        }
        visit::visit_expr_return(self, e);
    }

    fn visit_field_value(&mut self, fv: &'ast syn::FieldValue) {
        self.hand_off(&fv.expr);
        visit::visit_field_value(self, fv);
    }
}

impl LocalVisitor<'_> {
    /// A bare `name` (not `&name`) given away: someone else now owns it.
    fn hand_off(&mut self, expr: &Expr) {
        if let Expr::Path(p) = expr {
            if let Some(id) = p.path.get_ident() {
                if let Some(l) = self.locals.get_mut(&id.to_string()) {
                    l.moved = true;
                }
            }
        }
    }

    fn fn_scope(&mut self, walk: impl FnOnce(&mut Self)) {
        let saved = std::mem::take(&mut self.locals);
        let saved_tail = std::mem::take(&mut self.tail_moved);
        walk(self);
        let locals = std::mem::replace(&mut self.locals, saved);
        self.tail_moved = saved_tail;
        for (name, l) in locals {
            if l.filled && !l.zeroized && !l.moved {
                self.out.push(self.file.finding(
                    &MISSING_META,
                    Confidence::Medium,
                    l.span,
                    format!(
                        "`{name}` is filled with key material and dropped without being zeroized"
                    ),
                    "wrap it in `zeroize::Zeroizing`, or call `.zeroize()` before it goes out of scope",
                ));
            }
        }
    }
}

/// Bare variable names in a tail expression: `key`, `Ok(key)`, `(key, nonce)`.
fn collect_paths(expr: &Expr, out: &mut Vec<String>) {
    match expr {
        Expr::Path(p) => {
            if let Some(id) = p.path.get_ident() {
                out.push(id.to_string());
            }
        }
        Expr::Call(c) => c.args.iter().for_each(|a| collect_paths(a, out)),
        Expr::Tuple(t) => t.elems.iter().for_each(|a| collect_paths(a, out)),
        Expr::Paren(p) => collect_paths(&p.expr, out),
        Expr::Struct(s) => s.fields.iter().for_each(|f| collect_paths(&f.expr, out)),
        Expr::Try(t) => collect_paths(&t.expr, out),
        _ => {}
    }
}

// ---- CA016 ---------------------------------------------------------------

struct ManualVisitor<'a> {
    file: &'a ParsedFile,
    /// Variables this function wipes with `.zeroize()`.
    zeroized: HashSet<String>,
    /// Where every identifier of the current function appears (line, column).
    idents: HashMap<String, Vec<(usize, usize)>>,
    out: Vec<Finding>,
}

/// Records the position of every identifier in a function.
#[derive(Default)]
struct IdentPositions {
    at: HashMap<String, Vec<(usize, usize)>>,
}

impl<'ast> Visit<'ast> for IdentPositions {
    fn visit_ident(&mut self, i: &'ast syn::Ident) {
        let start = i.span().start();
        self.at
            .entry(i.to_string())
            .or_default()
            .push((start.line, start.column));
    }
}

/// The last component of a variable path: `self.key` -> `key`.
fn leaf(name: &str) -> &str {
    name.rsplit('.').next().unwrap_or(name)
}

fn is_zero(expr: &Expr) -> bool {
    match expr {
        Expr::Lit(l) => matches!(&l.lit, Lit::Int(i) if i.base10_digits() == "0"),
        Expr::Paren(p) => is_zero(&p.expr),
        Expr::Cast(c) => is_zero(&c.expr),
        _ => false,
    }
}

fn is_zero_array(expr: &Expr) -> bool {
    match expr {
        Expr::Repeat(r) => is_zero(&r.expr),
        Expr::Reference(r) => is_zero_array(&r.expr),
        Expr::Paren(p) => is_zero_array(&p.expr),
        _ => false,
    }
}

#[derive(Default)]
struct ZeroizeCalls {
    vars: HashSet<String>,
}

impl<'ast> Visit<'ast> for ZeroizeCalls {
    fn visit_expr_method_call(&mut self, c: &'ast ExprMethodCall) {
        if c.method == "zeroize" {
            if let Some(n) = root_var(&c.receiver) {
                self.vars.insert(n);
            }
        }
        visit::visit_expr_method_call(self, c);
    }
}

impl ManualVisitor<'_> {
    fn secret(&self, var: &str) -> Option<Confidence> {
        if self.zeroized.contains(var) {
            return None;
        }
        match classify_name(leaf(var))? {
            crate::secret::Strength::Strong => Some(Confidence::High),
            crate::secret::Strength::Weak => Some(Confidence::Medium),
        }
    }

    /// `wiped` is the whole wiping expression. If the variable is mentioned
    /// again after it, the buffer is still in use and the stores are not dead.
    fn report(&mut self, var: &str, span: Span, wiped: Span, how: &str) {
        let Some(confidence) = self.secret(var) else {
            return;
        };
        let end = wiped.end();
        let used_later = self
            .idents
            .get(leaf(var))
            .is_some_and(|at| at.iter().any(|&p| p > (end.line, end.column)));
        if used_later {
            return;
        }
        self.out.push(self.file.finding(
            &MANUAL_META,
            confidence,
            span,
            format!(
                "`{var}` is wiped with {how}, which the optimiser may remove: the buffer is never read again"
            ),
            "use `zeroize::Zeroize::zeroize()`, which writes volatile and fences the compiler",
        ));
    }

    fn with_zeroized(
        &mut self,
        vars: HashSet<String>,
        idents: HashMap<String, Vec<(usize, usize)>>,
        walk: impl FnOnce(&mut Self),
    ) {
        let saved = std::mem::replace(&mut self.zeroized, vars);
        let saved_idents = std::mem::replace(&mut self.idents, idents);
        walk(self);
        self.zeroized = saved;
        self.idents = saved_idents;
    }
}

impl<'ast> Visit<'ast> for ManualVisitor<'_> {
    fn visit_item_fn(&mut self, f: &'ast ItemFn) {
        let mut calls = ZeroizeCalls::default();
        calls.visit_item_fn(f);
        let mut pos = IdentPositions::default();
        pos.visit_item_fn(f);
        self.with_zeroized(calls.vars, pos.at, |s| visit::visit_item_fn(s, f));
    }

    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        let mut calls = ZeroizeCalls::default();
        calls.visit_impl_item_fn(f);
        let mut pos = IdentPositions::default();
        pos.visit_impl_item_fn(f);
        self.with_zeroized(calls.vars, pos.at, |s| visit::visit_impl_item_fn(s, f));
    }

    fn visit_expr_method_call(&mut self, c: &'ast ExprMethodCall) {
        let method = c.method.to_string();
        // `key.fill(0)`
        if method == "fill" && c.args.first().is_some_and(is_zero) {
            if let Some(var) = root_var(&c.receiver) {
                self.report(&var, c.method.span(), c.span(), "`.fill(0)`");
            }
        }
        // `key.copy_from_slice(&[0u8; 32])`
        if matches!(method.as_str(), "copy_from_slice" | "clone_from_slice")
            && c.args.first().is_some_and(is_zero_array)
        {
            if let Some(var) = root_var(&c.receiver) {
                self.report(
                    &var,
                    c.method.span(),
                    c.span(),
                    "`copy_from_slice` of zeros",
                );
            }
        }
        // `key.iter_mut().for_each(|b| *b = 0)`
        if matches!(method.as_str(), "for_each" | "try_for_each") {
            if let Expr::MethodCall(inner) = &*c.receiver {
                if inner.method == "iter_mut" {
                    if let (Some(var), Some(Expr::Closure(cl))) =
                        (root_var(&inner.receiver), c.args.first())
                    {
                        if stores_zero(&cl.body) {
                            self.report(
                                &var,
                                c.method.span(),
                                c.span(),
                                "`iter_mut().for_each(|b| *b = 0)`",
                            );
                        }
                    }
                }
            }
        }
        visit::visit_expr_method_call(self, c);
    }

    fn visit_expr_assign(&mut self, e: &'ast syn::ExprAssign) {
        // `key = [0u8; 32];`
        if is_zero_array(&e.right) {
            if let Expr::Path(_) | Expr::Field(_) = &*e.left {
                if let Some(var) = root_var(&e.left) {
                    self.report(&var, e.left.span(), e.span(), "an assignment of zeros");
                }
            }
        }
        visit::visit_expr_assign(self, e);
    }

    fn visit_expr_for_loop(&mut self, e: &'ast syn::ExprForLoop) {
        // `for b in key.iter_mut() { *b = 0; }` / `for b in &mut key { *b = 0 }`
        let target = match &*e.expr {
            Expr::MethodCall(c) if c.method == "iter_mut" => root_var(&c.receiver),
            Expr::Reference(r) if r.mutability.is_some() => root_var(&r.expr),
            _ => None,
        };
        let mut finder = ZeroStores::default();
        finder.visit_block(&e.body);
        if let Some(var) = target {
            if finder.deref_zero {
                self.report(
                    &var,
                    e.for_token.span,
                    e.span(),
                    "a loop that stores `0` into each byte",
                );
            }
        }
        // `for i in 0..key.len() { key[i] = 0; }`
        for var in finder.indexed_zero {
            self.report(
                &var,
                e.for_token.span,
                e.span(),
                "a loop that stores `0` into each byte",
            );
        }
        visit::visit_expr_for_loop(self, e);
    }

    fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
        // `ptr::write_bytes(key.as_mut_ptr(), 0, n)`: not volatile either.
        if let Expr::Path(f) = &*c.func {
            let is_write_bytes = f
                .path
                .segments
                .last()
                .is_some_and(|s| s.ident == "write_bytes");
            if is_write_bytes && c.args.iter().nth(1).is_some_and(is_zero) {
                if let Some(var) = c.args.first().and_then(|a| match a {
                    Expr::MethodCall(m) => root_var(&m.receiver),
                    other => root_var(other),
                }) {
                    self.report(&var, f.span(), c.span(), "`ptr::write_bytes`");
                }
            }
        }
        visit::visit_expr_call(self, c);
    }
}

fn stores_zero(body: &Expr) -> bool {
    let mut f = ZeroStores::default();
    f.visit_expr(body);
    f.deref_zero
}

/// Stores of `0`: `*b = 0` and `x[i] = 0`.
#[derive(Default)]
struct ZeroStores {
    deref_zero: bool,
    indexed_zero: Vec<String>,
}

impl<'ast> Visit<'ast> for ZeroStores {
    fn visit_expr_assign(&mut self, e: &'ast syn::ExprAssign) {
        if is_zero(&e.right) {
            match &*e.left {
                Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => self.deref_zero = true,
                Expr::Index(i) => {
                    if let Some(var) = root_var(&i.expr) {
                        self.indexed_zero.push(var);
                    }
                }
                _ => {}
            }
        }
        visit::visit_expr_assign(self, e);
    }
}

/// `&[u8]`, `Option<&[u8]>`, `Option<&'a str>`: the struct does not own the bytes.
fn is_borrowed(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Reference(_) => true,
        syn::Type::Path(p) => p.path.segments.last().is_some_and(|seg| {
            seg.ident == "Option"
                && matches!(&seg.arguments, syn::PathArguments::AngleBracketed(a)
                    if a.args.iter().any(|g| matches!(g, syn::GenericArgument::Type(t) if is_borrowed(t))))
        }),
        _ => false,
    }
}

/// `#[repr(C)]` structs are FFI values handed to foreign code, which cannot run `Drop`.
fn is_repr_c(attrs: &[syn::Attribute]) -> bool {
    attrs
        .iter()
        .any(|a| a.path().is_ident("repr") && a.to_token_stream().to_string().contains('C'))
}
