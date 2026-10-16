//! CA028: a nonce used for more than one encryption, or fixed in the source.
//!
//! Within one function body the rule follows each nonce variable in source order,
//! counting the `encrypt` calls that use the same value. A re-assignment, a
//! `&mut nonce`, or a mutating method call starts a new value. Branches are
//! analysed separately and merged, and a loop body that does not refresh the
//! nonce counts as reuse across iterations.

use std::collections::{HashMap, HashSet};

use proc_macro2::Span;
use quote::ToTokens;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, ItemFn};

use super::bytes::{ConstCollector, ConstEnv, literal_bytes, macro_idents, mentions_time};
use super::{Rule, RuleMeta};
use crate::finding::{Confidence, Finding, Severity};
use crate::secret::words;
use crate::source::ParsedFile;

pub static META: RuleMeta = RuleMeta {
    id: "CA028",
    name: "nonce-reuse",
    severity: Severity::Critical,
    explain: "\
CA028: nonce reuse or fixed nonce

    let nonce = Nonce::from_slice(b\"unique nonce\");
    let c1 = cipher.encrypt(nonce, m1.as_ref())?;
    let c2 = cipher.encrypt(nonce, m2.as_ref())?;   // same key, same nonce

ChaCha20 and AES-CTR/GCM derive their keystream from (key, nonce, counter). The
same key and nonce give the same keystream, so c1 XOR c2 equals m1 XOR m2: the
keystream cancels and both plaintexts can be recovered. With GCM the
authentication key is exposed as well, so messages can be forged. This is the
root cause of the PS3 signing-key disclosure and of several TLS session breaks.

Reported, within one function:
  * the same nonce value passed to two or more `encrypt`-style calls on the
    same cipher, with no re-assignment between them
  * a nonce defined outside a loop and used inside it without being refreshed
  * a nonce that is a literal or a `const`
  * a nonce derived from the clock (`SystemTime::now()`, `Instant::now()`)
  * a nonce, IV, salt or key filled from a *clone* of the random number
    generator (`let mut rng = self.rng.clone(); rng.fill_bytes(&mut nonce);`):
    the clone starts from the same internal state every time, so every call
    produces the same bytes. This was RUSTSEC-2023-0068 in the `cocoon` crate.

The timestamp nonce deserves its own note. \"Use a timestamp\" fails in four
ways: two nodes encrypt in the same tick; nanosecond clocks still collide under
load because the OS timer is coarser than the request rate; timestamps are
predictable where freshness is required; and two threads can read the same
instant.

Fix: a fresh random nonce per message (`generate_nonce(&mut OsRng)`), or a
strictly monotonic counter with an atomic increment and rekeying before wrap. For
XChaCha20 and AES-GCM-SIV random nonces are safe at any realistic volume.

Confidence:
  high    two uses of one nonce on one cipher in straight-line code
  medium  reuse after a branch or across loop iterations, a literal nonce, a
          clock-derived nonce
  low     a literal nonce in a function that also derives its key with a KDF,
          which is a legitimate pattern when the key is unique per message

Known false positive for the cloned-RNG check: `rand::rngs::ThreadRng` shares
its state between clones, so cloning it is harmless. A seeded `StdRng` is the
dangerous case.

Known limits: only one function body is analysed, so a nonce reused across a
function call is missed; two different keys that share a nonce variable are only
told apart when the cipher variables have different names.
",
};

pub struct NonceReuse;

impl Rule for NonceReuse {
    fn meta(&self) -> &'static RuleMeta {
        &META
    }

    fn check(&self, file: &ParsedFile) -> Vec<Finding> {
        let mut consts = ConstCollector::default();
        consts.visit_file(&file.ast);
        let mut v = Visitor {
            file,
            consts: consts.env,
            state: State::default(),
            next_version: 1,
            loops: Vec::new(),
            branches_seen: 0,
            fn_has_kdf: false,
            reported: HashSet::new(),
            out: Vec::new(),
        };
        v.visit_file(&file.ast);
        let mut clones = CloneRng {
            file,
            rngs: HashSet::new(),
            out: Vec::new(),
        };
        clones.visit_file(&file.ast);
        v.out.extend(clones.out);
        v.out
    }
}

/// Calls that encrypt with a nonce as the first argument.
const ENCRYPT: &[&str] = &[
    "encrypt",
    "encrypt_in_place",
    "encrypt_in_place_detached",
    "seal",
    "seal_in_place",
    "seal_in_place_append_tag",
    "seal_in_place_separate_tag",
];

/// Names that are passed first to an `encrypt` method but are not nonces.
const NOT_NONCES: &[&str] = &[
    "ctx",
    "context",
    "sched",
    "schedule",
    "state",
    "plaintext",
    "msg",
    "message",
    "data",
    "buf",
    "input",
    "from",
    "crypto",
    "provider",
    "backend",
    "rng",
    "ciphersuite",
    "event_type",
    // The object that encrypts, passed to a helper: `.encrypt(self.encdec.as_ref(), id)`.
    "encdec",
    "encryptor",
    "encrypter",
    "decryptor",
    "cipher",
    "aead",
];

fn is_empty_or_text_literal(expr: &Expr) -> bool {
    match expr {
        Expr::Reference(e) => is_empty_or_text_literal(&e.expr),
        Expr::Paren(e) => is_empty_or_text_literal(&e.expr),
        Expr::Array(a) => a.elems.is_empty(),
        Expr::Lit(l) => matches!(l.lit, syn::Lit::Str(_)),
        _ => false,
    }
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

/// Constructors that wrap a nonce value: `Nonce::from_slice(&n)`.
const NONCE_WRAPPERS: &[&str] = &[
    "from_slice",
    "clone_from_slice",
    "from",
    "new",
    "assume_unique_for_key",
    "try_assume_unique_for_key",
];

/// Iterator adapters whose closure runs once per element.
const ITER_ADAPTERS: &[&str] = &[
    "map",
    "for_each",
    "flat_map",
    "filter_map",
    "try_for_each",
    "fold",
    "inspect",
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Origin {
    Fresh,
    /// A literal or `const`.
    Fixed,
    /// Derived from the clock.
    Time,
}

#[derive(Clone)]
struct VarInfo {
    version: u32,
    origin: Origin,
}

/// How many times a (cipher, nonce value) pair has been used.
type UseKey = (String, String, u32);

#[derive(Clone, Default)]
struct State {
    vars: HashMap<String, VarInfo>,
    uses: HashMap<UseKey, (u32, usize)>,
}

fn merge(a: State, b: State) -> State {
    let mut out = a;
    for (name, info) in b.vars {
        let keep = out.vars.get(&name).map(|i| i.version);
        if keep != Some(info.version) {
            out.vars.insert(name, info);
        }
    }
    for (key, (count, line)) in b.uses {
        let e = out.uses.entry(key).or_insert((0, line));
        if count > e.0 {
            *e = (count, line);
        }
    }
    out
}

struct Visitor<'a> {
    file: &'a ParsedFile,
    consts: ConstEnv,
    state: State,
    next_version: u32,
    /// Names refreshed inside each enclosing loop body.
    loops: Vec<HashSet<String>>,
    branches_seen: usize,
    fn_has_kdf: bool,
    reported: HashSet<(usize, usize)>,
    out: Vec<Finding>,
}

/// Root variable of an expression: `nonce`, `nonce[..8]`, `self.nonce`.
fn root_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Path(p) => p.path.get_ident().map(ToString::to_string),
        Expr::Field(f) => {
            let base = root_name(&f.base)?;
            Some(format!("{base}.{}", f.member.to_token_stream()))
        }
        Expr::Index(i) => root_name(&i.expr),
        Expr::Reference(r) => root_name(&r.expr),
        Expr::Paren(p) => root_name(&p.expr),
        Expr::Unary(u) => root_name(&u.expr),
        Expr::MethodCall(c) if READ_ONLY.contains(&c.method.to_string().as_str()) => {
            root_name(&c.receiver)
        }
        _ => None,
    }
}

/// What a nonce argument refers to.
enum NonceRef {
    Var(String),
    /// A literal or constant, directly in the call.
    Fixed,
    /// Anything else: a fresh value from a function call.
    Other,
}

impl Visitor<'_> {
    fn nonce_ref(&self, expr: &Expr) -> NonceRef {
        match expr {
            Expr::Reference(e) => self.nonce_ref(&e.expr),
            Expr::Paren(e) => self.nonce_ref(&e.expr),
            Expr::Group(e) => self.nonce_ref(&e.expr),
            Expr::MethodCall(c) if READ_ONLY.contains(&c.method.to_string().as_str()) => {
                self.nonce_ref(&c.receiver)
            }
            Expr::Call(c) => {
                let wraps = matches!(&*c.func, Expr::Path(f) if f.path.segments.last()
                    .is_some_and(|s| NONCE_WRAPPERS.contains(&s.ident.to_string().as_str())));
                match c.args.first() {
                    Some(arg) if wraps => self.nonce_ref(arg),
                    _ => NonceRef::Other,
                }
            }
            Expr::Index(i) => self.nonce_ref(&i.expr),
            Expr::Lit(_) | Expr::Array(_) | Expr::Repeat(_) => {
                if literal_bytes(expr, &self.consts).is_some() {
                    NonceRef::Fixed
                } else {
                    NonceRef::Other
                }
            }
            Expr::Path(_) | Expr::Field(_) => {
                if literal_bytes(expr, &self.consts).is_some() {
                    return NonceRef::Fixed;
                }
                match root_name(expr) {
                    Some(name) => NonceRef::Var(name),
                    None => NonceRef::Other,
                }
            }
            _ => NonceRef::Other,
        }
    }

    /// Constants visible at this point: module constants plus locals that hold a literal.
    fn const_env(&self) -> ConstEnv {
        let mut env = self.consts.clone();
        for (name, info) in &self.state.vars {
            if info.origin == Origin::Fixed {
                env.insert(name.clone(), super::bytes::Konst::Plain);
            }
        }
        env
    }

    /// Where a value comes from. A value read from a clock-derived local is clock-derived too.
    fn origin_of(&self, init: &Expr) -> Origin {
        let mut reads = ReadsTimeVar {
            vars: &self.state.vars,
            found: false,
        };
        reads.visit_expr(init);
        if mentions_time(init) || reads.found {
            Origin::Time
        } else if literal_bytes(init, &self.const_env()).is_some() {
            Origin::Fixed
        } else {
            Origin::Fresh
        }
    }

    /// `name` now holds a new value.
    fn refresh(&mut self, name: &str, origin: Origin) {
        let version = self.next_version;
        self.next_version += 1;
        self.state
            .vars
            .insert(name.to_string(), VarInfo { version, origin });
    }

    /// Mark everything a statement may change, once it has run.
    fn refresh_expr(&mut self, expr: &Expr) {
        if let Some(name) = root_name(expr) {
            self.refresh(&name, Origin::Fresh);
        }
    }

    fn report_once(&mut self, span: Span, confidence: Confidence, message: String, help: &str) {
        let at = (span.start().line, span.start().column);
        if self.reported.insert(at) {
            self.out
                .push(self.file.finding(&META, confidence, span, message, help));
        }
    }

    fn encrypt_call(&mut self, call: &ExprMethodCall) {
        let span = call.method.span();
        let receiver = call.receiver.to_token_stream().to_string();
        let nonce_arg = &call.args[0];
        // `ff1.encrypt(&[], ..)` has no tweak, and a text literal is a label
        // (`encrypt("m.dummy", ..)`): neither is a nonce.
        if is_empty_or_text_literal(nonce_arg) {
            return;
        }
        // `value.encrypt(ctx, key)`: a key-store context, not a nonce.
        if let Expr::Path(p) = nonce_arg {
            if p.path
                .get_ident()
                .is_some_and(|i| NOT_NONCES.contains(&i.to_string().as_str()))
            {
                return;
            }
        }
        // `self.encrypt(plaintext, ..)` is a wrapper method on the type itself.
        if matches!(&*call.receiver, Expr::Path(p) if p.path.is_ident("self")) {
            return;
        }

        match self.nonce_ref(nonce_arg) {
            NonceRef::Other => {}
            NonceRef::Fixed => self.report_fixed(span, Origin::Fixed),
            NonceRef::Var(name)
                if NOT_NONCES.contains(&name.rsplit('.').next().unwrap_or(&name)) => {}
            NonceRef::Var(name) => {
                let info = self.state.vars.get(&name).cloned().unwrap_or_else(|| {
                    let version = self.next_version;
                    self.next_version += 1;
                    let info = VarInfo {
                        version,
                        origin: Origin::Fresh,
                    };
                    self.state.vars.insert(name.clone(), info.clone());
                    info
                });
                if info.origin != Origin::Fresh {
                    self.report_fixed(span, info.origin);
                }

                let key = (receiver, name.clone(), info.version);
                let line = span.start().line;
                let entry = self.state.uses.entry(key).or_insert((0, line));
                entry.0 += 1;
                let (count, first_line) = *entry;

                let straight = self.branches_seen == 0 && self.loops.is_empty();
                if count >= 2 && info.origin == Origin::Fresh {
                    let confidence = if straight {
                        Confidence::High
                    } else {
                        Confidence::Medium
                    };
                    self.report_once(
                        span,
                        confidence,
                        format!(
                            "nonce `{name}` is used for a second encryption with the same cipher (first use at line {first_line}): the keystream repeats"
                        ),
                        "generate a fresh random nonce for every message",
                    );
                }
                if let Some(refreshed) = self.loops.last() {
                    if !refreshed.contains(&name) && info.origin == Origin::Fresh {
                        self.report_once(
                            span,
                            Confidence::Medium,
                            format!(
                                "nonce `{name}` is defined outside this loop and never refreshed inside it: every iteration encrypts with the same nonce"
                            ),
                            "generate a fresh nonce inside the loop body",
                        );
                    }
                }
            }
        }
    }

    fn report_fixed(&mut self, span: Span, origin: Origin) {
        match origin {
            Origin::Time => self.report_once(
                span,
                Confidence::Medium,
                "nonce derived from the clock: two nodes or threads can read the same instant, and timestamps are predictable".to_string(),
                "use a random nonce, or a monotonic counter with an atomic increment and rekeying before wrap",
            ),
            Origin::Fixed => {
                let confidence = if self.fn_has_kdf {
                    Confidence::Low
                } else {
                    Confidence::Medium
                };
                self.report_once(
                    span,
                    confidence,
                    "encryption with a hardcoded nonce: every message under this key shares one keystream".to_string(),
                    "generate a fresh random nonce for every message",
                );
            }
            Origin::Fresh => {}
        }
    }
}

/// Does an expression read a local whose value came from the clock?
struct ReadsTimeVar<'a> {
    vars: &'a HashMap<String, VarInfo>,
    found: bool,
}

impl<'ast> Visit<'ast> for ReadsTimeVar<'_> {
    fn visit_expr_path(&mut self, p: &'ast syn::ExprPath) {
        if let Some(id) = p.path.get_ident() {
            if self
                .vars
                .get(&id.to_string())
                .is_some_and(|i| i.origin == Origin::Time)
            {
                self.found = true;
            }
        }
    }
}

/// Collects the names a loop body refreshes: new bindings, assignments, `&mut`
/// borrows, mutating method calls and the loop pattern itself.
#[derive(Default)]
struct Refreshed {
    names: HashSet<String>,
}

impl<'ast> Visit<'ast> for Refreshed {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        collect_pat(&local.pat, &mut self.names);
        visit::visit_local(self, local);
    }

    fn visit_expr_assign(&mut self, e: &'ast syn::ExprAssign) {
        if let Some(n) = root_name(&e.left) {
            self.names.insert(n);
        }
        visit::visit_expr_assign(self, e);
    }

    fn visit_expr_reference(&mut self, e: &'ast syn::ExprReference) {
        if e.mutability.is_some() {
            if let Some(n) = root_name(&e.expr) {
                self.names.insert(n);
            }
        }
        visit::visit_expr_reference(self, e);
    }

    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        self.names.extend(macro_idents(m));
    }

    fn visit_expr_method_call(&mut self, c: &'ast ExprMethodCall) {
        if !READ_ONLY.contains(&c.method.to_string().as_str()) {
            if let Some(n) = root_name(&c.receiver) {
                self.names.insert(n);
            }
        }
        visit::visit_expr_method_call(self, c);
    }

    fn visit_expr_for_loop(&mut self, e: &'ast syn::ExprForLoop) {
        collect_pat(&e.pat, &mut self.names);
        visit::visit_expr_for_loop(self, e);
    }
}

fn collect_pat(pat: &syn::Pat, out: &mut HashSet<String>) {
    match pat {
        syn::Pat::Ident(i) => {
            out.insert(i.ident.to_string());
        }
        syn::Pat::Type(t) => collect_pat(&t.pat, out),
        syn::Pat::Tuple(t) => t.elems.iter().for_each(|p| collect_pat(p, out)),
        syn::Pat::Reference(r) => collect_pat(&r.pat, out),
        syn::Pat::TupleStruct(t) => t.elems.iter().for_each(|p| collect_pat(p, out)),
        _ => {}
    }
}

fn has_kdf(f: &impl ToTokens) -> bool {
    let t = f.to_token_stream().to_string().to_lowercase();
    [
        "hkdf", "derive", "expand", "argon2", "pbkdf2", "scrypt", "kdf",
    ]
    .iter()
    .any(|k| t.contains(k))
}

impl Visitor<'_> {
    fn enter_fn<T>(&mut self, f: &T, walk: impl FnOnce(&mut Self))
    where
        T: ToTokens,
    {
        let saved = (
            std::mem::take(&mut self.state),
            std::mem::take(&mut self.loops),
            self.branches_seen,
            self.fn_has_kdf,
        );
        self.branches_seen = 0;
        self.fn_has_kdf = has_kdf(f);
        walk(self);
        self.state = saved.0;
        self.loops = saved.1;
        self.branches_seen = saved.2;
        self.fn_has_kdf = saved.3;
    }

    fn in_loop(&mut self, body: &impl ToTokensVisit, extra: Option<&syn::Pat>) {
        let mut refreshed = Refreshed::default();
        body.visit_with(&mut refreshed);
        if let Some(p) = extra {
            collect_pat(p, &mut refreshed.names);
        }
        self.loops.push(refreshed.names);
    }
}

/// Lets us run a `Visit` over blocks and expressions alike.
trait ToTokensVisit {
    fn visit_with<'ast, V: Visit<'ast>>(&'ast self, v: &mut V);
}

impl ToTokensVisit for syn::Block {
    fn visit_with<'ast, V: Visit<'ast>>(&'ast self, v: &mut V) {
        v.visit_block(self);
    }
}

impl ToTokensVisit for Expr {
    fn visit_with<'ast, V: Visit<'ast>>(&'ast self, v: &mut V) {
        v.visit_expr(self);
    }
}

impl<'ast> Visit<'ast> for Visitor<'_> {
    fn visit_item_fn(&mut self, f: &'ast ItemFn) {
        self.enter_fn(f, |s| visit::visit_item_fn(s, f));
    }

    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        self.enter_fn(f, |s| visit::visit_impl_item_fn(s, f));
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        visit::visit_local(self, local);
        let mut names = HashSet::new();
        collect_pat(&local.pat, &mut names);
        let origin = local
            .init
            .as_ref()
            .map_or(Origin::Fresh, |i| self.origin_of(&i.expr));
        for name in names {
            self.refresh(&name, origin);
        }
    }

    fn visit_expr_assign(&mut self, e: &'ast syn::ExprAssign) {
        visit::visit_expr_assign(self, e);
        if let Some(name) = root_name(&e.left) {
            let origin = if matches!(&*e.left, Expr::Path(_) | Expr::Field(_)) {
                self.origin_of(&e.right)
            } else {
                Origin::Fresh
            };
            self.refresh(&name, origin);
        }
    }

    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        for name in macro_idents(m) {
            if self.state.vars.contains_key(&name) {
                self.refresh(&name, Origin::Fresh);
            }
        }
    }

    fn visit_expr_reference(&mut self, e: &'ast syn::ExprReference) {
        visit::visit_expr_reference(self, e);
        if e.mutability.is_some() {
            self.refresh_expr(&e.expr);
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        let method = call.method.to_string();

        // Closures passed to iterator adapters run once per element.
        if ITER_ADAPTERS.contains(&method.as_str())
            && call.args.iter().any(|a| matches!(a, Expr::Closure(_)))
        {
            self.visit_expr(&call.receiver);
            for arg in &call.args {
                if let Expr::Closure(c) = arg {
                    let mut refreshed = Refreshed::default();
                    for input in &c.inputs {
                        collect_pat(input, &mut refreshed.names);
                    }
                    refreshed.visit_expr(&c.body);
                    self.loops.push(refreshed.names);
                    self.visit_expr(&c.body);
                    self.loops.pop();
                } else {
                    self.visit_expr(arg);
                }
            }
            return;
        }

        visit::visit_expr_method_call(self, call);

        if ENCRYPT.contains(&method.as_str()) && call.args.len() >= 2 {
            self.encrypt_call(call);
        } else if !READ_ONLY.contains(&method.as_str()) {
            // `nonce.copy_from_slice(..)`, `rng.fill_bytes(..)` on the receiver, ...
            if let Some(name) = root_name(&call.receiver) {
                if self.state.vars.contains_key(&name) {
                    self.refresh(&name, Origin::Fresh);
                }
            }
        }
    }

    fn visit_expr_if(&mut self, e: &'ast syn::ExprIf) {
        self.visit_expr(&e.cond);
        self.branches_seen += 1;
        let before = self.state.clone();
        self.visit_block(&e.then_branch);
        let after_then = std::mem::replace(&mut self.state, before);
        if let Some((_, else_branch)) = &e.else_branch {
            self.visit_expr(else_branch);
        }
        let after_else = std::mem::take(&mut self.state);
        self.state = merge(after_then, after_else);
    }

    fn visit_expr_match(&mut self, e: &'ast syn::ExprMatch) {
        self.visit_expr(&e.expr);
        self.branches_seen += 1;
        let before = self.state.clone();
        let mut merged: Option<State> = None;
        for arm in &e.arms {
            self.state = before.clone();
            if let Some((_, guard)) = &arm.guard {
                self.visit_expr(guard);
            }
            self.visit_expr(&arm.body);
            let after = std::mem::take(&mut self.state);
            merged = Some(match merged {
                Some(m) => merge(m, after),
                None => after,
            });
        }
        self.state = merged.unwrap_or(before);
    }

    fn visit_expr_for_loop(&mut self, e: &'ast syn::ExprForLoop) {
        self.visit_expr(&e.expr);
        self.in_loop(&e.body, Some(&e.pat));
        self.visit_block(&e.body);
        self.loops.pop();
    }

    fn visit_expr_while(&mut self, e: &'ast syn::ExprWhile) {
        self.in_loop(&e.body, None);
        self.visit_expr(&e.cond);
        self.visit_block(&e.body);
        self.loops.pop();
    }

    fn visit_expr_loop(&mut self, e: &'ast syn::ExprLoop) {
        self.in_loop(&e.body, None);
        self.visit_block(&e.body);
        self.loops.pop();
    }
}

/// Random-number-generator methods that write into a buffer.
const RNG_FILL: &[&str] = &["fill_bytes", "try_fill_bytes", "fill", "try_fill"];

/// Names of buffers that must be fresh for every message.
const FRESH_WORDS: &[&str] = &["nonce", "iv", "salt", "key"];

fn is_rng_name(name: &str) -> bool {
    words(name)
        .iter()
        .any(|w| matches!(w.as_str(), "rng" | "prng" | "csprng" | "rand" | "random"))
}

/// The receiver of a `.clone()` that is a random number generator: `rng`,
/// `self.rng`, `&self.rng`.
fn is_rng_expr(expr: &Expr) -> bool {
    match expr {
        Expr::Path(p) => p
            .path
            .get_ident()
            .is_some_and(|i| is_rng_name(&i.to_string())),
        Expr::Field(f) => match &f.member {
            syn::Member::Named(n) => is_rng_name(&n.to_string()),
            syn::Member::Unnamed(_) => is_rng_expr(&f.base),
        },
        Expr::Reference(r) => is_rng_expr(&r.expr),
        Expr::Paren(p) => is_rng_expr(&p.expr),
        _ => false,
    }
}

/// `x.clone()` where `x` is a random number generator.
fn is_rng_clone(expr: &Expr) -> Option<Span> {
    match expr {
        Expr::MethodCall(c) if c.method == "clone" && is_rng_expr(&c.receiver) => {
            Some(c.method.span())
        }
        Expr::Paren(p) => is_rng_clone(&p.expr),
        _ => None,
    }
}

/// A nonce, IV, salt or key filled from a copy of the generator. The copy starts
/// from the same state on every call, so every call yields the same bytes.
struct CloneRng<'a> {
    file: &'a ParsedFile,
    /// Local names bound to a cloned generator, with where it was cloned.
    rngs: HashSet<String>,
    out: Vec<Finding>,
}

impl CloneRng<'_> {
    fn check_fill(&mut self, call: &ExprMethodCall) {
        if !RNG_FILL.contains(&call.method.to_string().as_str()) {
            return;
        }
        let cloned = match &*call.receiver {
            Expr::Path(p) => p
                .path
                .get_ident()
                .is_some_and(|i| self.rngs.contains(&i.to_string())),
            other => is_rng_clone(other).is_some(),
        };
        if !cloned {
            return;
        }
        let Some(target) = call.args.first().and_then(root_name) else {
            return;
        };
        if !words(&target)
            .iter()
            .any(|w| FRESH_WORDS.contains(&w.as_str()))
        {
            return;
        }
        self.out.push(self.file.finding(
            &META,
            Confidence::Medium,
            call.method.span(),
            format!(
                "`{target}` is filled from a clone of the random number generator, so every call produces the same bytes"
            ),
            "fill it from the generator itself (`&mut self.rng`), not from a clone; a clone restarts from the same internal state",
        ));
    }
}

impl<'ast> Visit<'ast> for CloneRng<'_> {
    fn visit_item_fn(&mut self, f: &'ast ItemFn) {
        self.rngs.clear();
        visit::visit_item_fn(self, f);
    }

    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        self.rngs.clear();
        visit::visit_impl_item_fn(self, f);
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        visit::visit_local(self, local);
        let pat = match &local.pat {
            syn::Pat::Type(t) => &*t.pat,
            other => other,
        };
        if let (Some(init), syn::Pat::Ident(bound)) = (&local.init, pat) {
            if is_rng_clone(&init.expr).is_some() {
                self.rngs.insert(bound.ident.to_string());
            }
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        self.check_fill(call);
        visit::visit_expr_method_call(self, call);
    }
}
