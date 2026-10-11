//! CA023, CA071, CA072: random number generators that must not produce secrets.
//!
//! `SmallRng::seed_from_u64(42)` is fine for a simulation and a bug for a key.
//! The rules therefore track what each generator is used for: a finding is only
//! confident when the generator's output reaches a binding named like a key, a
//! nonce, an IV, a salt or a secret.

use std::collections::HashMap;

use proc_macro2::Span;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, ExprMethodCall, ItemFn, Lit};

use super::bytes::{ConstCollector, ConstEnv, literal_bytes, mentions_time, path_idents, root_var};
use super::{Rule, RuleMeta};
use crate::finding::{Confidence, Finding, Severity};
use crate::secret::{Strength, classify_name, words};
use crate::source::ParsedFile;

pub static WEAK_META: RuleMeta = RuleMeta {
    id: "CA023",
    name: "non-csprng-for-secret",
    severity: Severity::High,
    explain: "\
CA023: non-cryptographic RNG generating a key, nonce, IV or salt

    let mut rng = SmallRng::from_entropy();
    let key: [u8; 32] = rng.gen();

`SmallRng`, `fastrand`, `oorandom`, the PCG and xoshiro families, `StepRng` and
the other general-purpose generators are fast and statistically good, and
predictable: observing a few outputs is enough to compute every later one, and in
some cases every earlier one. `SmallRng` is documented as not suitable for
cryptography.

Reported only when the generator's output reaches a binding named like a secret:
`key`, `secret`, `token`, `password`, `nonce`, `iv`, `salt`, a struct field of
that name, or `rng.fill_bytes(&mut key)`.

Not reported: `thread_rng()`, `rand::random()` and `StdRng::from_entropy()`.
`ThreadRng` and `StdRng` are documented as cryptographically secure, so using them
for keys is fine.

Fix: `OsRng`, or `rand::thread_rng()` / `StdRng::from_entropy()`.

Confidence:
  high    the binding is named `secret`, `password`, `nonce`, `iv`, `salt`, ...
  medium  the binding is named `key` or `token`, which also have benign uses
",
};

pub static FIXED_META: RuleMeta = RuleMeta {
    id: "CA071",
    name: "fixed-rng-seed",
    severity: Severity::Critical,
    explain: "\
CA071: random number generator seeded with a constant

    let mut rng = StdRng::seed_from_u64(42);
    let key: [u8; 32] = rng.gen();      // the same key on every run

A seeded generator is deterministic. With a constant seed, every run, on every
machine, produces the same sequence, so the \"random\" key is a constant that
anyone can regenerate.

Detected: `seed_from_u64(<literal or const>)`, `from_seed([<literals>])`,
`with_seed(..)` and `fastrand::seed(..)`.

Confidence:
  high    the generator's output reaches a key, nonce, IV, salt or secret
  medium  the generator is a cryptographic one (`StdRng`, `ChaCha20Rng`): someone
          chose it for security, then seeded it with a constant
  low     any other generator with no sign of use for secrets, which is most
          simulation, game and benchmark code

Known false positives: reproducible tests and benchmarks that are not in a test
directory.
",
};

pub static TIME_META: RuleMeta = RuleMeta {
    id: "CA072",
    name: "time-seeded-rng",
    severity: Severity::Critical,
    explain: "\
CA072: random number generator seeded from the clock

    let mut rng = StdRng::seed_from_u64(SystemTime::now()
        .duration_since(UNIX_EPOCH)?.as_secs());
    let key: [u8; 32] = rng.gen();

The seed has a few bits of entropy, not 256. A clock reading to the second is one
of about 31 million values per year, so an attacker who knows roughly when the key
was made can try every candidate in moments.

Detected: a seed expression that reads `SystemTime`, `Instant`, `UNIX_EPOCH`, a
timestamp or `elapsed`.

Confidence is graded as for CA071.

Fix: `StdRng::from_entropy()` or `OsRng`.
",
};

pub struct WeakRng;
pub struct FixedSeed;
pub struct TimeSeed;

impl Rule for WeakRng {
    fn meta(&self) -> &'static RuleMeta {
        &WEAK_META
    }
    fn check(&self, file: &ParsedFile) -> Vec<Finding> {
        scan(file, WEAK_META.id)
    }
}

impl Rule for FixedSeed {
    fn meta(&self) -> &'static RuleMeta {
        &FIXED_META
    }
    fn check(&self, file: &ParsedFile) -> Vec<Finding> {
        scan(file, FIXED_META.id)
    }
}

impl Rule for TimeSeed {
    fn meta(&self) -> &'static RuleMeta {
        &TIME_META
    }
    fn check(&self, file: &ParsedFile) -> Vec<Finding> {
        scan(file, TIME_META.id)
    }
}

fn scan(file: &ParsedFile, rule: &'static str) -> Vec<Finding> {
    let mut consts = ConstCollector::default();
    consts.visit_file(&file.ast);
    let mut ints = IntCollector::default();
    ints.visit_file(&file.ast);
    let mut v = Visitor {
        file,
        rule,
        consts: consts.env,
        module_ints: ints.env.clone(),
        ints: ints.env,
        rngs: HashMap::new(),
        sites: Vec::new(),
        bound: HashMap::new(),
        out: Vec::new(),
    };
    v.visit_file(&file.ast);
    v.flush_sites();
    v.out
}

/// Whether an integer is a constant, or comes from the clock.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SeedKind {
    Fixed,
    Time,
}

type IntEnv = HashMap<String, SeedKind>;

#[derive(Default)]
struct IntCollector {
    env: IntEnv,
}

impl<'ast> Visit<'ast> for IntCollector {
    fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
        if is_int_lit(&item.expr) {
            self.env.insert(item.ident.to_string(), SeedKind::Fixed);
        }
        visit::visit_item_const(self, item);
    }
}

fn is_int_lit(expr: &Expr) -> bool {
    match expr {
        Expr::Lit(l) => matches!(l.lit, Lit::Int(_)),
        Expr::Unary(u) => is_int_lit(&u.expr),
        Expr::Paren(p) => is_int_lit(&p.expr),
        Expr::Cast(c) => is_int_lit(&c.expr),
        _ => false,
    }
}

/// Generators that are not cryptographically secure.
fn is_weak_type(seg: &str) -> bool {
    let l = seg.to_lowercase();
    [
        "smallrng", "steprng", "wyrand", "mt19937", "mersenne", "splitmix",
    ]
    .contains(&l.as_str())
        || ["pcg", "xoshiro", "xoroshiro", "xorshift", "lcg", "mcg"]
            .iter()
            .any(|p| l.starts_with(p))
        || matches!(
            l.as_str(),
            "fastrand" | "oorandom" | "nanorand" | "tinyrand"
        )
}

/// Generators documented as cryptographically secure.
fn is_csprng_type(seg: &str) -> bool {
    let l = seg.to_lowercase();
    matches!(l.as_str(), "stdrng" | "threadrng" | "osrng" | "hc128rng")
        || (l.starts_with("chacha") && l.ends_with("rng"))
}

const SEED_FNS: &[&str] = &["seed_from_u64", "from_seed", "with_seed", "seed"];

/// Methods that draw numbers out of a generator.
const DRAW: &[&str] = &[
    "gen",
    "r#gen",
    "gen_range",
    "gen_bool",
    "gen_ratio",
    "fill",
    "fill_bytes",
    "try_fill",
    "try_fill_bytes",
    "next_u32",
    "next_u64",
    "random",
    "random_range",
    "sample",
    "sample_iter",
    "u8",
    "u16",
    "u32",
    "u64",
    "u128",
    "usize",
    "i8",
    "i16",
    "i32",
    "i64",
    "i128",
    "isize",
    "alphanumeric",
    "bool",
    "char",
    "f32",
    "f64",
];
const FILL: &[&str] = &["fill", "fill_bytes", "try_fill", "try_fill_bytes"];

const NONCE_WORDS: &[&str] = &["nonce", "nonces", "iv", "ivs", "salt", "salts"];
const METADATA: &[&str] = &[
    "len", "length", "size", "count", "index", "idx", "bits", "type", "kind", "version", "format",
    "name", "path", "id", "ids", "url", "uri", "hash", "expiry", "ttl", "prefix", "label", "error",
];

/// How secret a binding name sounds, as a confidence.
fn secret_name(name: &str) -> Option<Confidence> {
    let ws = words(name);
    if ws.iter().any(|w| METADATA.contains(&w.as_str())) {
        return None;
    }
    if ws.iter().any(|w| NONCE_WORDS.contains(&w.as_str())) {
        return Some(Confidence::High);
    }
    match classify_name(name)? {
        Strength::Strong => Some(Confidence::High),
        Strength::Weak => Some(Confidence::Medium),
    }
}

#[derive(Clone, Default)]
struct RngInfo {
    weak: bool,
    /// Output has reached a secret-named binding.
    secret_use: bool,
}

/// A place where a generator is seeded.
struct Site {
    span: Span,
    kind: SeedKind,
    csprng: bool,
    weak: bool,
    var: Option<String>,
}

struct Visitor<'a> {
    file: &'a ParsedFile,
    rule: &'static str,
    consts: ConstEnv,
    module_ints: IntEnv,
    ints: IntEnv,
    rngs: HashMap<String, RngInfo>,
    sites: Vec<Site>,
    /// Seeding call (by source position) -> the variable it is bound to.
    bound: HashMap<(usize, usize), String>,
    out: Vec<Finding>,
}

fn pos(span: Span) -> (usize, usize) {
    (span.start().line, span.start().column)
}

/// A call that constructs a generator: `SmallRng::from_entropy()`, `fastrand::Rng::new()`.
fn constructor(call: &ExprCall) -> Option<(Vec<String>, String)> {
    let Expr::Path(f) = &*call.func else {
        return None;
    };
    let segs = path_idents(&f.path);
    let last = segs.last()?.clone();
    Some((segs, last))
}

impl Visitor<'_> {
    fn seed_kind(&self, arg: &Expr) -> Option<SeedKind> {
        if mentions_time(arg) {
            return Some(SeedKind::Time);
        }
        if is_int_lit(arg) || literal_bytes(arg, &self.consts).is_some() {
            return Some(SeedKind::Fixed);
        }
        if let Expr::Path(p) = arg {
            return self.ints.get(&p.path.get_ident()?.to_string()).copied();
        }
        None
    }

    /// The generator an expression draws from, if it draws from one we know.
    fn draws_from(&self, expr: &Expr) -> Option<String> {
        struct Finder<'a> {
            rngs: &'a HashMap<String, RngInfo>,
            found: Option<String>,
        }
        impl<'ast> Visit<'ast> for Finder<'_> {
            fn visit_expr_method_call(&mut self, c: &'ast ExprMethodCall) {
                if let Some(name) = root_var(&c.receiver) {
                    if let Some(info) = self.rngs.get(&name) {
                        let m = c.method.to_string();
                        if info.weak || DRAW.contains(&m.as_str()) {
                            self.found.get_or_insert(name);
                        }
                    }
                }
                visit::visit_expr_method_call(self, c);
            }

            fn visit_expr_call(&mut self, c: &'ast ExprCall) {
                // `fastrand::u8(..)`, `oorandom::..`: free functions on a global weak RNG.
                if let Expr::Path(f) = &*c.func {
                    let segs = path_idents(&f.path);
                    if segs.len() >= 2 && matches!(segs[0].as_str(), "fastrand" | "oorandom") {
                        self.found.get_or_insert_with(|| segs[0].clone());
                    }
                }
                visit::visit_expr_call(self, c);
            }
        }
        let mut f = Finder {
            rngs: &self.rngs,
            found: None,
        };
        f.visit_expr(expr);
        f.found
    }

    /// A secret-named binding received output from generator `rng`.
    fn secret_bound(&mut self, rng: &str, name: &str, span: Span) {
        let Some(conf) = secret_name(name) else {
            return;
        };
        let weak = match self.rngs.get_mut(rng) {
            Some(info) => {
                info.secret_use = true;
                info.weak
            }
            // `fastrand::..` free functions.
            None => true,
        };
        if weak && self.rule == WEAK_META.id {
            self.out.push(self.file.finding(
                &WEAK_META,
                conf,
                span,
                format!(
                    "`{name}` is generated by a non-cryptographic RNG (`{rng}`): its output can be predicted"
                ),
                "use `OsRng`, or `rand::thread_rng()` / `StdRng::from_entropy()`",
            ));
        }
    }

    fn flush_sites(&mut self) {
        let sites = std::mem::take(&mut self.sites);
        for site in sites {
            let secret = site
                .var
                .as_ref()
                .and_then(|v| self.rngs.get(v))
                .is_some_and(|i| i.secret_use);
            let confidence = if secret {
                Confidence::High
            } else if site.csprng {
                Confidence::Medium
            } else {
                Confidence::Low
            };
            let (meta, what, help) = match site.kind {
                SeedKind::Fixed => (
                    &FIXED_META,
                    "seeded with a constant: every run produces the same sequence",
                    "seed from the operating system (`from_entropy()`) or use `OsRng`",
                ),
                SeedKind::Time => (
                    &TIME_META,
                    "seeded from the clock: the seed has only a few bits of entropy",
                    "seed from the operating system (`from_entropy()`) or use `OsRng`",
                ),
            };
            if meta.id != self.rule {
                continue;
            }
            let subject = if secret {
                "random number generator that produces a secret is"
            } else {
                "random number generator is"
            };
            let _ = site.weak;
            self.out.push(self.file.finding(
                meta,
                confidence,
                site.span,
                format!("{subject} {what}"),
                help,
            ));
        }
    }
}

impl<'ast> Visit<'ast> for Visitor<'_> {
    fn visit_item_fn(&mut self, f: &'ast ItemFn) {
        self.fn_scope(|s| visit::visit_item_fn(s, f));
    }

    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        self.fn_scope(|s| visit::visit_impl_item_fn(s, f));
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        let pat = match &local.pat {
            syn::Pat::Type(t) => &*t.pat,
            other => other,
        };
        let name = match pat {
            syn::Pat::Ident(i) => Some(i.ident.to_string()),
            _ => None,
        };

        if let (Some(name), Some(init)) = (&name, &local.init) {
            let expr = peel(&init.expr);
            // `let mut rng = SmallRng::seed_from_u64(7);`
            if let Expr::Call(call) = expr {
                if let Some((segs, last)) = constructor(call) {
                    let weak = segs.iter().any(|s| is_weak_type(s));
                    let seeding = SEED_FNS.contains(&last.as_str());
                    let rng_like = weak
                        || segs.iter().any(|s| is_csprng_type(s))
                        || (seeding && segs.iter().any(|s| s.ends_with("Rng")));
                    if rng_like {
                        self.rngs.insert(
                            name.clone(),
                            RngInfo {
                                weak,
                                secret_use: false,
                            },
                        );
                        if seeding {
                            if let Some(span) = last_segment_span(call) {
                                self.bound.insert(pos(span), name.clone());
                            }
                        }
                    }
                }
            }
            // Integer seeds: `let seed = 42;`, `let seed = now.as_secs();`
            if let Some(kind) = self.seed_kind(expr) {
                self.ints.insert(name.clone(), kind);
            } else {
                self.ints.remove(name);
            }
        }

        visit::visit_local(self, local);

        // `let key = rng.gen();`
        if let (Some(name), Some(init)) = (&name, &local.init) {
            if let Some(rng) = self.draws_from(&init.expr) {
                self.secret_bound(&rng, name, local.pat.span());
            }
        }
    }

    fn visit_expr_reference(&mut self, e: &'ast syn::ExprReference) {
        // `fill_bytes(&mut seed)`: the local is no longer the constant it started as.
        if e.mutability.is_some() {
            if let Some(name) = root_var(&e.expr) {
                self.ints.remove(&name);
            }
        }
        visit::visit_expr_reference(self, e);
    }

    fn visit_expr_assign(&mut self, e: &'ast syn::ExprAssign) {
        visit::visit_expr_assign(self, e);
        if let Some(name) = root_var(&e.left) {
            self.ints.remove(&name);
            if let Some(rng) = self.draws_from(&e.right) {
                self.secret_bound(&rng, &name, e.right.span());
            }
        }
    }

    fn visit_field_value(&mut self, fv: &'ast syn::FieldValue) {
        visit::visit_field_value(self, fv);
        if let syn::Member::Named(name) = &fv.member {
            if let Some(rng) = self.draws_from(&fv.expr) {
                self.secret_bound(&rng, &name.to_string(), fv.expr.span());
            }
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        visit::visit_expr_method_call(self, call);
        if !matches!(
            call.method.to_string().as_str(),
            "as_ref" | "as_slice" | "to_vec" | "clone" | "len" | "iter" | "into"
        ) {
            if let Some(name) = root_var(&call.receiver) {
                self.ints.remove(&name);
            }
        }
        // `rng.fill_bytes(&mut key)`
        let method = call.method.to_string();
        if FILL.contains(&method.as_str()) {
            if let Some(rng) = root_var(&call.receiver) {
                if self.rngs.contains_key(&rng) {
                    for arg in &call.args {
                        if let Some(name) = root_var(arg) {
                            self.secret_bound(&rng, &name, call.method.span());
                        }
                    }
                }
            }
        }
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Some((segs, last)) = constructor(call) {
            if SEED_FNS.contains(&last.as_str()) {
                // `fastrand::seed(..)`: free function. Others: `Type::seed_from_u64(..)`.
                let is_rng = segs.iter().any(|s| s.ends_with("Rng") || is_weak_type(s))
                    || segs.first().is_some_and(|s| s == "fastrand");
                if let (true, Some(arg)) = (is_rng, call.args.first()) {
                    if let Some(kind) = self.seed_kind(arg) {
                        if let Some(span) = last_segment_span(call) {
                            self.sites.push(Site {
                                span,
                                kind,
                                csprng: segs.iter().any(|s| is_csprng_type(s)),
                                weak: segs.iter().any(|s| is_weak_type(s)),
                                var: self.bound.get(&pos(span)).cloned(),
                            });
                        }
                    }
                }
            }
        }
        visit::visit_expr_call(self, call);
    }
}

impl Visitor<'_> {
    fn fn_scope(&mut self, walk: impl FnOnce(&mut Self)) {
        let saved_rngs = std::mem::take(&mut self.rngs);
        let saved_sites = std::mem::take(&mut self.sites);
        let saved_ints = std::mem::replace(&mut self.ints, self.module_ints.clone());
        walk(self);
        self.flush_sites();
        self.rngs = saved_rngs;
        self.sites = saved_sites;
        self.ints = saved_ints;
    }
}

fn peel(expr: &Expr) -> &Expr {
    match expr {
        Expr::Paren(p) => peel(&p.expr),
        Expr::Group(g) => peel(&g.expr),
        Expr::Try(t) => peel(&t.expr),
        Expr::MethodCall(c)
            if matches!(c.method.to_string().as_str(), "unwrap" | "expect" | "clone") =>
        {
            peel(&c.receiver)
        }
        other => other,
    }
}

fn last_segment_span(call: &ExprCall) -> Option<Span> {
    let Expr::Path(f) = &*call.func else {
        return None;
    };
    Some(f.path.segments.last()?.ident.span())
}
