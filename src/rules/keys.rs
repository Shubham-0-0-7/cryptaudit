//! CA027 and CA079: constant key or IV material reaching a cipher constructor.

use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, ItemFn};

use super::bytes::{ConstCollector, ConstEnv, Invalidate, Konst, literal_bytes, path_idents};
use super::{Rule, RuleMeta};
use crate::finding::{Confidence, Finding, Severity};
use crate::secret::words;
use crate::source::ParsedFile;

pub static KEY_META: RuleMeta = RuleMeta {
    id: "CA027",
    name: "hardcoded-key",
    severity: Severity::High,
    explain: "\
CA027: hardcoded key or IV reaching a cipher constructor

    let key = [0u8; 32];
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

A key that is a literal in the source ships in every copy of the binary, sits in
version control forever, and cannot be rotated without a release. Anyone with the
binary or the repository can decrypt everything it protects.

Detected: a byte-string, array, `vec![..]`, `hex!(..)`, `hex::decode(\"..\")` or
`include_bytes!(..)` value, directly or through a local `let`, a `const` or a
`static`, that is passed to `new`, `new_from_slice`, `Key::from_slice`,
`hmac::Key::new`, `UnboundKey::new` or a key type's `from_bytes`, on a type named
like a cipher. Also a literal IV passed to a non-CBC mode such as CTR.

Confidence:
  high    an all-zero, single-byte or counting pattern (`[0u8; 32]`)
  medium  any other literal

Fix: load the key from the environment, a secrets manager or a file, or derive it
from a password with a KDF.

Known false positives: test vectors and examples that live in non-test code. Code
under `#[cfg(test)]`, `tests/`, `benches/` and `examples/` is skipped by default,
but a \"test\" key that ships in a release binary is itself a finding.
",
};

pub static IV_META: RuleMeta = RuleMeta {
    id: "CA079",
    name: "fixed-cbc-iv",
    severity: Severity::High,
    explain: "\
CA079: fixed IV for CBC

    let enc = cbc::Encryptor::<Aes256>::new(&key.into(), &[0u8; 16].into());

With a constant IV, CBC is deterministic: two messages with the same first block
produce the same first ciphertext block, so equality between messages leaks, and
chosen-plaintext attacks such as BEAST become possible.

Fix: generate a fresh random 16-byte IV for every message and send it with the
ciphertext. Better still, use an AEAD such as AES-GCM or ChaCha20-Poly1305.

Detected: a constant passed as the IV argument of `new` or `new_from_slices` on a
type whose path mentions `cbc`.
",
};

/// Which of the two rules a visitor reports.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Which {
    Key,
    Iv,
}

pub struct HardcodedKey;
pub struct FixedCbcIv;

impl Rule for HardcodedKey {
    fn meta(&self) -> &'static RuleMeta {
        &KEY_META
    }
    fn check(&self, file: &ParsedFile) -> Vec<Finding> {
        scan(file, Which::Key)
    }
}

impl Rule for FixedCbcIv {
    fn meta(&self) -> &'static RuleMeta {
        &IV_META
    }
    fn check(&self, file: &ParsedFile) -> Vec<Finding> {
        scan(file, Which::Iv)
    }
}

fn scan(file: &ParsedFile, which: Which) -> Vec<Finding> {
    let mut consts = ConstCollector::default();
    consts.visit_file(&file.ast);
    let mut v = Visitor {
        file,
        which,
        env: consts.env.clone(),
        module_env: consts.env,
        out: Vec::new(),
    };
    v.visit_file(&file.ast);
    v.out
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SinkKind {
    Key,
    Iv { cbc: bool },
}

struct Sink<'a> {
    arg: &'a Expr,
    kind: SinkKind,
}

/// Stems distinctive enough to match inside a type name: `ChaCha20Poly1305`, `Aes256Gcm`.
const CIPHER_STEMS: &[&str] = &[
    "aes",
    "chacha",
    "salsa",
    "hmac",
    "cmac",
    "poly1305",
    "gcm",
    "ccm",
    "blowfish",
    "camellia",
    "twofish",
    "serpent",
    "kuznyechik",
];
/// Short names that must match as a whole word, so `description` and `ideal` do not.
const CIPHER_WORDS: &[&str] = &[
    "des", "idea", "aria", "sm4", "rc4", "cast5", "siv", "ocb", "eax", "xts", "cbc", "ctr", "cfb",
    "ofb", "ecb", "aead", "cipher",
];
const IV_MODES: &[&str] = &["cbc", "ctr", "cfb", "ofb", "cfb8"];
const KEY_TYPES: &[&str] = &["SigningKey", "SecretKey", "StaticSecret", "PrivateKey"];

fn has_word(seg: &str, list: &[&str]) -> bool {
    words(seg).iter().any(|w| list.contains(&w.as_str()))
}

fn is_cipher_name(seg: &str) -> bool {
    let lower = seg.to_lowercase();
    CIPHER_STEMS.iter().any(|s| lower.contains(s)) || has_word(seg, CIPHER_WORDS)
}

/// The key and IV arguments of a cipher constructor call, if it is one.
fn sinks(call: &ExprCall) -> Vec<Sink<'_>> {
    let Expr::Path(f) = &*call.func else {
        return Vec::new();
    };
    let segs = path_idents(&f.path);
    let [.., prev, last] = segs.as_slice() else {
        return Vec::new();
    };
    let args: Vec<&Expr> = call.args.iter().collect();
    let key = |i: usize| {
        args.get(i).map(|a| Sink {
            arg: a,
            kind: SinkKind::Key,
        })
    };
    let cipherish = segs[..segs.len() - 1].iter().any(|s| is_cipher_name(s));
    let cbc = segs.iter().any(|s| has_word(s, &["cbc"]));
    let iv_mode = segs.iter().any(|s| has_word(s, IV_MODES));
    let iv = |i: usize| {
        args.get(i).map(|a| Sink {
            arg: a,
            kind: SinkKind::Iv { cbc },
        })
    };

    let mut out = Vec::new();
    match last.as_str() {
        "new_from_slice" if cipherish || matches!(prev.as_str(), "KeyInit" | "Mac") => {
            out.extend(key(0));
        }
        "new_from_slices" if cipherish => {
            out.extend(key(0));
            out.extend(iv(1));
        }
        "new" if cipherish && segs.iter().any(|s| s == "hmac") && args.len() == 2 => {
            // ring: `hmac::Key::new(algorithm, key_value)`
            out.extend(key(1));
        }
        "new" if prev == "UnboundKey" && args.len() == 2 => out.extend(key(1)),
        "new" if cipherish && iv_mode && args.len() >= 2 => {
            out.extend(key(0));
            out.extend(iv(1));
        }
        "new" if cipherish && args.len() == 1 => out.extend(key(0)),
        "from_slice" | "clone_from_slice" if prev == "Key" => out.extend(key(0)),
        "from_bytes" | "from" | "from_slice" | "new" if KEY_TYPES.contains(&prev.as_str()) => {
            out.extend(key(0));
        }
        _ => {}
    }
    out
}

/// Is `expr` itself a recognised sink call, which will be reported on its own?
fn is_inner_sink(expr: &Expr) -> bool {
    match expr {
        Expr::Reference(e) => is_inner_sink(&e.expr),
        Expr::Paren(e) => is_inner_sink(&e.expr),
        Expr::MethodCall(c) => is_inner_sink(&c.receiver),
        Expr::Call(c) => !sinks(c).is_empty(),
        _ => false,
    }
}

struct Visitor<'a> {
    file: &'a ParsedFile,
    which: Which,
    /// Module constants plus the current function's locals.
    env: ConstEnv,
    module_env: ConstEnv,
    out: Vec<Finding>,
}

impl<'ast> Visit<'ast> for Visitor<'_> {
    fn visit_item_fn(&mut self, f: &'ast ItemFn) {
        let saved = std::mem::replace(&mut self.env, self.module_env.clone());
        visit::visit_item_fn(self, f);
        self.env = saved;
    }

    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        let saved = std::mem::replace(&mut self.env, self.module_env.clone());
        visit::visit_impl_item_fn(self, f);
        self.env = saved;
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        visit::visit_local(self, local);
        let pat = match &local.pat {
            syn::Pat::Type(t) => &*t.pat,
            other => other,
        };
        if let syn::Pat::Ident(bound) = pat {
            let name = bound.ident.to_string();
            match local
                .init
                .as_ref()
                .and_then(|i| literal_bytes(&i.expr, &self.env))
            {
                Some(k) => {
                    self.env.insert(name, k);
                }
                None => {
                    self.env.remove(&name);
                }
            }
        }
    }

    // Work out what the statements before this call did to the locals.
    fn visit_expr_reference(&mut self, e: &'ast syn::ExprReference) {
        Invalidate { env: &mut self.env }.visit_expr_reference(e);
        visit::visit_expr_reference(self, e);
    }

    fn visit_expr_assign(&mut self, e: &'ast syn::ExprAssign) {
        Invalidate { env: &mut self.env }.visit_expr_assign(e);
        visit::visit_expr_assign(self, e);
    }

    fn visit_expr_method_call(&mut self, c: &'ast syn::ExprMethodCall) {
        // Report calls inside the arguments first, then record the mutation.
        for arg in &c.args {
            self.visit_expr(arg);
        }
        self.visit_expr(&c.receiver);
        Invalidate { env: &mut self.env }.visit_expr_method_call(c);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        for sink in sinks(call) {
            if is_inner_sink(sink.arg) {
                continue;
            }
            let Some(konst) = literal_bytes(sink.arg, &self.env) else {
                continue;
            };
            self.report(call, &sink, konst);
        }
        visit::visit_expr_call(self, call);
    }
}

impl Visitor<'_> {
    fn report(&mut self, call: &ExprCall, sink: &Sink<'_>, konst: Konst) {
        let Expr::Path(f) = &*call.func else { return };
        let callee = path_idents(&f.path).join("::");
        let span = f
            .path
            .segments
            .last()
            .map_or_else(proc_macro2::Span::call_site, |s| s.ident.span());
        let pattern = match konst {
            Konst::Degenerate => "an all-same-byte or counting pattern",
            Konst::Plain => "a literal",
        };
        let (meta, confidence, message, help) = match sink.kind {
            SinkKind::Iv { cbc: true } => (
                &IV_META,
                Confidence::High,
                format!("fixed IV passed to `{callee}`: CBC with a constant IV is deterministic"),
                "generate a fresh random IV per message and send it with the ciphertext, or use an AEAD",
            ),
            SinkKind::Iv { cbc: false } => (
                &KEY_META,
                confidence_of(konst),
                format!("hardcoded IV ({pattern}) passed to `{callee}`"),
                "generate a fresh random IV per message",
            ),
            SinkKind::Key => (
                &KEY_META,
                confidence_of(konst),
                format!("hardcoded key ({pattern}) passed to `{callee}`"),
                "load the key from the environment or a secrets manager, or derive it with a KDF",
            ),
        };
        let wanted = match meta.id {
            "CA079" => Which::Iv,
            _ => Which::Key,
        };
        if wanted == self.which {
            self.out
                .push(self.file.finding(meta, confidence, span, message, help));
        }
    }
}

fn confidence_of(konst: Konst) -> Confidence {
    match konst {
        Konst::Degenerate => Confidence::High,
        Konst::Plain => Confidence::Medium,
    }
}
