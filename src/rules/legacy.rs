//! CA024, CA025: broken or discouraged primitives.
//!
//! Names are matched whole (`Md5`, `Rc4`, `aes_128_ecb`), never as substrings, and
//! each hit is reported once per item so a type alias and its five uses do not
//! become six findings.

use std::collections::HashSet;

use proc_macro2::Span;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{ExprPath, ImplItemFn, ItemFn, ItemType, TypePath};

use super::{Rule, RuleMeta};
use crate::finding::{Confidence, Finding, Severity};
use crate::secret::words;
use crate::source::ParsedFile;

pub static WEAK_META: RuleMeta = RuleMeta {
    id: "CA024",
    name: "weak-primitive",
    severity: Severity::High,
    explain: "\
CA024: broken cipher or hash

    let mut cipher = Rc4::new(&key.into());
    let digest = Md5::digest(certificate_bytes);

Cryptographic primitives wear out. Some are now broken so badly that using
them gives a false sense of safety:

  RC4, RC2, DES, 3DES  encryption that can be broken, or that leaks the
                       plaintext when enough data is sent. DES has a 56-bit
                       key, which can be tried in full in hours. RC4's output
                       is statistically biased. 3DES has a 64-bit block and is
                       attackable after a few hundred gigabytes (\"Sweet32\").
  MD5, MD4, MD2        hashes for which anyone can produce two different
                       inputs with the same digest, in seconds on a laptop.
  SHA-1                the same, at a cost of a few thousand dollars of
                       computing time since 2017.

A hash is used for many things. A checksum that only catches accidents
(a corrupted download) does not need collision resistance. A signature, a
certificate fingerprint or a \"has this file been tampered with\" check does:
if an attacker can craft a second file with the same hash, the check passes.

Confidence:
  medium  a broken cipher (RC4, RC2, DES, 3DES). Almost never intended.
  low     MD5, MD4, MD2 or SHA-1. Hidden unless `--min-confidence low` is
          given, because most uses are checksums, cache keys, `git` object
          ids, or HMAC-SHA1 (which is still sound), and cannot be told apart
          from the source.

Fix: AES-GCM or ChaCha20-Poly1305 for encryption; SHA-256 or BLAKE3 for hashing;
Argon2 for passwords (see CA063).

Known false positives: a legacy file format or protocol that mandates the
algorithm (the primitive is then required, and should be contained), and
non-security checksums.
",
};

pub static ECB_META: RuleMeta = RuleMeta {
    id: "CA025",
    name: "ecb-mode",
    severity: Severity::High,
    explain: "\
CA025: ECB mode

    type Aes128Ecb = ecb::Encryptor<aes::Aes128>;
    let cipher = openssl::symm::Cipher::aes_128_ecb();

AES encrypts one 16-byte block at a time. A *mode* says how blocks are chained.
ECB, \"electronic codebook\", is the mode with no chaining: the same 16 bytes of
plaintext always become the same 16 bytes of ciphertext. So patterns in the
message survive encryption. The classic picture is a bitmap of a penguin
encrypted with AES-ECB: the penguin's outline is still plainly visible. In
practice an attacker can see which records are equal, can cut and paste blocks
from one message into another, and can often work out the contents block by
block.

ECB offers no authentication either, so tampering is not detected.

Fix: an authenticated mode, AES-GCM or ChaCha20-Poly1305, with a fresh nonce
per message.

Confidence:
  high    a named ECB constructor: `ecb::Encryptor`, `Cipher::aes_128_ecb()`
  low     any other name with ECB in it (`Aes128EcbEnc`, `Mode::ECB`, an FFI
          call such as `AES_ecb_encrypt`). Hidden unless `--min-confidence low`
          is given: a cipher library lists ECB among its modes, and QUIC
          header protection uses single-block AES-ECB on purpose.

Known false positives: ECB on exactly one block of random data is sound and
is how some protocols derive keys or wrap them (for example the YubiKey OTP
format). A cipher library that implements every mode lists ECB among them.
",
};

pub struct WeakPrimitive;
pub struct EcbMode;

impl Rule for WeakPrimitive {
    fn meta(&self) -> &'static RuleMeta {
        &WEAK_META
    }
    fn check(&self, file: &ParsedFile) -> Vec<Finding> {
        scan(file, WEAK_META.id)
    }
}

impl Rule for EcbMode {
    fn meta(&self) -> &'static RuleMeta {
        &ECB_META
    }
    fn check(&self, file: &ParsedFile) -> Vec<Finding> {
        scan(file, ECB_META.id)
    }
}

fn scan(file: &ParsedFile, rule: &'static str) -> Vec<Finding> {
    let mut v = Visitor {
        file,
        rule,
        item: None,
        seen: HashSet::new(),
        out: Vec::new(),
    };
    v.visit_file(&file.ast);
    // One finding per item, the most confident one: a type alias and the calls
    // through it are one problem.
    let mut best: Vec<(Option<usize>, Finding)> = Vec::new();
    for (item, f) in v.out {
        match best.iter_mut().find(|(i, _)| *i == item && item.is_some()) {
            Some((_, kept)) if f.confidence > kept.confidence => *kept = f,
            Some(_) => {}
            None => best.push((item, f)),
        }
    }
    best.into_iter().map(|(_, f)| f).collect()
}

/// What a path names, and how sure we are that it is a problem.
struct Hit {
    meta: &'static RuleMeta,
    confidence: Confidence,
    name: String,
    why: &'static str,
}

fn classify(segs: &[String]) -> Option<Hit> {
    for (i, seg) in segs.iter().enumerate() {
        // A lone lowercase name is a variable (`let md5 = ..`, `des` for destination).
        if segs.len() == 1 && seg.chars().next().is_some_and(char::is_lowercase) {
            continue;
        }
        // `DES_CBC_IV_LEN` is a constant of a cipher library, and an algorithm that
        // is already named `..ForLegacyUseOnly` is a choice someone made with open eyes.
        if !seg.chars().any(char::is_lowercase) || seg.to_lowercase().contains("legacy") {
            continue;
        }
        let n = seg.to_lowercase().replace('_', "");
        let cipher = |why| Hit {
            meta: &WEAK_META,
            confidence: Confidence::Medium,
            name: seg.clone(),
            why,
        };
        let hash = |why| Hit {
            meta: &WEAK_META,
            confidence: Confidence::Low,
            name: seg.clone(),
            why,
        };
        if matches!(
            n.as_str(),
            "rc4"
                | "rc2"
                | "arcfour"
                | "des"
                | "des3"
                | "tdes"
                | "desede2"
                | "desede3"
                | "tdesede2"
                | "tdesede3"
        ) || n.starts_with("rc4")
            || n.starts_with("descbc")
            || n.starts_with("desecb")
            || n.starts_with("desede")
            || n.starts_with("rc2cbc")
        {
            return Some(cipher(
                "is a broken cipher: it can be attacked in practice, so data encrypted with it is not safe",
            ));
        }
        if matches!(n.as_str(), "md5" | "md4" | "md2" | "sha1") || n.starts_with("sha1for") {
            return Some(hash(
                "is broken for anything that needs collision resistance (signatures, certificates, tamper checks); it is fine for a plain checksum",
            ));
        }
        let ws = words(seg);
        if ws.iter().any(|w| w == "ecb") {
            // `ecb::Encryptor`, `Cipher::aes_128_ecb()`, `block_modes::Ecb<..>`
            let named = (i + 1 < segs.len() && seg == "ecb")
                || segs[..i]
                    .iter()
                    .any(|s| s == "Cipher" || s == "block_modes");
            return Some(Hit {
                meta: &ECB_META,
                confidence: if named
                    || (seg == "Ecb"
                        && segs[..i]
                            .iter()
                            .all(|s| s.chars().next().is_some_and(char::is_lowercase)))
                {
                    Confidence::High
                } else {
                    Confidence::Low
                },
                name: seg.clone(),
                why: "encrypts equal blocks to equal ciphertext, so patterns in the message show through",
            });
        }
    }
    None
}

struct Visitor<'a> {
    file: &'a ParsedFile,
    rule: &'static str,
    /// Line of the function, alias or other item being visited.
    item: Option<usize>,
    /// `(item line, hit name)` already reported.
    seen: HashSet<(Option<usize>, String)>,
    out: Vec<(Option<usize>, Finding)>,
}

impl Visitor<'_> {
    fn path(&mut self, path: &syn::Path, span: Span) {
        let segs: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        let Some(hit) = classify(&segs) else {
            return;
        };
        if hit.meta.id != self.rule || !self.seen.insert((self.item, hit.name.clone())) {
            return;
        }
        let (help, message) = if hit.meta.id == ECB_META.id {
            (
                "use AES-GCM or ChaCha20-Poly1305 with a fresh nonce per message",
                format!("`{}` {}", hit.name, hit.why),
            )
        } else {
            (
                "use AES-GCM or ChaCha20-Poly1305 for encryption, SHA-256 or BLAKE3 for hashing, Argon2 for passwords",
                format!("`{}` {}", hit.name, hit.why),
            )
        };
        let finding = self
            .file
            .finding(hit.meta, hit.confidence, span, message, help);
        self.out.push((self.item, finding));
    }

    fn within<T>(&mut self, line: usize, walk: impl FnOnce(&mut Self) -> T) -> T {
        let saved = self.item.replace(line);
        let out = walk(self);
        self.item = saved;
        out
    }
}

impl<'ast> Visit<'ast> for Visitor<'_> {
    fn visit_item_fn(&mut self, f: &'ast ItemFn) {
        self.within(f.span().start().line, |v| visit::visit_item_fn(v, f));
    }

    fn visit_impl_item_fn(&mut self, f: &'ast ImplItemFn) {
        self.within(f.span().start().line, |v| visit::visit_impl_item_fn(v, f));
    }

    fn visit_item_type(&mut self, t: &'ast ItemType) {
        self.within(t.span().start().line, |v| visit::visit_item_type(v, t));
    }

    fn visit_expr_path(&mut self, p: &'ast ExprPath) {
        self.path(&p.path, p.span());
        visit::visit_expr_path(self, p);
    }

    fn visit_type_path(&mut self, p: &'ast TypePath) {
        self.path(&p.path, p.span());
        visit::visit_type_path(self, p);
    }
}
