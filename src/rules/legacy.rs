//! CA024, CA025: broken or discouraged primitives.
//!
//! Names are matched whole (`Md5`, `Rc4`, `aes_128_ecb`), never as substrings, and
//! each hit is reported once per item so a type alias and its five uses do not
//! become six findings.

use std::collections::HashSet;

use proc_macro2::Span;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    ExprPath, ImplItemFn, ItemEnum, ItemFn, ItemImpl, ItemMod, ItemStruct, ItemTrait, ItemType,
    Type, TypePath,
};

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

Also low: code that *is* the primitive. A file called `tdes.rs`, a `trait Tdes`,
`struct Md5`, `impl Cipher for Des`, or any file of a crate that declares such a
type or an enum variant like `AlgorithmId::Tdes`: a crypto library offering the
algorithm so that callers who need it for compatibility (smart cards that speak
3DES, old file formats) can have it. The mistake would be in the program that
chooses it, and that program is reported. This is decided by the names declared
in the crate, so a library that wraps the algorithm under another name is still
reported.

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
        implementing: usize::from(file.offers_primitive || file_is_primitive(file)),
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

/// Whether an item or module name is the primitive itself: `Tdes`, `md5`, `Rc4`.
fn names_primitive(ident: &str) -> bool {
    let mut chars = ident.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    let capitalised: String = first.to_uppercase().chain(chars).collect();
    // A name that merely contains `ecb` (`EcbDemo`) is not the mode itself.
    classify(&[capitalised])
        .is_some_and(|h| h.meta.id == WEAK_META.id || ident.eq_ignore_ascii_case("ecb"))
}

/// Whether `source` declares a struct, enum, trait, module or enum variant named
/// after a broken primitive: the file belongs to a crate that offers it. Reads
/// tokens only, so it is cheap enough to run on every file of a crate.
pub fn declares_primitive(source: &str) -> bool {
    let Ok(tokens) = source.parse::<proc_macro2::TokenStream>() else {
        return false;
    };
    declares_in(tokens)
}

fn declared_name_is_primitive(ident: &str) -> bool {
    // `DesForLegacyUseOnly` is a library naming the algorithm it keeps for old callers.
    let trimmed = ident
        .strip_suffix("ForLegacyUseOnly")
        .or_else(|| ident.strip_suffix("Legacy"))
        .unwrap_or(ident);
    names_primitive(trimmed)
}

fn declares_in(tokens: proc_macro2::TokenStream) -> bool {
    use proc_macro2::TokenTree;
    let mut keyword = false;
    let mut enum_next = false;
    for tt in tokens {
        match tt {
            TokenTree::Ident(i) => {
                let name = i.to_string();
                if keyword {
                    keyword = false;
                    if declared_name_is_primitive(&name) {
                        return true;
                    }
                } else if matches!(name.as_str(), "struct" | "trait" | "mod" | "union") {
                    keyword = true;
                    enum_next = false;
                } else if name == "enum" {
                    keyword = true;
                    enum_next = true;
                }
            }
            TokenTree::Group(g) => {
                if enum_next && g.delimiter() == proc_macro2::Delimiter::Brace {
                    enum_next = false;
                    if enum_variants(g.stream())
                        .iter()
                        .any(|v| declared_name_is_primitive(v))
                    {
                        return true;
                    }
                } else if declares_in(g.stream()) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// The first identifier of each comma-separated item of an enum body, skipping
/// attributes.
fn enum_variants(body: proc_macro2::TokenStream) -> Vec<String> {
    use proc_macro2::TokenTree;
    let mut out = Vec::new();
    let mut at_start = true;
    let mut depth_skip = false;
    for tt in body {
        match &tt {
            TokenTree::Punct(p) if p.as_char() == ',' => at_start = true,
            TokenTree::Punct(p) if p.as_char() == '#' => depth_skip = true,
            TokenTree::Group(_) if depth_skip => depth_skip = false,
            TokenTree::Ident(i) if at_start => {
                out.push(i.to_string());
                at_start = false;
            }
            _ => {}
        }
    }
    out
}

/// A file named for the primitive it implements: `tdes.rs`, `md5/mod.rs`.
fn file_is_primitive(file: &ParsedFile) -> bool {
    let path = &file.path;
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let name = if stem == "mod" {
        path.parent()
            .and_then(|p| p.file_name())
            .and_then(|s| s.to_str())
            .unwrap_or("")
    } else {
        stem
    };
    names_primitive(name)
}

/// The last segment of a type path: `Tdes` in `super::Tdes`.
fn type_name(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
        Type::Reference(r) => type_name(&r.elem),
        _ => None,
    }
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
    /// Depth of enclosing items that are the primitive itself.
    implementing: usize,
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
        let confidence = if self.implementing > 0 {
            hit.confidence.min(Confidence::Low)
        } else {
            hit.confidence
        };
        let finding = self.file.finding(hit.meta, confidence, span, message, help);
        self.out.push((self.item, finding));
    }

    /// Walks an item that may be the primitive's own definition.
    fn defining<T>(&mut self, is_primitive: bool, walk: impl FnOnce(&mut Self) -> T) -> T {
        self.implementing += usize::from(is_primitive);
        let out = walk(self);
        self.implementing -= usize::from(is_primitive);
        out
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

    fn visit_item_trait(&mut self, t: &'ast ItemTrait) {
        let own = names_primitive(&t.ident.to_string());
        self.defining(own, |v| visit::visit_item_trait(v, t));
    }

    fn visit_item_struct(&mut self, t: &'ast ItemStruct) {
        let own = names_primitive(&t.ident.to_string());
        self.defining(own, |v| visit::visit_item_struct(v, t));
    }

    fn visit_item_enum(&mut self, t: &'ast ItemEnum) {
        let own = names_primitive(&t.ident.to_string());
        self.defining(own, |v| visit::visit_item_enum(v, t));
    }

    fn visit_item_mod(&mut self, t: &'ast ItemMod) {
        let own = names_primitive(&t.ident.to_string());
        self.defining(own, |v| visit::visit_item_mod(v, t));
    }

    fn visit_item_impl(&mut self, t: &'ast ItemImpl) {
        let own = type_name(&t.self_ty).is_some_and(|n| names_primitive(&n))
            || t.trait_
                .as_ref()
                .and_then(|(_, p, _)| p.segments.last())
                .is_some_and(|s| names_primitive(&s.ident.to_string()));
        self.defining(own, |v| visit::visit_item_impl(v, t));
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
