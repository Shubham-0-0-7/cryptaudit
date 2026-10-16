//! CA011, CA012, CA013: derive macros that silently give a secret type a
//! capability it should not have. Same detector as CA010, different derive.

use std::collections::HashMap;

use quote::ToTokens;
use syn::visit::{self, Visit};
use syn::{Field, ItemImpl, ItemStruct, Type};

use super::ca010::{DeriveHit, Items, derive_hits, fallback_owner, leaking_fields};
use super::{Rule, RuleMeta};
use crate::finding::{Confidence, Finding, Severity};
use crate::secret::{Strength, classify_type_name, is_place_name, is_public_name, words};
use crate::source::ParsedFile;

pub static COPY_META: RuleMeta = RuleMeta {
    id: "CA011",
    name: "copy-on-secret",
    severity: Severity::Medium,
    explain: "\
CA011: `#[derive(Copy)]` on a secret type

`Copy` makes every assignment and every by-value call an implicit duplicate
of the key material. Zeroizing one owner leaves every other copy in memory.
Worse, a `Copy` type cannot implement `Drop`, so `ZeroizeOnDrop` is
structurally impossible: the compiler forbids the fix.

    #[derive(Clone, Copy)]
    struct SessionKey([u8; 32]);

Fix: do not derive `Copy` on secrets. Derive `Clone` only where a copy is
really needed, and pair it with `ZeroizeOnDrop`.

False positives: a type named like a secret that only holds public data,
or a deliberately short-lived key in a test helper.
",
};

pub static SERIALIZE_META: RuleMeta = RuleMeta {
    id: "CA012",
    name: "serialize-on-secret",
    severity: Severity::High,
    explain: "\
CA012: `#[derive(Serialize)]` on a secret type

One `serde_json::to_string(&config)` writes the key into a log line, a
metrics payload, an error response or a cache entry. It is the same
mechanism as CA010, with a wider blast radius, because serialised output
routinely crosses a network boundary.

    #[derive(Serialize)]
    struct Config { api_key: String, endpoint: String }

Fix: `#[serde(skip)]` on the secret field, or a newtype with a redacting
`Serialize` impl. Fields with `skip`, `skip_serializing`, `serialize_with`
or `with` are not reported.

Confidence: high when the type is itself named like a clear secret
(`SessionKey`, `StaticSecret`); low when it is an ordinary record
(`Config { api_key }`, `TokenRequest`, `Credentials`), because most such
records exist to be serialised. A type named `*Request`, `*Response`, `*Args`
or `*Opts` is a record, whatever its other words say. Low findings are hidden unless `--min-confidence low` is given.

False positives: a type that is meant to be written to an encrypted
keystore or config file on purpose. Suppress those with a comment saying why.
",
};

pub static EQ_META: RuleMeta = RuleMeta {
    id: "CA013",
    name: "partialeq-on-secret",
    severity: Severity::Medium,
    explain: "\
CA013: `PartialEq` on a secret type

The derived `==` compares field by field and stops at the first difference.
Any comparison of the type is then a timing oracle, and the call site looks
completely ordinary. The same applies to a hand-written `PartialEq` that
compares the raw bytes with `==`:

    impl PartialEq for SecretKey {
        fn eq(&self, other: &Self) -> bool {
            self.0.to_bytes() == other.0.to_bytes()
        }
    }

Fix: implement `subtle::ConstantTimeEq` and compare with `ct_eq`. A manual
`PartialEq` that calls `ct_eq` or `ConstantTimeEq` is not reported.

Confidence: high for a key held as bytes, for a password or secret string,
and for a type named like a secret (`SessionKey`). Low for an `api_key` or
`token` string in a settings, task or request record, which is compared when
the settings change, not against a guess. Low findings are
hidden unless `--min-confidence low` is given.

False positives: an `==` that is never reached with attacker-influenced
input, for example comparing a key to itself in a test helper.
",
};

/// A rule that fires when a secret-bearing type derives a given trait.
pub struct DeriveRule {
    meta: &'static RuleMeta,
    derive: &'static str,
    skip: fn(&Field) -> bool,
    message: fn(&DeriveHit) -> String,
    help: &'static str,
    /// Also check hand-written `impl PartialEq` (CA013 only).
    manual_eq: bool,
}

pub fn copy_rule() -> DeriveRule {
    DeriveRule {
        meta: &COPY_META,
        derive: "Copy",
        skip: |_| false,
        message: |hit| {
            format!(
                "`#[derive(Copy)]` on `{}`: every move silently duplicates secret {}, and `Drop` (so `ZeroizeOnDrop`) is impossible",
                hit.ty,
                hit.fields_phrase()
            )
        },
        help: "remove `Copy`; derive `Clone` only if needed and add `ZeroizeOnDrop`",
        manual_eq: false,
    }
}

pub fn serialize_rule() -> DeriveRule {
    DeriveRule {
        meta: &SERIALIZE_META,
        derive: "Serialize",
        skip: serde_skips_serialize,
        message: |hit| {
            format!(
                "`#[derive(Serialize)]` on `{}` serialises secret {}",
                hit.ty,
                hit.fields_phrase()
            )
        },
        help: "add `#[serde(skip)]` to the secret field, or use a newtype with a redacting `Serialize`",
        manual_eq: false,
    }
}

pub fn eq_rule() -> DeriveRule {
    DeriveRule {
        meta: &EQ_META,
        derive: "PartialEq",
        skip: |_| false,
        message: |hit| {
            format!(
                "`#[derive(PartialEq)]` on `{}` compares secret {} with early-exit equality",
                hit.ty,
                hit.fields_phrase()
            )
        },
        help: "implement `subtle::ConstantTimeEq` and compare with `ct_eq`",
        manual_eq: true,
    }
}

impl Rule for DeriveRule {
    fn meta(&self) -> &'static RuleMeta {
        self.meta
    }

    fn check(&self, file: &ParsedFile) -> Vec<Finding> {
        let mut items = Items::default();
        items.visit_file(&file.ast);

        let mut out = Vec::new();
        for hit in derive_hits(&items, self.derive, self.skip) {
            if let Some(mut confidence) = hit.confidence() {
                // A record that merely holds secret-named fields (a request, a
                // config, a stored session) exists to be serialised. Only a type
                // that is itself named like a secret (`StaticSecret`, `Password`)
                // is a clear leak.
                let named_secret = classify_type_name(&hit.ty) == Some(Strength::Strong);
                if self.derive == "Serialize" && !named_secret {
                    confidence = confidence.min(Confidence::Low);
                }
                // The same goes for `==`: a settings or task record with an
                // `api_key: String` is compared when the settings change, not against
                // an attacker's guess. A byte-array key, or a password or secret, which is
                // compared against what a user types, is still reported.
                let password = hit.leaks.iter().any(|(label, _)| {
                    words(label).iter().any(|w| {
                        matches!(w.as_str(), "password" | "passwd" | "passphrase" | "secret")
                    })
                });
                if self.derive == "PartialEq" && !named_secret && !hit.bytes && !password {
                    confidence = confidence.min(Confidence::Low);
                }
                let message = (self.message)(&hit);
                out.push(file.finding(self.meta, confidence, hit.span, message, self.help));
            }
        }
        if self.manual_eq {
            let structs: HashMap<String, &ItemStruct> = items
                .structs
                .iter()
                .rev()
                .map(|s| (s.ident.to_string(), *s))
                .collect();
            for imp in &items.impls {
                out.extend(self.check_manual_eq(file, imp, &structs));
            }
        }
        out
    }
}

impl DeriveRule {
    /// `impl PartialEq for SecretType` that does not use a constant-time comparison.
    fn check_manual_eq(
        &self,
        file: &ParsedFile,
        imp: &ItemImpl,
        structs: &HashMap<String, &ItemStruct>,
    ) -> Option<Finding> {
        let (_, trait_path, _) = imp.trait_.as_ref()?;
        let last = trait_path.segments.last()?;
        if last.ident != "PartialEq" {
            return None;
        }
        let Type::Path(self_ty) = &*imp.self_ty else {
            return None;
        };
        let name = self_ty.path.segments.last()?.ident.to_string();
        if is_public_name(&name) || is_place_name(&name) {
            return None;
        }

        // A constant-time comparison anywhere in the impl clears it.
        let body = imp.to_token_stream().to_string();
        if crate::secret::has_constant_time_call(&body) {
            return None;
        }

        // The impl has to actually compare something.
        let mut cmp = HasComparison::default();
        cmp.visit_item_impl(imp);
        if !cmp.found && !body.contains(". eq (") {
            return None;
        }

        let by_type = classify_type_name(&name);
        let confidence = match structs.get(&name) {
            Some(def) => {
                let owner = fallback_owner(by_type, &def.fields);
                let leaks = leaking_fields(owner, &def.fields, |_| false);
                match (leaks.iter().map(|(_, c)| *c).max(), by_type) {
                    (Some(c), _) => c,
                    // Opaque wrapper (`struct SecretKey(k256::SecretKey)`): the
                    // type name and the `==` in the body are the evidence.
                    (None, Some(Strength::Strong)) => Confidence::High,
                    (None, _) => return None,
                }
            }
            None => match by_type? {
                Strength::Strong => Confidence::Medium,
                Strength::Weak => Confidence::Low,
            },
        };
        let message = format!(
            "`impl PartialEq for {name}` compares secret data with `==` instead of a constant-time comparison"
        );
        Some(file.finding(self.meta, confidence, last.ident.span(), message, self.help))
    }
}

/// Fields that serde leaves out of `Serialize`, or serialises through custom code.
fn serde_skips_serialize(field: &Field) -> bool {
    field.attrs.iter().any(|a| {
        if !a.path().is_ident("serde") {
            return false;
        }
        let tokens = a.to_token_stream().to_string();
        tokens
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .any(|w| {
                matches!(
                    w,
                    "skip" | "skip_serializing" | "skip_serializing_if" | "serialize_with" | "with"
                )
            })
    })
}

/// Does the impl contain a `==` or `!=`?
#[derive(Default)]
struct HasComparison {
    found: bool,
}

impl<'ast> Visit<'ast> for HasComparison {
    fn visit_expr_binary(&mut self, e: &'ast syn::ExprBinary) {
        if matches!(e.op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_)) {
            self.found = true;
        }
        visit::visit_expr_binary(self, e);
    }
}
