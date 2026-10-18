use std::path::{Path, PathBuf};

use proc_macro2::Span;
use syn::punctuated::Punctuated;
use syn::visit_mut::{self, VisitMut};
use syn::{Attribute, Item, ItemMod, Meta, Token};

use crate::finding::{Class, Confidence, Finding, fingerprint};
use crate::rules::RuleMeta;

/// A parsed source file, with test-only items removed unless tests were requested.
pub struct ParsedFile {
    pub path: PathBuf,
    pub source: String,
    pub ast: syn::File,
    /// Some file of the crate implements `PartialEq` with a constant-time compare.
    pub ct_partialeq: bool,
    /// The crate declares a type, trait or enum variant named after a broken
    /// primitive (`Tdes`, `Md5`): it is a library offering the algorithm.
    pub offers_primitive: bool,
}

impl ParsedFile {
    pub fn parse(path: PathBuf, source: String, include_tests: bool) -> syn::Result<Self> {
        let mut ast = syn::parse_file(&source)?;
        if !include_tests {
            StripTests.visit_file_mut(&mut ast);
        }
        Ok(ParsedFile {
            path,
            source,
            ast,
            ct_partialeq: false,
            offers_primitive: false,
        })
    }

    pub fn finding(
        &self,
        meta: &RuleMeta,
        confidence: Confidence,
        span: Span,
        message: String,
        help: &str,
    ) -> Finding {
        let (start, end) = (span.start(), span.end());
        let snippet = self
            .source
            .lines()
            .nth(start.line.saturating_sub(1))
            .unwrap_or("");
        let path = display(&self.path);
        Finding {
            rule: meta.id,
            class: Class::of(meta.id),
            severity: meta.severity,
            confidence,
            fingerprint: fingerprint(meta.id, &path, snippet),
            path: self.path.clone(),
            line: start.line,
            column: start.column + 1,
            end_column: (end.line == start.line).then_some(end.column + 1),
            message,
            help: help.to_string(),
            snippet: snippet.to_string(),
        }
    }
}

fn display(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// Removes `#[cfg(test)]` modules and `#[test]`-style functions.
struct StripTests;

impl VisitMut for StripTests {
    fn visit_file_mut(&mut self, file: &mut syn::File) {
        file.items.retain(|item| !is_test_item(item));
        visit_mut::visit_file_mut(self, file);
    }

    fn visit_item_mod_mut(&mut self, module: &mut ItemMod) {
        if let Some((_, items)) = &mut module.content {
            items.retain(|item| !is_test_item(item));
        }
        visit_mut::visit_item_mod_mut(self, module);
    }

    /// `#[cfg(test)] fn for_test() -> Self` inside an `impl` block.
    fn visit_item_impl_mut(&mut self, imp: &mut syn::ItemImpl) {
        imp.items.retain(|item| {
            let attrs: &[Attribute] = match item {
                syn::ImplItem::Fn(i) => &i.attrs,
                syn::ImplItem::Const(i) => &i.attrs,
                syn::ImplItem::Type(i) => &i.attrs,
                syn::ImplItem::Macro(i) => &i.attrs,
                _ => &[],
            };
            !attrs.iter().any(is_test_attr)
        });
        visit_mut::visit_item_impl_mut(self, imp);
    }
}

fn is_test_item(item: &Item) -> bool {
    let attrs: &[Attribute] = match item {
        Item::Fn(i) => &i.attrs,
        Item::Mod(i) => &i.attrs,
        Item::Impl(i) => &i.attrs,
        Item::Struct(i) => &i.attrs,
        Item::Enum(i) => &i.attrs,
        Item::Const(i) => &i.attrs,
        Item::Static(i) => &i.attrs,
        Item::Use(i) => &i.attrs,
        Item::Trait(i) => &i.attrs,
        Item::Type(i) => &i.attrs,
        Item::Macro(i) => &i.attrs,
        _ => &[],
    };
    attrs.iter().any(is_test_attr)
}

fn is_test_attr(attr: &Attribute) -> bool {
    // `#[test]`, `#[tokio::test]`, `#[rstest::test]`, ...
    if attr
        .path()
        .segments
        .last()
        .is_some_and(|s| s.ident == "test")
    {
        return true;
    }
    attr.path().is_ident("cfg")
        && attr
            .parse_args::<Meta>()
            .is_ok_and(|m| cfg_requires_test(&m))
}

/// `test` and `all(test, ..)` require test; `any(test, ..)` and `not(test)` do not,
/// except `any(test, debug_assertions)`: code that only exists in test and debug
/// builds is a test helper, never part of a release.
pub(crate) fn cfg_requires_test(meta: &Meta) -> bool {
    match meta {
        Meta::Path(p) => p.is_ident("test"),
        Meta::List(list) if list.path.is_ident("all") => list
            .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            .is_ok_and(|metas| metas.iter().any(cfg_requires_test)),
        Meta::List(list) if list.path.is_ident("any") => list
            .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            .is_ok_and(|metas| {
                metas.iter().any(cfg_requires_test)
                    && metas.iter().all(|m| {
                        cfg_requires_test(m)
                            || matches!(m, Meta::Path(p) if p.is_ident("debug_assertions"))
                    })
            }),
        _ => false,
    }
}
