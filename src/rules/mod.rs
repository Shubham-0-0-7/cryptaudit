use crate::finding::{Finding, Severity};
use crate::source::ParsedFile;

mod ca010;
mod compare;
mod derives;
mod results;

pub struct RuleMeta {
    pub id: &'static str,
    pub name: &'static str,
    pub severity: Severity,
    /// Long-form documentation, printed by `--explain`.
    pub explain: &'static str,
}

pub trait Rule: Sync {
    fn meta(&self) -> &'static RuleMeta;
    fn check(&self, file: &ParsedFile) -> Vec<Finding>;
}

pub fn all() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(ca010::DebugLeak),
        Box::new(derives::copy_rule()),
        Box::new(derives::serialize_rule()),
        Box::new(derives::eq_rule()),
        Box::new(compare::MacEq),
        Box::new(compare::MacAssert),
        Box::new(results::UnwrapOnCrypto),
        Box::new(results::DiscardedVerify),
    ]
}

pub fn find(id: &str) -> Option<Box<dyn Rule>> {
    all()
        .into_iter()
        .find(|r| r.meta().id.eq_ignore_ascii_case(id))
}
