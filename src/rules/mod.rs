use crate::finding::{Finding, Severity};
use crate::source::ParsedFile;

mod bytes;
mod ca010;
mod compare;
mod derives;
mod keys;
mod logging;
mod nonce;
mod results;
mod rng;
mod zeroize;

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
        Box::new(logging::SecretInLog),
        Box::new(compare::MacEq),
        Box::new(compare::MacAssert),
        Box::new(results::UnwrapOnCrypto),
        Box::new(results::DiscardedVerify),
        Box::new(keys::HardcodedKey),
        Box::new(keys::FixedCbcIv),
        Box::new(nonce::NonceReuse),
        Box::new(rng::WeakRng),
        Box::new(rng::FixedSeed),
        Box::new(rng::TimeSeed),
        Box::new(zeroize::MissingZeroize),
        Box::new(zeroize::ManualZeroing),
    ]
}

pub fn find(id: &str) -> Option<Box<dyn Rule>> {
    all()
        .into_iter()
        .find(|r| r.meta().id.eq_ignore_ascii_case(id))
}
