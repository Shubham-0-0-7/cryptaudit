use std::fmt;
use std::path::PathBuf;

use serde::Serialize;

/// Impact if the finding is exploitable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// How likely a finding is to be a true positive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// What kind of report a finding is.
///
/// A `Finding` points at code that is wrong on its own: a certificate check
/// switched off, a MAC compared with `==`, a key printed to a log. `Hardening`
/// points at a weakness that only matters if something else goes wrong first: a
/// key type that derives `Debug`, a secret that is not zeroed on drop. Those are
/// worth fixing, but nothing here shows the leak happening, so they are listed
/// apart and do not fail the exit code unless `--fail-on-hardening` is given.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Class {
    Finding,
    Hardening,
}

impl Class {
    /// CA010 (Debug), CA011 (Copy), CA012 (Serialize), CA013 (PartialEq), CA015
    /// (not zeroized) and CA016 (manual zeroing) are about how a secret is
    /// handled in memory or in a type's derives.
    pub fn of(rule: &str) -> Self {
        match rule {
            "CA010" | "CA011" | "CA012" | "CA013" | "CA015" | "CA016" => Class::Hardening,
            _ => Class::Finding,
        }
    }
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Class::Finding => "finding",
            Class::Hardening => "hardening",
        })
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        })
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub rule: &'static str,
    pub class: Class,
    pub severity: Severity,
    pub confidence: Confidence,
    pub path: PathBuf,
    /// 1-based.
    pub line: usize,
    /// 1-based, in characters.
    pub column: usize,
    /// End column on the same line, if the span is single-line.
    pub end_column: Option<usize>,
    pub message: String,
    pub help: String,
    /// The source line the finding starts on.
    pub snippet: String,
    /// Stable across line shifts: hash of rule, path and whitespace-normalised snippet.
    pub fingerprint: String,
}

/// FNV-1a, 64-bit. Stable across Rust versions, unlike `DefaultHasher`.
pub(crate) fn fingerprint(rule: &str, path: &str, snippet: &str) -> String {
    let normalised = snippet.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in [rule, "\0", path, "\0", &normalised].concat().bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{hash:016x}")
}
