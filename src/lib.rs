//! Static analysis for cryptographic API misuse in Rust source.
#![forbid(unsafe_code)]

pub mod finding;
pub mod report;
pub mod rules;
pub mod secret;
pub mod source;

use std::path::{Path, PathBuf};

use serde::Serialize;

pub use finding::{Confidence, Finding, Severity};
pub use source::ParsedFile;

pub struct ScanOptions {
    /// Scan `tests/`, `benches/`, `examples/` and `#[cfg(test)]` code.
    pub include_tests: bool,
}

#[derive(Serialize)]
pub struct ScanError {
    pub path: PathBuf,
    pub message: String,
}

#[derive(Serialize)]
pub struct ScanReport {
    pub files_scanned: usize,
    pub findings: Vec<Finding>,
    pub errors: Vec<ScanError>,
}

/// Scans a directory tree or a single `.rs` file.
pub fn scan(root: &Path, opts: &ScanOptions) -> ScanReport {
    let rules = rules::all();
    let mut report = ScanReport {
        files_scanned: 0,
        findings: Vec::new(),
        errors: Vec::new(),
    };
    for path in discover(root, opts.include_tests) {
        let display = path.strip_prefix(".").unwrap_or(&path).to_path_buf();
        let source = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                report.errors.push(ScanError {
                    path: display,
                    message: e.to_string(),
                });
                continue;
            }
        };
        match ParsedFile::parse(display.clone(), source, opts.include_tests) {
            Ok(file) => {
                report.files_scanned += 1;
                report.findings.extend(check_file(&file, &rules));
            }
            Err(e) => {
                let at = e.span().start();
                let message = format!("parse error at {}:{}: {e}", at.line, at.column + 1);
                report.errors.push(ScanError {
                    path: display,
                    message,
                });
            }
        }
    }
    report
}

pub fn check_file(file: &ParsedFile, rules: &[Box<dyn rules::Rule>]) -> Vec<Finding> {
    let mut findings: Vec<Finding> = rules.iter().flat_map(|r| r.check(file)).collect();
    findings.sort_by(|a, b| (a.line, a.column, a.rule).cmp(&(b.line, b.column, b.rule)));
    findings
}

const TEST_DIRS: &[&str] = &["tests", "benches", "examples"];

/// Lists `.rs` files under `root`, honouring `.gitignore` and skipping `target/`.
fn discover(root: &Path, include_tests: bool) -> Vec<PathBuf> {
    if root.is_file() {
        return vec![root.to_path_buf()];
    }
    let walker = ignore::WalkBuilder::new(root)
        .require_git(false)
        .filter_entry(move |entry| {
            if entry.depth() == 0 || !entry.file_type().is_some_and(|t| t.is_dir()) {
                return true;
            }
            let name = entry.file_name().to_string_lossy();
            name != "target" && (include_tests || !TEST_DIRS.contains(&name.as_ref()))
        })
        .build();
    let mut files: Vec<PathBuf> = walker
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_some_and(|t| t.is_file()))
        .map(ignore::DirEntry::into_path)
        .filter(|p| p.extension().is_some_and(|ext| ext == "rs"))
        .collect();
    files.sort();
    files
}
