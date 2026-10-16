//! Static analysis for cryptographic API misuse in Rust source.
#![forbid(unsafe_code)]

pub mod finding;
pub mod report;
pub mod rules;
pub mod secret;
pub mod source;
pub mod suppress;

use std::path::{Path, PathBuf};

use serde::Serialize;

pub use finding::{Confidence, Finding, Severity};
pub use source::ParsedFile;

pub struct ScanOptions {
    /// Scan `tests/`, `benches/`, `examples/`, `xtask/`, `build.rs` and `#[cfg(test)]` code.
    pub include_tests: bool,
    /// Config from `cryptaudit.toml`; `None` applies no config rules.
    pub config: Option<suppress::Config>,
    /// Honour `// cryptaudit:allow` comments and the config. Off for audits.
    pub suppress: bool,
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
    /// Findings silenced by comments or config.
    pub suppressed: usize,
    pub warnings: Vec<String>,
    pub errors: Vec<ScanError>,
}

/// Scans a directory tree or a single `.rs` file.
pub fn scan(root: &Path, opts: &ScanOptions) -> ScanReport {
    let rules = rules::all();
    let no_config = suppress::Config::default();
    let config = opts.config.as_ref().unwrap_or(&no_config);
    let mut report = ScanReport {
        files_scanned: 0,
        findings: Vec::new(),
        suppressed: 0,
        warnings: Vec::new(),
        errors: Vec::new(),
    };
    let mut sources = Vec::new();
    for path in discover(root, opts.include_tests) {
        let display = path.strip_prefix(".").unwrap_or(&path).to_path_buf();
        match std::fs::read_to_string(&path) {
            Ok(s) => sources.push((display, s)),
            Err(e) => report.errors.push(ScanError {
                path: display,
                message: e.to_string(),
            }),
        }
    }
    if !opts.include_tests {
        let test_files = out_of_line_test_modules(&sources);
        sources.retain(|(path, _)| !test_files.contains(path));
    }
    let ct_partialeq = sources
        .iter()
        .any(|(_, s)| s.contains("fn eq") && secret::has_constant_time_call(s));
    for (display, source) in sources {
        match ParsedFile::parse(display.clone(), source, opts.include_tests) {
            Ok(mut file) => {
                if is_generated(&file.source) {
                    continue;
                }
                file.ct_partialeq = ct_partialeq;
                report.files_scanned += 1;
                let found = check_file(&file, &rules);
                if opts.suppress {
                    let directives = suppress::Directives::parse(&display, &file.source);
                    report.warnings.extend(directives.warnings.iter().cloned());
                    let (kept, n) = suppress::apply(found, &directives, config, root);
                    report.suppressed += n;
                    report.findings.extend(kept);
                } else {
                    report.findings.extend(found);
                }
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

const TEST_DIRS: &[&str] = &["tests", "benches", "bench", "examples", "xtask"];

/// Words that mark a directory or file as test, fuzz or benchmark support:
/// `tests_and_kats/`, `test_utils/`, `interop_test_vectors.rs`, `benchmark.rs`.
const TEST_WORDS: &[&str] = &[
    "test",
    "tests",
    "testing",
    "kat",
    "kats",
    "fuzz",
    "bench",
    "benches",
    "benchmark",
    "benchmarks",
];

fn is_test_support_name(name: &str) -> bool {
    let stem = name.strip_suffix(".rs").unwrap_or(name);
    secret::words(stem)
        .iter()
        .any(|w| TEST_WORDS.contains(&w.as_str()))
}

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
            name != "target"
                && (include_tests
                    || !(TEST_DIRS.contains(&name.as_ref()) || is_test_support_name(&name)))
        })
        .build();
    let mut files: Vec<PathBuf> = walker
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_some_and(|t| t.is_file()))
        .map(ignore::DirEntry::into_path)
        .filter(|p| p.extension().is_some_and(|ext| ext == "rs"))
        // `#[cfg(test)] mod tests;` lives in its own file, so the attribute is not in it.
        // Build scripts run on the developer's machine, not on attacker input.
        .filter(|p| {
            include_tests
                || !p
                    .file_name()
                    .is_some_and(|n| n == "build.rs" || is_test_support_name(&n.to_string_lossy()))
        })
        .collect();
    files.sort();
    files
}

/// OpenAPI clients and protobuf bindings: nobody edits them, so findings in them
/// belong to the generator.
fn is_generated(source: &str) -> bool {
    let head: String = source.chars().take(1200).collect::<String>().to_lowercase();
    head.contains("@generated")
        || head.contains("generated by")
        || head.contains("do not edit")
        || head.contains("auto-generated")
        || head.contains("autogenerated")
}

/// Files declared as `#[cfg(test)] mod name;`. The attribute sits in the parent
/// file, so the module's own file looks like ordinary code.
fn out_of_line_test_modules(sources: &[(PathBuf, String)]) -> std::collections::HashSet<PathBuf> {
    let mut out = std::collections::HashSet::new();
    for (path, source) in sources {
        let (Some(dir), Some(stem)) = (path.parent(), path.file_stem().and_then(|s| s.to_str()))
        else {
            continue;
        };
        let base = if matches!(stem, "mod" | "lib" | "main") {
            dir.to_path_buf()
        } else {
            dir.join(stem)
        };
        let mut cfg_test = false;
        for line in source.lines().map(str::trim) {
            if line.starts_with("#[cfg(test)]") || line.starts_with("#[cfg(all(test") {
                cfg_test = true;
            } else if cfg_test
                && (line.starts_with("#[") || line.starts_with("//") || line.is_empty())
            {
                continue;
            } else {
                if cfg_test {
                    let decl = line.trim_start_matches("pub ");
                    let decl = decl.strip_prefix("pub(crate) ").unwrap_or(decl);
                    if let Some(name) = decl.strip_prefix("mod ").and_then(|r| r.strip_suffix(';'))
                    {
                        out.insert(base.join(format!("{}.rs", name.trim())));
                        out.insert(base.join(name.trim()).join("mod.rs"));
                    }
                }
                cfg_test = false;
            }
        }
    }
    out
}
