//! Runs every rule over `tests/fixtures/**/*.rs`.
//!
//! Each fixture marks the lines it expects findings on with a trailing
//! `// expect: CA010 high` (several separated by commas). The set of
//! (line, rule, confidence) must match exactly, at every confidence level,
//! so a fixture with no annotations asserts that nothing is reported.

use std::collections::BTreeSet;
use std::fmt::Write;
use std::path::{Path, PathBuf};

use cryptaudit::{ParsedFile, check_file, rules};

type Key = (usize, String, String);

fn expected(source: &str) -> BTreeSet<Key> {
    let mut out = BTreeSet::new();
    for (i, line) in source.lines().enumerate() {
        let Some((_, spec)) = line.split_once("// expect:") else {
            continue;
        };
        for item in spec.split(',') {
            let mut parts = item.split_whitespace();
            let (Some(rule), Some(conf)) = (parts.next(), parts.next()) else {
                panic!("bad expect annotation on line {}: {line}", i + 1);
            };
            out.insert((i + 1, rule.to_string(), conf.to_string()));
        }
    }
    out
}

#[test]
fn fixtures() {
    let rules = rules::all();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut paths = Vec::new();
    collect(&root, &mut paths);
    assert!(!paths.is_empty(), "no fixtures found");
    for path in &paths {
        let source = std::fs::read_to_string(path).unwrap();
        let name = path
            .strip_prefix(env!("CARGO_MANIFEST_DIR"))
            .unwrap_or(path);
        let file = ParsedFile::parse(name.to_path_buf(), source.clone(), false)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let findings = check_file(&file, &rules);

        let actual: BTreeSet<Key> = findings
            .iter()
            .map(|f| (f.line, f.rule.to_string(), f.confidence.to_string()))
            .collect();
        let want = expected(&source);
        let missing: Vec<_> = want.difference(&actual).collect();
        let unexpected: Vec<_> = actual.difference(&want).collect();
        assert!(
            missing.is_empty() && unexpected.is_empty(),
            "{}\n  missing (false negatives): {missing:?}\n  unexpected (false positives): {unexpected:?}",
            path.display()
        );

        let mut snap = String::new();
        for f in &findings {
            let _ = writeln!(
                snap,
                "{}:{} {} [{}/{}] {}",
                f.line, f.column, f.rule, f.severity, f.confidence, f.message
            );
        }
        let snap_name = path
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace(['/', '\\'], "__");
        insta::assert_snapshot!(snap_name, snap);
    }
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}
