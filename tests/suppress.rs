//! Inline `// cryptaudit:allow` comments and `cryptaudit.toml`.

use std::path::{Path, PathBuf};

use cryptaudit::suppress::Config;
use cryptaudit::{ScanOptions, ScanReport, scan};

const HEAD: &str = "use hmac::{Hmac, Mac};\nuse sha2::Sha256;\n\
fn check(key: &[u8], msg: &[u8], expected: &[u8]) -> bool {\n\
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();\n\
    mac.update(msg);\n";
const FLAGGED: &str = "    mac.finalize().into_bytes().as_slice() == expected";

fn dir(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("suppress")
        .join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("src")).unwrap();
    d
}

fn run(dir: &Path, source: &str, config: Option<&str>) -> ScanReport {
    std::fs::write(dir.join("src/lib.rs"), source).unwrap();
    let config = config.map(|c| {
        std::fs::write(dir.join("cryptaudit.toml"), c).unwrap();
        Config::load(&dir.join("cryptaudit.toml")).unwrap()
    });
    scan(
        dir,
        &ScanOptions {
            include_tests: false,
            config,
            suppress: true,
        },
    )
}

fn program(before: &str, trailing: &str) -> String {
    format!("{HEAD}{before}{FLAGGED}{trailing}\n}}\n")
}

#[test]
fn unsuppressed_baseline() {
    let r = run(&dir("base"), &program("", ""), None);
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.suppressed, 0);
}

#[test]
fn comment_above_and_trailing() {
    let above = program("    // cryptaudit:allow(CA021) test helper\n", "");
    let r = run(&dir("above"), &above, None);
    assert_eq!((r.findings.len(), r.suppressed), (0, 1));

    let trailing = program("", " // cryptaudit:allow(CA021) test helper");
    let r = run(&dir("trailing"), &trailing, None);
    assert_eq!((r.findings.len(), r.suppressed), (0, 1));
}

#[test]
fn wrong_rule_or_missing_reason_does_not_suppress() {
    let wrong = program("    // cryptaudit:allow(CA015) other rule\n", "");
    let r = run(&dir("wrong"), &wrong, None);
    assert_eq!(r.findings.len(), 1);

    let no_reason = program("    // cryptaudit:allow(CA021)\n", "");
    let r = run(&dir("noreason"), &no_reason, None);
    assert_eq!(r.findings.len(), 1);
    assert!(r.warnings.iter().any(|w| w.contains("no reason")));
}

#[test]
fn unknown_rule_warns() {
    let src = program("    // cryptaudit:allow(CA999) typo\n", "");
    let r = run(&dir("unknown"), &src, None);
    assert_eq!(r.findings.len(), 1);
    assert!(r.warnings.iter().any(|w| w.contains("unknown rule")));
}

#[test]
fn file_wide_directive() {
    let src = format!(
        "// cryptaudit:allow-file(CA021) generated\n{}",
        program("", "")
    );
    let r = run(&dir("file"), &src, None);
    assert_eq!((r.findings.len(), r.suppressed), (0, 1));
}

#[test]
fn config_disable_and_path_allow() {
    let r = run(
        &dir("disable"),
        &program("", ""),
        Some("disable = [\"CA021\"]\n"),
    );
    assert_eq!((r.findings.len(), r.suppressed), (0, 1));

    let allow = "[[allow]]\nrule = \"CA021\"\npath = \"src/**\"\nreason = \"vendored\"\n";
    let r = run(&dir("allow"), &program("", ""), Some(allow));
    assert_eq!((r.findings.len(), r.suppressed), (0, 1));

    let other = "[[allow]]\nrule = \"CA021\"\npath = \"vendor/**\"\nreason = \"vendored\"\n";
    let r = run(&dir("allow_other"), &program("", ""), Some(other));
    assert_eq!(r.findings.len(), 1);
}

#[test]
fn config_rejects_bad_input() {
    let d = dir("badcfg");
    let p = d.join("cryptaudit.toml");
    for bad in [
        "disable = [\"CA999\"]\n",
        "[[allow]]\nrule = \"CA021\"\npath = \"a\"\nreason = \"\"\n",
        "oops = 1\n",
    ] {
        std::fs::write(&p, bad).unwrap();
        assert!(Config::load(&p).is_err(), "{bad}");
    }
}
