//! Findings and hardening reports are listed apart, and only findings fail the run.

use std::path::Path;

use cryptaudit::finding::Class;
use cryptaudit::{Confidence, ScanOptions, report, scan};

const SOURCE: &str = "#[derive(Debug)]\nstruct SessionKey([u8; 32]);\n\
fn connect() { let c = reqwest::Client::builder().danger_accept_invalid_certs(true).build(); }\n";

fn scanned() -> cryptaudit::ScanReport {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("class");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("src/lib.rs"), SOURCE).unwrap();
    scan(
        &dir,
        &ScanOptions {
            include_tests: false,
            config: None,
            suppress: false,
        },
    )
}

#[test]
fn rules_are_classed_by_what_they_show() {
    for rule in ["CA010", "CA011", "CA012", "CA013", "CA015", "CA016"] {
        assert_eq!(Class::of(rule), Class::Hardening, "{rule}");
    }
    for rule in ["CA014", "CA021", "CA029", "CA064", "CA024", "CA027"] {
        assert_eq!(Class::of(rule), Class::Finding, "{rule}");
    }
}

#[test]
fn text_output_lists_findings_before_hardening_and_counts_them_apart() {
    let report = scanned();
    let shown: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.confidence >= Confidence::Medium)
        .collect();
    assert!(shown.iter().any(|f| f.class == Class::Hardening));
    assert!(shown.iter().any(|f| f.class == Class::Finding));
    let text = report::human(&report, &shown, 0, Confidence::Medium);
    let finding_at = text.find("[CA064]").expect("CA064 shown");
    let heading_at = text.find("hardening:").expect("hardening heading");
    let hardening_at = text.find("[CA010]").expect("CA010 shown");
    assert!(
        finding_at < heading_at && heading_at < hardening_at,
        "{text}"
    );
    assert!(
        text.contains("1 finding and 2 hardening reports in"),
        "{text}"
    );
}

#[test]
fn json_and_sarif_carry_the_class() {
    let report = scanned();
    let shown: Vec<_> = report.findings.iter().collect();
    let json: serde_json::Value =
        serde_json::from_str(&report::json(&report, &shown).unwrap()).unwrap();
    let classes: Vec<_> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["class"].as_str().unwrap().to_string())
        .collect();
    assert!(classes.contains(&"finding".to_string()));
    assert!(classes.contains(&"hardening".to_string()));
    let sarif: serde_json::Value =
        serde_json::from_str(&report::sarif(&report, &shown).unwrap()).unwrap();
    let result = &sarif["runs"][0]["results"][0];
    assert!(result["properties"]["class"].is_string());
}
