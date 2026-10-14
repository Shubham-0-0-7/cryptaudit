//! The SARIF 2.1.0 output: structure GitHub code scanning requires.

use std::path::Path;

use cryptaudit::{Confidence, ScanOptions, report, scan};
use serde_json::Value;

const SOURCE: &str = "use hmac::{Hmac, Mac};\nuse sha2::Sha256;\n\
#[derive(Debug)]\nstruct Login {\n    password: String,\n}\n\
fn verify(key: &[u8], msg: &[u8], expected: &[u8]) -> bool {\n\
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();\n\
    mac.update(msg);\n\
    mac.finalize().into_bytes().as_slice() == expected\n}\n";

fn sarif_for(name: &str, source: &str) -> Value {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("sarif")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("src/lib.rs"), source).unwrap();
    let report = scan(
        &dir,
        &ScanOptions {
            include_tests: false,
            config: None,
            suppress: false,
        },
    );
    let shown: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.confidence >= Confidence::Medium)
        .collect();
    serde_json::from_str(&report::sarif(&report, &shown).unwrap()).unwrap()
}

#[test]
fn has_the_required_envelope() {
    let doc = sarif_for("envelope", SOURCE);
    assert_eq!(doc["version"], "2.1.0");
    assert!(doc["$schema"].as_str().unwrap().contains("sarif-2.1.0"));
    let driver = &doc["runs"][0]["tool"]["driver"];
    assert_eq!(driver["name"], "cryptaudit");
    assert_eq!(driver["version"], env!("CARGO_PKG_VERSION"));
    assert!(
        driver["informationUri"]
            .as_str()
            .unwrap()
            .starts_with("https://")
    );
}

#[test]
fn lists_every_rule_with_a_level_and_severity() {
    let doc = sarif_for("rules", SOURCE);
    let rules = doc["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    assert_eq!(rules.len(), cryptaudit::rules::all().len());
    for rule in rules {
        assert!(rule["id"].as_str().unwrap().starts_with("CA"));
        assert!(
            !rule["shortDescription"]["text"]
                .as_str()
                .unwrap()
                .is_empty()
        );
        assert!(
            ["error", "warning", "note"]
                .contains(&rule["defaultConfiguration"]["level"].as_str().unwrap())
        );
        assert!(
            rule["properties"]["security-severity"]
                .as_str()
                .unwrap()
                .parse::<f64>()
                .is_ok()
        );
    }
    let ids: Vec<_> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted);
}

#[test]
fn results_point_into_the_rule_list_and_the_source() {
    let doc = sarif_for("results", SOURCE);
    let run = &doc["runs"][0];
    let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
    let results = run["results"].as_array().unwrap();
    let ids: Vec<_> = results
        .iter()
        .map(|r| r["ruleId"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"CA010"), "{ids:?}");
    assert!(ids.contains(&"CA021"), "{ids:?}");
    for r in results {
        let index = r["ruleIndex"].as_u64().unwrap() as usize;
        assert_eq!(rules[index]["id"], r["ruleId"]);
        assert!(r["message"]["text"].as_str().unwrap().contains("Help: "));
        assert!(
            r["partialFingerprints"]["cryptaudit/v1"]
                .as_str()
                .unwrap()
                .len()
                == 16
        );
        let loc = &r["locations"][0]["physicalLocation"];
        assert!(
            loc["artifactLocation"]["uri"]
                .as_str()
                .unwrap()
                .ends_with("src/lib.rs")
        );
        let region = &loc["region"];
        assert!(region["startLine"].as_u64().unwrap() >= 1);
        assert!(region["startColumn"].as_u64().unwrap() >= 1);
        assert!(!region["snippet"]["text"].as_str().unwrap().is_empty());
    }
    // CA021 is high severity: an error. Its comparison is on line 10.
    let ca021 = results.iter().find(|r| r["ruleId"] == "CA021").unwrap();
    assert_eq!(ca021["level"], "error");
    assert_eq!(
        ca021["locations"][0]["physicalLocation"]["region"]["startLine"],
        10
    );
    assert_eq!(ca021["properties"]["confidence"], "high");
}

#[test]
fn no_findings_is_a_valid_empty_run() {
    let doc = sarif_for("clean", "fn main() {}\n");
    assert_eq!(doc["runs"][0]["results"].as_array().unwrap().len(), 0);
    assert_eq!(
        doc["runs"][0]["invocations"][0]["executionSuccessful"],
        true
    );
}
