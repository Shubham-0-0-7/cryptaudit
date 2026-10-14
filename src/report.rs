use std::fmt::Write;

use crate::finding::{Confidence, Finding, Severity};
use crate::{ScanReport, rules};

/// rustc-style text output.
pub fn human(report: &ScanReport, shown: &[&Finding], hidden: usize, min: Confidence) -> String {
    let mut out = String::new();
    for f in shown {
        let line_no = f.line.to_string();
        let pad = " ".repeat(line_no.len());
        let _ = writeln!(out, "{}[{}]: {}", f.severity, f.rule, f.message);
        let _ = writeln!(out, "{pad}--> {}:{}:{}", f.path.display(), f.line, f.column);
        let _ = writeln!(out, "{pad} |");
        let _ = writeln!(out, "{line_no} | {}", f.snippet);
        let width = f
            .end_column
            .map_or(1, |end| end.saturating_sub(f.column).max(1));
        let indent: String = f
            .snippet
            .chars()
            .take(f.column - 1)
            .map(|c| if c == '\t' { '\t' } else { ' ' })
            .collect();
        let _ = writeln!(out, "{pad} | {indent}{}", "^".repeat(width));
        let _ = writeln!(out, "{pad} = confidence: {}", f.confidence);
        let _ = writeln!(out, "{pad} = help: {}\n", f.help);
    }
    for w in &report.warnings {
        let _ = writeln!(out, "warning: {w}");
    }
    for e in &report.errors {
        let _ = writeln!(out, "warning: skipped {}: {}", e.path.display(), e.message);
    }
    let noun = if shown.len() == 1 {
        "finding"
    } else {
        "findings"
    };
    let files = if report.files_scanned == 1 {
        "file"
    } else {
        "files"
    };
    let _ = write!(
        out,
        "{} {noun} in {} {files}",
        shown.len(),
        report.files_scanned
    );
    if hidden > 0 {
        let _ = write!(out, " ({hidden} below --min-confidence {min} hidden)");
    }
    if report.suppressed > 0 {
        let _ = write!(out, " ({} suppressed)", report.suppressed);
    }
    out.push('\n');
    out
}

pub fn json(report: &ScanReport, shown: &[&Finding]) -> serde_json::Result<String> {
    serde_json::to_string_pretty(&serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "files_scanned": report.files_scanned,
        "findings": shown,
        "suppressed": report.suppressed,
        "warnings": report.warnings,
        "errors": report.errors,
    }))
}

const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");

/// SARIF 2.1.0, the format GitHub code scanning and most CI dashboards read.
///
/// Severity maps to the SARIF level (`critical` and `high` are `error`, `medium` is
/// `warning`, `low` is `note`) and to `security-severity`, the number GitHub uses
/// to sort alerts. Confidence travels in each result's `properties`. The
/// fingerprint is the same one `--format json` prints, so alerts stay matched
/// when lines move.
pub fn sarif(report: &ScanReport, shown: &[&Finding]) -> serde_json::Result<String> {
    let mut all = rules::all();
    all.sort_by_key(|r| r.meta().id);
    let rule_index = |id: &str| all.iter().position(|r| r.meta().id == id);

    let rule_list: Vec<_> = all
        .iter()
        .map(|r| {
            let m = r.meta();
            let title = m.explain.lines().next().unwrap_or(m.name);
            let title = title.split_once(": ").map_or(title, |(_, rest)| rest);
            serde_json::json!({
                "id": m.id,
                "name": m.name,
                "shortDescription": { "text": title },
                "fullDescription": { "text": m.explain.trim() },
                "help": { "text": m.explain.trim() },
                "defaultConfiguration": { "level": sarif_level(m.severity) },
                "properties": {
                    "security-severity": security_severity(m.severity),
                    "tags": ["security", "cryptography"],
                },
            })
        })
        .collect();

    let results: Vec<_> = shown
        .iter()
        .map(|f| {
            let mut region = serde_json::json!({
                "startLine": f.line,
                "startColumn": f.column,
                "snippet": { "text": f.snippet },
            });
            if let Some(end) = f.end_column {
                region["endLine"] = f.line.into();
                region["endColumn"] = end.into();
            }
            serde_json::json!({
                "ruleId": f.rule,
                "ruleIndex": rule_index(f.rule),
                "level": sarif_level(f.severity),
                "message": { "text": format!("{}\n\nHelp: {}", f.message, f.help) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": sarif_uri(&f.path) },
                        "region": region,
                    }
                }],
                "partialFingerprints": { "cryptaudit/v1": f.fingerprint },
                "properties": {
                    "confidence": f.confidence.to_string(),
                    "severity": f.severity.to_string(),
                },
            })
        })
        .collect();

    let notifications: Vec<_> = report
        .warnings
        .iter()
        .map(|w| serde_json::json!({ "level": "warning", "message": { "text": w } }))
        .chain(report.errors.iter().map(|e| {
            serde_json::json!({
                "level": "warning",
                "message": { "text": format!("skipped {}: {}", e.path.display(), e.message) },
                "locations": [{
                    "physicalLocation": { "artifactLocation": { "uri": sarif_uri(&e.path) } }
                }],
            })
        }))
        .collect();

    serde_json::to_string_pretty(&serde_json::json!({
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "cryptaudit",
                    "version": env!("CARGO_PKG_VERSION"),
                    "semanticVersion": env!("CARGO_PKG_VERSION"),
                    "informationUri": REPOSITORY,
                    "rules": rule_list,
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": true,
                "toolExecutionNotifications": notifications,
            }],
        }],
    }))
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

/// GitHub sorts alerts by this number: 9.0+ is critical, 7.0+ high, 4.0+ medium.
fn security_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "9.5",
        Severity::High => "8.0",
        Severity::Medium => "5.0",
        Severity::Low => "2.0",
    }
}

/// A relative, forward-slash path stays relative (GitHub resolves it against the
/// repository root); an absolute one becomes a `file://` URI.
fn sarif_uri(path: &std::path::Path) -> String {
    let p = path.to_string_lossy().replace('\\', "/");
    if p.starts_with('/') {
        format!("file://{p}")
    } else {
        p
    }
}
