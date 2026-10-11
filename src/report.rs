use std::fmt::Write;

use crate::ScanReport;
use crate::finding::{Confidence, Finding};

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
