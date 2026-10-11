//! Silencing findings: inline comments and a `cryptaudit.toml` config.
//!
//! Inline, on the flagged line or on the comment lines directly above it:
//!
//! ```text
//! // cryptaudit:allow(CA021) compared in a test helper, not on a secret path
//! // cryptaudit:allow-file(CA015) legacy module, rewritten in the next release
//! ```
//!
//! A reason is required. A directive without one does not suppress anything and
//! produces a warning, so every silenced finding can be explained later.
//!
//! Config file (`cryptaudit.toml` in the scanned directory, or `--config`):
//!
//! ```toml
//! disable = ["CA016"]                      # turn rules off everywhere
//!
//! [[allow]]
//! rule = "CA015"
//! path = "src/legacy/**"                   # gitignore-style glob on the reported path
//! reason = "legacy code, tracked in #42"
//! ```

use std::path::Path;

use ignore::gitignore::{Gitignore, GitignoreBuilder};
use serde::Deserialize;

use crate::finding::Finding;
use crate::rules;

const MARKER: &str = "cryptaudit:allow";

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    disable: Vec<String>,
    #[serde(default)]
    allow: Vec<RawAllow>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAllow {
    rule: String,
    path: String,
    reason: String,
}

struct AllowEntry {
    rule: String,
    paths: Gitignore,
}

#[derive(Default)]
pub struct Config {
    disabled: Vec<String>,
    allow: Vec<AllowEntry>,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
        let raw: RawConfig = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("invalid {}: {e}", path.display()))?;
        let mut config = Config::default();
        for id in raw.disable {
            check_rule_id(&id, path)?;
            config.disabled.push(id.to_ascii_uppercase());
        }
        for entry in raw.allow {
            check_rule_id(&entry.rule, path)?;
            if entry.reason.trim().is_empty() {
                anyhow::bail!(
                    "{}: [[allow]] for {} needs a reason",
                    path.display(),
                    entry.rule
                );
            }
            let mut builder = GitignoreBuilder::new("");
            builder.add_line(None, &entry.path).map_err(|e| {
                anyhow::anyhow!("{}: bad path `{}`: {e}", path.display(), entry.path)
            })?;
            config.allow.push(AllowEntry {
                rule: entry.rule.to_ascii_uppercase(),
                paths: builder.build()?,
            });
        }
        Ok(config)
    }

    fn silences(&self, f: &Finding, root: &Path) -> bool {
        if self.disabled.iter().any(|d| d == f.rule) {
            return true;
        }
        let relative = f.path.strip_prefix(root).unwrap_or(&f.path);
        let path = relative.to_string_lossy().replace('\\', "/");
        self.allow.iter().any(|a| {
            a.rule == f.rule
                && a.paths
                    .matched_path_or_any_parents(path.trim_start_matches("./"), false)
                    .is_ignore()
        })
    }
}

fn check_rule_id(id: &str, config: &Path) -> anyhow::Result<()> {
    if rules::find(id).is_none() {
        anyhow::bail!("{}: unknown rule `{id}`", config.display());
    }
    Ok(())
}

/// Directives found in one source file.
#[derive(Default)]
pub struct Directives {
    /// (1-based line, rule ids)
    lines: Vec<(usize, Vec<String>)>,
    file_wide: Vec<String>,
    source_lines: Vec<bool>,
    pub warnings: Vec<String>,
}

impl Directives {
    pub fn parse(path: &Path, source: &str) -> Directives {
        let mut d = Directives::default();
        for (i, line) in source.lines().enumerate() {
            let trimmed = line.trim_start();
            let comment_only = trimmed.starts_with("//");
            d.source_lines.push(comment_only);
            let Some(comment_at) = line.find("//") else {
                continue;
            };
            let comment = &line[comment_at..];
            let Some(at) = comment.find(MARKER) else {
                continue;
            };
            let rest = &comment[at + MARKER.len()..];
            let (file_wide, rest) = match rest.strip_prefix("-file") {
                Some(r) => (true, r),
                None => (false, rest),
            };
            let where_ = format!("{}:{}", path.display(), i + 1);
            let Some((ids, reason)) = rest.strip_prefix('(').and_then(|r| r.split_once(')')) else {
                d.warnings.push(format!(
                    "{where_}: malformed cryptaudit directive, expected `{MARKER}(CA000) reason`"
                ));
                continue;
            };
            let ids: Vec<String> = ids
                .split(',')
                .map(|s| s.trim().to_ascii_uppercase())
                .filter(|s| !s.is_empty())
                .collect();
            if ids.is_empty() || ids.iter().any(|id| rules::find(id).is_none()) {
                d.warnings.push(format!(
                    "{where_}: cryptaudit directive names an unknown rule"
                ));
                continue;
            }
            if reason.trim().is_empty() {
                d.warnings.push(format!(
                    "{where_}: cryptaudit directive has no reason, so it was ignored"
                ));
                continue;
            }
            if file_wide {
                d.file_wide.extend(ids);
            } else {
                d.lines.push((i + 1, ids));
            }
        }
        d
    }

    fn silences(&self, f: &Finding) -> bool {
        if self.file_wide.iter().any(|id| id == f.rule) {
            return true;
        }
        let covers = |line: usize| {
            self.lines
                .iter()
                .any(|(l, ids)| *l == line && ids.iter().any(|id| id == f.rule))
        };
        if covers(f.line) {
            return true;
        }
        // Walk up through the comment lines directly above the finding.
        let mut line = f.line;
        while line > 1 && self.source_lines.get(line - 2).copied().unwrap_or(false) {
            line -= 1;
            if covers(line) {
                return true;
            }
        }
        false
    }
}

/// Splits `findings` into (kept, suppressed count). Config paths match relative to `root`.
pub fn apply(
    findings: Vec<Finding>,
    directives: &Directives,
    config: &Config,
    root: &Path,
) -> (Vec<Finding>, usize) {
    let total = findings.len();
    let kept: Vec<Finding> = findings
        .into_iter()
        .filter(|f| !directives.silences(f) && !config.silences(f, root))
        .collect();
    let suppressed = total - kept.len();
    (kept, suppressed)
}
