#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use cryptaudit::{Confidence, ScanOptions, Severity, report, rules};

/// Find cryptographic API misuse in Rust source code.
#[derive(Parser)]
#[command(name = "cargo-cryptaudit", bin_name = "cargo cryptaudit", version)]
struct Cli {
    /// Crate directory or single .rs file to scan
    #[arg(default_value = ".")]
    path: PathBuf,

    #[arg(long, value_enum, default_value_t = Format::Human)]
    format: Format,

    /// Hide findings below this confidence
    #[arg(long, value_enum, default_value_t = Confidence::Medium)]
    min_confidence: Confidence,

    /// Exit with status 1 if a shown finding has at least this severity
    #[arg(long, value_enum, default_value_t = Severity::Low)]
    fail_on: Severity,

    /// Also scan tests/, benches/, examples/ and #[cfg(test)] code
    #[arg(long)]
    include_tests: bool,

    /// Config file (default: cryptaudit.toml in the scanned directory, if present)
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Ignore `// cryptaudit:allow` comments and the config file
    #[arg(long)]
    no_suppress: bool,

    /// Print the documentation for a rule, e.g. --explain CA010
    #[arg(long, value_name = "RULE")]
    explain: Option<String>,

    /// List all rules
    #[arg(long)]
    list_rules: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Human,
    Json,
}

fn main() -> ExitCode {
    // `cargo cryptaudit ..` runs `cargo-cryptaudit cryptaudit ..`.
    let mut args: Vec<_> = std::env::args_os().collect();
    if args.get(1).is_some_and(|a| a == "cryptaudit") {
        args.remove(1);
    }
    match run(Cli::parse_from(args)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    if let Some(id) = &cli.explain {
        let rule = rules::find(id).ok_or_else(|| anyhow::anyhow!("unknown rule `{id}`"))?;
        print!("{}", rule.meta().explain);
        return Ok(ExitCode::SUCCESS);
    }
    if cli.list_rules {
        let mut all = rules::all();
        all.sort_by_key(|r| r.meta().id);
        for rule in all {
            let m = rule.meta();
            println!("{}  {:<28} {}", m.id, m.name, m.severity);
        }
        return Ok(ExitCode::SUCCESS);
    }
    if !cli.path.exists() {
        anyhow::bail!("{} does not exist", cli.path.display());
    }

    let config_path = cli.config.clone().or_else(|| {
        let dir = if cli.path.is_file() {
            cli.path.parent().map(PathBuf::from).unwrap_or_default()
        } else {
            cli.path.clone()
        };
        Some(dir.join("cryptaudit.toml")).filter(|p| p.is_file())
    });
    let config = match &config_path {
        Some(p) if !cli.no_suppress => Some(cryptaudit::suppress::Config::load(p)?),
        _ => None,
    };

    let report = cryptaudit::scan(
        &cli.path,
        &ScanOptions {
            include_tests: cli.include_tests,
            config,
            suppress: !cli.no_suppress,
        },
    );
    let shown: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.confidence >= cli.min_confidence)
        .collect();
    let hidden = report.findings.len() - shown.len();
    match cli.format {
        Format::Human => print!(
            "{}",
            report::human(&report, &shown, hidden, cli.min_confidence)
        ),
        Format::Json => println!("{}", report::json(&report, &shown)?),
    }
    let failed = shown.iter().any(|f| f.severity >= cli.fail_on);
    Ok(if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}
