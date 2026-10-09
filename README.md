# cryptaudit

Static analysis for cryptographic API misuse in Rust code.

> **Status: early development.** Four rules are implemented (CA010 to CA013). More are planned; see the [roadmap](#roadmap).

Modern ciphers like ChaCha20-Poly1305 and AES-GCM are sound. Real systems still break because the API is used wrongly: a reused nonce, a hardcoded key, a tag compared with `==`, a secret printed through `#[derive(Debug)]`. `cryptaudit` looks for these mistakes in your source code.

## Install and run

```sh
cargo install cryptaudit
cd your-project
cargo cryptaudit
```

It parses source files only. It does not build your project or touch the network.

```
medium[CA013]: `impl PartialEq for SecretKey` compares secret data with `==` instead of a constant-time comparison
  --> src/elliptic/secp256k1.rs:39:6
   |
39 | impl PartialEq for SecretKey {
   |      ^^^^^^^^^
   = confidence: high
   = help: implement `subtle::ConstantTimeEq` and compare with `ct_eq`

high[CA010]: `impl Debug for SecretKey` formats secret `self.0.to_bytes()`
  --> src/elliptic/secp256k1.rs:50:43
   |
50 |         f.debug_tuple("SecretKey").field(&bytes).finish()
   |                                           ^^^^^
   = confidence: high
   = help: print a placeholder such as "[redacted]" instead of the secret

2 findings in 15 files
```

### Options

| Flag | Meaning |
|---|---|
| `--format human\|json` | Output format (default `human`) |
| `--min-confidence low\|medium\|high` | Hide less certain findings (default `medium`) |
| `--fail-on low\|medium\|high\|critical` | Exit with status 1 if a shown finding is at least this severe |
| `--include-tests` | Also scan `tests/`, `benches/`, `examples/` and `#[cfg(test)]` code |
| `--explain CA010` | Print the documentation for a rule |
| `--list-rules` | List the rules |

Exit status: `0` no findings, `1` findings, `2` the tool failed. Files that don't parse are reported as warnings and skipped. `target/` and anything in `.gitignore` is skipped.

## Rules

| ID | Name | Severity | What it finds |
|---|---|---|---|
| CA010 | secret-in-debug | high | `#[derive(Debug)]` on a struct with secret fields, and hand-written `Debug`/`Display` impls that print a secret, including through a local variable |
| CA011 | copy-on-secret | medium | `#[derive(Copy)]` on a secret type: every move duplicates the key, and `ZeroizeOnDrop` becomes impossible |
| CA012 | serialize-on-secret | high | `#[derive(Serialize)]` on a secret type, unless the field has `#[serde(skip)]` or custom serialisation |
| CA013 | partialeq-on-secret | medium | `#[derive(PartialEq)]` or a hand-written `==` on a secret type, instead of a constant-time comparison |

Run `cargo cryptaudit --explain CA013` for the full description of a rule, with examples and known false positives.

Each finding has a severity (impact if exploited) and a confidence (how likely it is a true positive). Low-confidence findings are hidden by default, so the first run stays quiet. The rule list is based on a [taxonomy of Rust crypto misuse](docs/taxonomy.md); many patterns in it are specific to Rust, such as derive macros that leak secrets, `Copy` types that cannot be zeroized, and zeroing code that the optimiser removes.

## How it differs from existing tools

- `cargo-audit` reports vulnerable crate versions, not misuse in your own code.
- Clippy has no cryptographic knowledge.
- CryptoGuard and CogniCrypt do this for Java only.

## Roadmap

- [x] CLI, `syn`-based scanner, human and JSON output
- [x] CA010: secrets printed by `Debug`/`Display`
- [x] CA011, CA012, CA013: `Copy`, `Serialize` and `PartialEq` on secret types
- [ ] `==` on MAC or digest output
- [ ] Hardcoded keys and IVs, nonce reuse
- [ ] Missing zeroization, `.unwrap()` on decrypt results
- [ ] `Cargo.toml` analysis
- [ ] SARIF output, config file, inline suppression
- [ ] Evaluation on a labelled corpus and on real crates

## Authors

Shubham Chhatbar and Rahul Paul.

## License

Apache-2.0. See [LICENSE](LICENSE).
