# cryptaudit

Static analysis for cryptographic API misuse in Rust code.

> **Status: early development.** The CLI is a scaffold and no rules are implemented yet. This README describes what the tool is being built to do.

Modern ciphers like ChaCha20-Poly1305 and AES-GCM are sound. Real systems still break because the API is used wrongly: a reused nonce, a hardcoded key, a tag compared with `==`, a secret printed through `#[derive(Debug)]`. `cryptaudit` looks for these mistakes in your source and `Cargo.toml`, on every build.

## Usage

```sh
cargo install cryptaudit
cd your-project
cargo cryptaudit
```

## What it will detect

Rules are grouped by what the analysis needs:

| Surface | Examples |
|---|---|
| Source (AST) | `#[derive(Debug/Serialize/Copy)]` on secret types, nonce reuse, hardcoded keys/IVs, `==` on MAC output, `.unwrap()` on decrypt results, non-CSPRNG key generation, disabled TLS verification |
| Manifest | feature flags that disable constant-time backends, raw cipher crates with no AEAD, crypto crates with known advisories |

Many of these are specific to Rust: derive macros that leak secrets, `Copy` types that cannot be zeroized, and zeroing code that the optimiser removes. Each finding carries a severity and a confidence level, and low-confidence findings are hidden by default to keep the first run quiet.

## How it differs from existing tools

- `cargo-audit` reports vulnerable crate versions, not misuse in your own code.
- Clippy has no cryptographic knowledge.
- CryptoGuard and CogniCrypt do this for Java only.

## Roadmap

- [ ] CLI scaffold and `syn`-based visitor
- [ ] First AST rules (derive leaks, `==` on tags, hardcoded keys)
- [ ] Nonce reuse detection
- [ ] `Cargo.toml` analysis
- [ ] Evaluation on a labelled corpus and on real crates

## Background

The project proposal is in [docs/PROPOSAL.md](docs/PROPOSAL.md).

## Authors

Shubham Chhatbar and Rahul Paul.

## License

Apache-2.0. See [LICENSE](LICENSE).
