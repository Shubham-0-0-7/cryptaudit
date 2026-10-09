# Build prompt — `cargo-cryptaudit` MVP

Paste everything below the line into a fresh Claude Code session started inside the new
`cargo-cryptaudit/` repo. Attach or copy `taxonomy.md` into the repo first (the prompt refers to it).

---

GOAL
Build `cargo-cryptaudit`, a Rust CLI (cargo subcommand) that statically detects cryptographic
API misuse in Rust source code. This is a 3rd-year design project (IIIT Vadodara, 14 weeks,
team of 2) and will be published to crates.io and evaluated in a paper. Prefer a small,
correct, well-tested tool over a broad, noisy one. Precision matters more than recall:
a false positive costs us credibility in the evaluation.

CONTEXT
- Rule catalogue and IDs live in `taxonomy.md` (rule IDs `CA0xx`, tiered A–E by build cost).
  Treat it as the spec. Do not invent new rule IDs; if you need one, propose it and stop.
- Prior art we position against: CryptoGuard (Java, CCS 2019), CogniCrypt (Java, ASE 2017),
  cargo-audit (lockfile advisories only), Clippy (no crypto knowledge), Semgrep p/rust
  (generic, almost no crypto rules). Our contribution: Rust-specific patterns (derive macros,
  ownership/copies, optimiser-elided zeroing, unwrap on crypto Results) + release + real-crate eval.
- Target ecosystem: RustCrypto (aes-gcm, chacha20poly1305, chacha20, aes, ctr, cbc, hmac,
  sha2, subtle, zeroize), ring, rand, dalek crates.

ARCHITECTURE (keep it boring)
- Single cargo workspace:
  - `crates/cryptaudit-core` — library: file discovery, `syn` parsing (`full`, `visit`
    features), rule trait, rule registry, findings model, config.
  - `crates/cargo-cryptaudit` — binary: CLI (`clap` derive), invoked as `cargo cryptaudit`
    (handle the extra `cryptaudit` argv cargo inserts).
- Rule trait: `fn id(&self) -> &'static str; fn check(&self, file: &ParsedFile, cx: &Context) -> Vec<Finding>`.
  One file per rule under `rules/`. Rules are pure functions of the AST + project context.
- `Context` holds: resolved `use` aliases per file (so `use chacha20poly1305::ChaCha20Poly1305 as C`
  still resolves), the crate's `Cargo.toml` dependencies (via `cargo_metadata`), and the config.
- Finding: rule id, severity, confidence, file, line/col span (use `proc-macro2` span-locations),
  message, short fix hint, and a stable fingerprint (rule + path + normalized snippet) for baselines.
- Output formats: human (default, colored, rustc-like with code snippet), `--format json`,
  `--format sarif` (SARIF 2.1.0, so GitHub code scanning can ingest it).
- Exit codes: 0 clean, 1 findings at or above `--fail-on <severity>`, 2 tool error.
- Config: `cryptaudit.toml` or `[package.metadata.cryptaudit]`: enable/disable rules, extra
  secret-type names, paths to ignore. Inline suppression: `// cryptaudit:allow(CA021) reason`.
- Skip `target/`, respect `.gitignore`, and by default ignore `#[cfg(test)]` modules, `tests/`,
  `benches/`, `examples/` (flag `--include-tests` to scan them). Report unparseable files as
  warnings, never crash.

SECRET-TYPE HEURISTIC (shared by many rules — build this first, test it hard)
A struct/field/variable is "secret-bearing" if any of:
- field or type name matches (case-insensitive, word-boundary) key|secret|private|priv|seed|
  password|passwd|pwd|token|nonce-is-NOT-secret (exclude nonce/iv/salt/public/pub_key/pk),
- field type is a known secret type: `Key<..>`, `GenericArray<u8,..>` in a key-named field,
  `SecretKey`, `SigningKey`, `StaticSecret`, `EphemeralSecret`, `Secret<..>`, `SecretBox<..>`,
  `[u8; 16|24|32|48|64]` in a key-named field,
- user-configured names.
Keep the heuristic in one module with a table-driven unit test (≥40 positive/negative names).

MVP RULES (ship these, in this order; every rule needs positive, negative, and
"looks-bad-but-is-fine" fixtures before it is considered done)
1. CA010 `#[derive(Debug)]` on secret-bearing struct. ALSO flag a manual `impl Debug`/`impl Display`
   whose body formats a secret field (real-world case: a crate's SecretKey had a hand-written Debug
   that printed raw key bytes — a derive-only rule misses it). Do NOT flag Debug impls that print
   a redaction string.
2. CA021 `==`/`!=` where either side is `.finalize()`, `.finalize_fixed()`, `.into_bytes()`,
   `.tag()`, `.verify..`-adjacent MAC/digest output, or a variable named *mac/*tag/*digest/*hmac.
   Suggest `subtle::ConstantTimeEq::ct_eq` or `Mac::verify_slice`.
3. CA020 `assert_eq!/assert_ne!` on MAC/tag values outside test code.
4. CA027 hardcoded key/IV: byte-array/byte-string/hex literal (or `const`/`static` of one) flowing
   directly into `new`, `new_from_slice`, `Key::from_slice`, `Nonce::from_slice`, `GenericArray::from_slice`
   of a known cipher type. Single-function, syntactic flow only.
5. CA028 nonce reuse (intra-function): the same nonce binding (not re-assigned between calls)
   passed to two `.encrypt(` / `.encrypt_in_place(` calls on an AEAD in one function body,
   including inside a loop body where the nonce is defined outside the loop.
6. CA022 raw stream cipher without AEAD: `chacha20::ChaCha20`/`XChaCha20`, `ctr::Ctr*`,
   `cbc::Encryptor` used and the same file/crate has no MAC usage (hmac, poly1305, blake2 MAC,
   or an AEAD type). Medium confidence; say so in the message.
7. CA023 non-CSPRNG for keys/nonces: `SmallRng`, `rand::rngs::mock`, `fastrand`, `oorandom`,
   or `thread_rng()`-free seeded `StdRng::seed_from_u64(..)` feeding a key/nonce/salt binding.
   CA071/CA072: `seed_from_u64(<literal>)`, `from_seed([literal; N])`, seeds from `SystemTime`/`Instant`.
8. CA015/CA016 zeroization: secret-bearing struct without `Zeroize`/`ZeroizeOnDrop` derive or
   `Drop` impl calling `.zeroize()`; and manual `fill(0)` / `iter_mut().for_each(|b| *b = 0)` /
   `= [0; N]` on a secret binding (optimiser-elidable) — suggest `zeroize`.
9. CA018/CA019 decrypt/verify result handling: `.decrypt(..).unwrap()/.expect()` and
   `verify*(..).unwrap()` in non-test code (Med), and results discarded via `let _ =`,
   `.ok();`, `if let Ok(_) = verify(..) {}` with no else-path that returns/errs (High).
   Do not flag `.unwrap()` on infallible-by-type calls (e.g. `try_into()` from a fixed-size array
   into the same size, HKDF expand of ≤ 255*HashLen); accept an inline `// never fails` comment
   ONLY as a confidence downgrade, not a suppression.
10. CA041 (manifest): raw cipher crate in `[dependencies]` with no AEAD/MAC crate present.

STRETCH (only after MVP + eval numbers exist)
- CA011/CA012/CA013 derives (Clone/Copy, Serialize, PartialEq) on secret types.
- CA014 secrets reaching `println!/format!/tracing::*!/log::*!`.
- CA024/CA025/CA079 weak primitives (md5, sha1, des, rc4), ECB, fixed CBC IV.
- CA064/CA065 TLS verification disabled (`danger_accept_invalid_certs(true)`, custom
  `ServerCertVerifier` returning Ok unconditionally).
- NEW candidate (propose an ID): KDF cost parameters (Argon2 m/t/p, PBKDF2 iterations, scrypt
  log_n) taken from deserialized/untrusted input without an upper bound before use — observed in
  a real crate during our manual audit (attacker-controlled Argon2 memory → OOM/abort).

TESTING / EVALUATION HARNESS (this is half the project, not an afterthought)
- `tests/fixtures/<rule>/{bad,good,tricky}/*.rs` + `insta` snapshot tests of findings.
- `corpus/` crate: one intentionally vulnerable module per rule + fixed twin (this is
  Deliverable 3). A `cargo xtask eval` command scans it and prints a per-rule table:
  TP, FP, FN, precision, recall, against a ground-truth `corpus/expected.toml`.
- `cargo xtask scan-real <git-url> <rev>`: clone at a pinned commit into `eval/repos/`, run the
  tool, write JSON results to `eval/results/<name>-<rev>.json`. Pinned commits = reproducibility.
- Calibration set (should be quiet or near-quiet; every finding here gets manually triaged):
  RustCrypto/AEADs, RustCrypto/MACs, rusty_paseto, ecies/rs, eth-keystore-rs.
  Known true positives from our manual audits to use as recall checks:
  * ecies/rs `src/elliptic/secp256k1.rs` — manual `impl Debug for SecretKey` printing raw bytes (CA010)
  * ecies/rs same file — `PartialEq for SecretKey` via `to_bytes() == to_bytes()` (CA013/CA021-adjacent)
  * eth-keystore-rs `src/lib.rs` — MAC compared with `!=` on slices (CA021)
  * eth-keystore-rs `src/lib.rs` — no zeroization of derived key / decrypted private key (CA015)
- CI: GitHub Actions running fmt, clippy -D warnings, tests, and `cargo cryptaudit` on its own
  workspace (dogfooding). Upload SARIF on the self-scan.

ENGINEERING RULES
- `#![forbid(unsafe_code)]`. No network access at runtime. No `cargo build` of the target —
  we only parse source (fast, safe to run on untrusted repos).
- MSRV: latest stable minus 2. Pin `syn = "2"`.
- Every rule: doc comment with ID, what/why, example bad + fixed code, known false-positive
  shapes. `cargo cryptaudit --explain CA021` prints it.
- Performance target: scan a 50k-LOC crate in < 2 s on a laptop. Parallelise per file with `rayon`.
- README: install, usage, rule table (ID, name, severity, confidence, Rust-specific?), how to
  suppress, SARIF/CI snippet, comparison table vs cargo-audit/clippy/semgrep.

WORKING STYLE
- Start by writing the workspace skeleton, the Finding/Rule/Context types, file walking, and
  the human + JSON reporters with ONE rule (CA010) end to end, including fixtures and snapshot
  tests. Show me the output on the fixtures before adding rule 2.
- After each rule: run the full test suite and `cargo xtask eval`, report the precision/recall
  delta, and commit with a message `rule(CA0xx): ...`.
- If a rule can't be done reliably syntactically, say so and downgrade its confidence rather
  than piling on heuristics.
- Don't publish to crates.io or push anywhere; we do that ourselves.

DEFINITION OF DONE (MVP)
- `cargo install --path crates/cargo-cryptaudit` then `cargo cryptaudit` works in any crate.
- 10 MVP rules with fixtures and snapshot tests, all green.
- `cargo xtask eval` prints per-rule precision/recall on the corpus.
- Results for ≥ 5 pinned real crates in `eval/results/`, each finding labelled TP/FP in
  `eval/triage.md` with a one-line reason.
- SARIF output validates and shows up in GitHub code scanning on the repo itself.
