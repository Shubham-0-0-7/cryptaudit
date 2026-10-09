# Design Project Proposal

**Title:** `cargo-cryptaudit` — A Static Analysis Tool for Cryptographic API Misuse in the Rust Ecosystem

**Team:** Shubham Chhatbar & Rahul Paul
**Supervisor:** Prof. Abhishek Kesarwani
**Duration:** 3.5 months (14 weeks)

---

## The Problem in One Paragraph

Modern cryptographic algorithms — ChaCha20-Poly1305, AES-GCM, Argon2 — are mathematically secure. Yet real-world systems built on them are routinely broken, not because the math fails, but because developers *use the API incorrectly.* A 2019 ACM CCS study (CryptoGuard) found that **89.5% of 300 analysed Java applications contained at least one cryptographic API misuse** — hardcoded keys, weak random numbers, missing authentication, non-constant-time comparisons. These are not theoretical: they are the source of real CVEs and production breaches. The Rust ecosystem has no equivalent detection tool. This project builds one.

---

## Why "Just Be Careful" Is Not Enough — The Nonce Problem

The most illustrative example is **nonce reuse** in stream ciphers like ChaCha20.

ChaCha20 encrypts by XORing plaintext with a keystream derived from `(key, nonce, counter)`. If two messages are encrypted with the **same key and same nonce**, the keystream is identical for both. XORing the two ciphertexts cancels the keystream entirely, giving an attacker the XOR of the two plaintexts — which is sufficient to recover both messages in most practical cases. This is not a new attack; it was the root cause of the PS3 private key leak (2010) and multiple TLS session vulnerabilities.

**A natural response is:** *"Use a timestamp as the nonce."*
This approach has a well-documented failure class:

| Scenario | Why timestamp nonce fails |
|---|---|
| Distributed systems | Two servers encrypting at the same millisecond produce identical nonces — same keystream, broken security |
| High-throughput services | Nanosecond granularity still collides under load; OS timer resolution is not fine enough |
| Predictability | Timestamps are sequential and guessable — violating the requirement that nonces be unpredictable in protocols that depend on nonce freshness |
| Multi-threaded code | A race condition between threads can generate the same timestamp nonce concurrently, a Rust-specific async hazard |

This is exactly the type of subtle, multi-condition misuse that no amount of developer caution reliably prevents — but that a static analysis tool can detect **at every commit, for free.**

---

## Why Not Just Hire a Security Expert?

Security audits by experts are valuable, but they have a fundamental scaling problem:

- A manual audit is a **point-in-time event** — it does not catch misuse introduced in the next commit.
- Expert audits are expensive (~$200–500/hour) and inaccessible to the majority of open-source projects and small teams — which is where most RustCrypto library users live.
- Even expert-audited codebases regress: a developer adds a feature next month and reintroduces a hardcoded IV.

This is precisely why automated static analysis tools exist — Veracode, Checkmarx, SonarQube — and why CryptoGuard/CogniCrypt were published at top venues (ACM CCS, NDSS). They do not *replace* experts; they provide **continuous, repeatable, zero-cost detection** on every build. Our tool applies the same philosophy specifically to the Rust cryptographic ecosystem, where no such tool currently exists.

---

## What Already Exists (and Why It's Not Enough)

| Tool | What it does | Gap |
|---|---|---|
| `cargo-audit` | Checks `Cargo.lock` for known CVEs | No pattern detection — tells you a crate version is vulnerable, not *how your code misuses it* |
| Clippy | Catches non-idiomatic Rust | No cryptographic domain knowledge — does not understand nonces, MACs, or constant-time requirements |
| Semgrep (Rust) | Generic pattern matching | No pre-built crypto rule set; no Rust-type-system awareness |
| CryptoGuard / CogniCrypt | Crypto misuse detection | **Java only** — Rust's ownership model, trait system, and `#[derive(Debug)]` footgun do not exist in Java |

The gap is real and documented. Our contribution is the first tool targeting this specific intersection.

---

## Rust-Specific Misuse — Not Just Java Problems Ported Over

Several misuse patterns are unique to Rust and cannot be detected by any existing tool:

1. **`#[derive(Debug)]` on a struct containing a key** — the compiler automatically generates a `Debug` impl that prints raw key bytes to logs. Developers add this habitually. No Java equivalent.

2. **`Clone`/`Copy` derived on secret types** — duplicates key material across memory locations, defeating zeroization even when the developer correctly calls `zeroize()` on one copy.

3. **Compiler-optimised-away zeroization** — a `buf.fill(0)` call on a key buffer can be silently removed by the LLVM optimiser as a "dead write" (the buffer goes out of scope anyway). The `zeroize` crate exists specifically to prevent this with volatile writes. Manual zeroing without it gives a false sense of security. This is a documented, real LLVM behaviour.

4. **`.unwrap()` on a crypto `Result`** — turning a decryption authentication failure (tampered ciphertext) into a panic, which is a denial-of-service vector rather than safe error handling.

5. **Non-constant-time comparison via `==`** — comparing MAC tags byte-by-byte with early exit. An attacker measuring response time can forge a valid MAC incrementally, one byte at a time.

These five patterns alone justify a Rust-specific tool. CogniCrypt cannot check any of them.

---

## What We Will Build

### Deliverable 1: Misuse Taxonomy
A documented catalogue of 6–8 Rust cryptographic anti-patterns, each with:
- A concrete code example showing the misuse
- The attack scenario it enables
- The correct fix
- Why existing tools miss it

### Deliverable 2: `cargo-cryptaudit` MVP
A Rust command-line tool (`cargo install cargo-cryptaudit`) that parses Rust source code using the `syn` crate (the standard Rust AST library) and reports violations. **Initial rule set:**

| Rule | What it detects |
|---|---|
| R1 | Hardcoded key/IV byte literals passed to encrypt functions |
| R2 | `==` comparison on MAC/hash output instead of `ct_eq()` |
| R3 | `use chacha20::ChaCha20` (raw cipher) without accompanying authentication — missing AEAD |
| R4 | Secret-holding structs missing `Zeroize` implementation |
| R5 | `#[derive(Debug)]` on a struct with key-typed fields |

### Deliverable 3: Synthetic Corpus
A small Rust crate with intentionally introduced misuses — one for each rule. Used to measure the tool's precision and recall (i.e., does it catch what it claims to catch, and does it avoid false positives?).

### Deliverable 4: Real-Crate Evaluation
Run the tool against 5–10 publicly available Rust projects that use RustCrypto AEAD crates. Report what is found — including a clean negative result ("no misuses found, and here is the proof") which is a valid scientific outcome.

### Deliverable 5: Report / Paper
Misuse taxonomy + tool design + evaluation results. Target: college design project report; stretch goal: SCORED workshop or ePrint.

---

## 14-Week Plan

| Weeks | Work |
|---|---|
| 1–2 | Literature review (CryptoGuard, CogniCrypt papers), taxonomy draft |
| 3–4 | CLI scaffold + `syn` integration, first 2 rules working |
| 5–6 | Remaining MVP rules + synthetic corpus |
| 7–8 | Precision/recall evaluation on corpus, false-positive tuning |
| 9–10 | Scan 5–10 real crates, triage findings |
| 11–12 | Write paper/report, polish tool documentation |
| 13–14 | Buffer, demo, submission |

---

## What Success Looks Like

**Minimum (pass bar):**
A working CLI that catches known bad patterns on the synthetic corpus, with documented precision/recall numbers, and a taxonomy paper.

**Good outcome:**
One or more real misuse patterns found in downstream crates using RustCrypto libraries.

**Strong outcome:**
A finding that warrants responsible disclosure to a crate maintainer — a concrete security contribution to the open-source ecosystem.

---

## Prior Art That Validates This Direction

- **CryptoGuard** (Rahaman et al., ACM CCS 2019) — Java crypto misuse detection, 98.6% accuracy, adopted internally by Oracle.
- **CogniCrypt** (Krüger et al., ASE 2017) — Eclipse plugin for Java, shipped to ~100K developers.
- **"An Empirical Study of Cryptographic Misuse in Android Apps"** (Egele et al., ACM CCS 2013) — found misuse in 88% of 11,748 apps.

These papers establish that crypto misuse is a real, measurable, widespread problem — and that automated detection is a published, peer-recognised solution. Our work is the first application of this methodology to the Rust ecosystem.
