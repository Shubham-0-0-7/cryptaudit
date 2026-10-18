# Blind evaluation, round 7

Build measured: the frozen scanner built after the round-6 fix pass (reports version 0.5.0, lists 25 rules, includes CA010-CA015 fixes and the seven new rules CA024, CA025, CA029, CA062-CA066). Scanned with `--format json --min-confidence low --fail-on critical`; "default view" means confidence medium or high.

## Method and caveats (read first)

- The labeller is one AI agent (Claude), not a human. Every label comes from reading the code around the finding, but they are one reader's judgement and were not cross-checked by a second labeller.
- The sample is seeded (seed 20261018) and stratified by rule: up to 12 default-view findings per rule, taken from the list sorted by (repo, path, line); rules with 12 or fewer default-view findings were taken whole. Low-confidence findings were counted but not labelled.
- Rules with few findings give percentages that say very little. CA014, CA018, CA024, CA063, CA071 have 2 to 4 samples each; a single row moves them by 25 to 50 points. Only CA010 and CA015 have n=12.
- One crate dominates the sample: rauthy produced 123 of 180 default-view findings and 22 of 49 sampled rows. The overall numbers are therefore close to "rauthy plus a few others".
- Clone problems: garage (deuxfleurs) and svix-webhooks hung on clone, so loco (loco-rs/loco) took the third web-framework slot instead. This was decided before any scan was run. bdk then produced zero findings; it was kept (not swapped) so the crate list was not tuned to results.
- No repo build scripts or code were run. Scans ran from the scratchpad, not the repo working tree.

## The 12 crates

Rust lines = all `.rs` lines in the clone, including tests and examples (via `wc -l`). Findings = all confidence levels / default view.

| Crate | Commit | Kind | Rust lines | Files scanned | Findings (all) | Default view |
|---|---|---|---:|---:|---:|---:|
| actix-web | 0ea6374 | HTTP server framework | 87,984 | 214 | 4 | 2 |
| Rocket | 3a54d07 | HTTP server framework | 80,152 | 262 | 19 | 1 |
| loco | 9f7e021 | web framework (JWT auth, mailer) | 63,555 | 166 | 29 | 15 |
| rauthy | ea58753 | OIDC / SSO auth service | 93,518 | 311 | 322 | 123 |
| reqwest | 2230ed3 | HTTP client (TLS) | 27,854 | 40 | 7 | 2 |
| mongo-rust-driver | 3b7fc93 | database driver (TLS, SCRAM, CSFLE) | 91,881 | 212 | 77 | 17 |
| rust-postgres | 6c161e3 | database driver (TLS, SCRAM) | 27,013 | 91 | 7 | 4 |
| lettre | 94b63ac | mail client (SMTP/TLS, DKIM) | 16,958 | 55 | 13 | 2 |
| bdk | b62debf | Bitcoin wallet library | 27,553 | 36 | 0 | 0 |
| rathole | a292f7e | reverse-proxy / tunnel (Noise) | 4,449 | 17 | 22 | 4 |
| rustic | 143d073 | backup CLI with encryption | 12,840 | 62 | 9 | 1 |
| trussed | 3a68a78 | embedded crypto service (device firmware) | 14,685 | 62 | 15 | 9 |
| **Total** | | | **548,442** | | **524** | **180** |

## Per-rule results (sampled rows)

TP = real problem; TH = true but hardening; NP = true pattern in test/example/dev code; FP = claim wrong. Strict precision = (TP+TH)/n. Default-view total is across all 12 crates. Rules not listed produced no default-view findings.

| Rule | Default-view total | Low-conf total | n | TP | TH | NP | FP | Strict precision | TP-only |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| CA010 secret-in-debug | 62 | 104 | 12 | 0 | 8 | 0 | 4 | 66.7% | 0.0% |
| CA014 secret-in-log | 2 | 18 | 2 | 1 | 0 | 0 | 1 | 50.0% | 50.0% |
| CA015 secret-not-zeroized | 93 | 56 | 12 | 0 | 9 | 0 | 3 | 75.0% | 0.0% |
| CA018 unwrap-on-crypto-result | 3 | 0 | 3 | 0 | 0 | 0 | 3 | 0.0% | 0.0% |
| CA021 mac-compared-with-eq | 4 | 0 | 4 | 0 | 1 | 0 | 3 | 25.0% | 0.0% |
| CA024 weak-primitive | 4 | 15 | 4 | 0 | 0 | 0 | 4 | 0.0% | 0.0% |
| CA063 fast-hash-of-password | 2 | 0 | 2 | 0 | 0 | 0 | 2 | 0.0% | 0.0% |
| CA064 tls-certificate-validation-disabled | 8 | 8 | 8 | 0 | 0 | 1 | 7 | 0.0% | 0.0% |
| CA071 fixed-rng-seed | 2 | 0 | 2 | 0 | 0 | 1 | 1 | 0.0% | 0.0% |
| CA011 copy-on-secret | 0 | 0 | 0 | | | | | n/a | n/a |
| CA012 serialize-on-secret | 0 | 111 | 0 | | | | | n/a | n/a |
| CA013 partialeq-on-secret | 0 | 26 | 0 | | | | | n/a | n/a |
| CA065 tls-hostname-verification-disabled | 0 | 6 | 0 | | | | | n/a | n/a |
| **All** | **180** | **344** | **49** | **1** | **18** | **2** | **28** | **38.8% (19/49)** | **2.0% (1/49)** |

Total findings 524 = 180 default view + 344 low confidence. 111 low-confidence CA012 and 26 CA013 findings were not looked at, so nothing is claimed about them beyond the fact that they stayed out of the default view.

## Overall against earlier rounds

| Round | Sampled | Strict precision | TP-only |
|---|---:|---:|---:|
| 5 | 52 | 31% | 12% |
| 6 (released 0.5.0) | 55 | 30.9% (17/55) | 9.1% |
| 7 (this build) | 49 | 38.8% (19/49) | 2.0% (1/49) |

Reading this honestly: strict precision rose by about 8 points, but with n of about 50 per round that difference is inside sampling noise (a 95 percent interval on 19/49 is roughly 26 to 53 percent). The rise comes entirely from TH rows (18 of the 19 positives; CA010 and CA015 hardening findings, 11 of them in rauthy). TP-only fell from 9.1 percent to 2.0 percent: one real finding in 49. Taking TH out, 1 of 49 is a true problem. CA011, CA012 and CA013 produced no default-view findings here (CA012 and CA013 only low-confidence ones), so the changes to them cannot be judged from this sample. The rules that remain loud, CA010 and CA015, are mostly hardening, and CA064/CA024/CA021/CA018 added or kept pure false positives.

Counting only non-NP rows (47), strict precision is 40.4 percent; this is the same denominator question rounds 5 and 6 faced, and the headline above keeps NP in the denominator as the earlier rounds did.

## New rules (CA024, CA025, CA029, CA062 to CA066)

| Rule | Default-view | Low-conf | n sampled | TP | TH | NP | FP | What happened |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| CA024 weak-primitive | 4 | 15 | 4 | 0 | 0 | 0 | 4 | all in trussed: a feature-gated 3DES mechanism the key-service library offers for PIV compatibility |
| CA025 ecb-mode | 0 | 0 | 0 | | | | | nothing fired |
| CA029 password-compared-with-eq | 0 | 0 | 0 | | | | | nothing fired |
| CA062 weak-password-hash-cost | 0 | 0 | 0 | | | | | nothing fired |
| CA063 fast-hash-of-password | 2 | 0 | 2 | 0 | 0 | 0 | 2 | both in rust-postgres: the MD5 exchange the Postgres wire protocol mandates |
| CA064 tls-certificate-validation-disabled | 8 | 8 | 8 | 0 | 0 | 1 | 7 | reqwest, mongo-rust-driver, lettre, rauthy offering opt-in switches; one Rocket test-bench client (NP) |
| CA065 tls-hostname-verification-disabled | 0 | 6 | 0 | | | | | only low-confidence findings, not labelled |
| CA066 jwt-verification-disabled | 0 | 0 | 0 | | | | | nothing fired (loco and rauthy both use JWT) |
| **New rules total** | **14** | **29** | **14** | **0** | **0** | **1** | **13** | **0 TP, 0 strict positives** |

The new rules found no true positives in these 12 crates. That does not show they are useless (zero firing on CA025/CA029/CA062/CA066 is the right answer if the crates have no such code, and only recall on seeded bad code can test that), but all 14 default-view findings they did produce were wrong or test code. CA064 is the notable one: 7 of 8 are libraries or services that expose a deliberate, documented, off-by-default switch for self-signed certificates. CA071 (not in the list of new rules) also fired twice: 0 positives.

## False-positive causes (28 FP rows, plus 2 NP)

| Cause | Count | Rules affected | Rows |
|---|---:|---|---|
| TLS-verification-off found inside code that implements an opt-in switch (library option, operator config flag, the `NoVerifier` behind a `danger_` method) | 7 | CA064 | 40-46 |
| Flagged "secret" is not a secret: a duration, URL, bool, SHA-256 of a random one-time password, ciphertext blob, per-session CSRF token | 6 | CA010, CA015 | 1, 4, 8, 17, 19, 20 |
| Library implements the primitive or protocol it is named for (3DES mechanism in a key service, MD5 in the Postgres auth exchange) | 6 | CA024, CA063 | 33-38 |
| Comparison is of public non-secret values (HTTP ETag tags, replica-set tags) matched by a `tag` name | 3 | CA021 | 29, 30, 32 |
| `unwrap`/`expect` on decrypt of the server's own stored data or startup bootstrap with an operator message, not attacker input | 3 | CA018 | 26-28 |
| Intended output or documented design (key-generation command that prints the key; documented test-only fixed seed) | 2 | CA014, CA071 | 12, 47 |
| Debug impl already redacts the field | 1 | CA010 | 10 |
| NP: test-bench client; statement-level `#[cfg(test)]` constant seed with a real-RNG non-test branch | 2 | CA064, CA071 | 39, 48 |

## True positives and near-misses

- TP, 1 row: rathole `src/server.rs:327` (CA014, high). On a failed authentication the server `debug!`-logs the expected `SHA-256(token || nonce)` digest next to the received one. Anyone who can read debug logs gets a value they can test token guesses against offline. Severity is low (debug level, per-connection nonce), but a reviewer would remove the line.
- TH worth knowing, rathole `src/server.rs:322` (CA021): the same function compares that digest with `!=`. The nonce is fresh per connection (`thread_rng().fill_bytes`), so a byte-by-byte timing attack has no stable target. Labelled TH, not TP, because the condition that would make it TP (a reusable expected value) is absent.
- The 18 TH rows are mostly `derive(Debug)` or missing `zeroize` on config structs, request DTOs and long-lived keys (rauthy 11, mongo-rust-driver 3, loco 2, rathole 2). None showed a sink where the value is actually printed.

## Anecdote: real things noticed that the tool did not flag

This is an anecdote from reading about 50 code regions, not a recall measurement. Little turned up.

- rathole authenticates a control channel with plain `SHA-256(token || nonce)` rather than an HMAC. Not a practical break (the nonce is random, the token is the secret), and the default transport is cleartext TCP unless Noise is enabled; both are design choices rather than bugs, so I would not call them findings.
- rauthy hand-writes redacting `Debug` impls for `User` and `ApiKey` (`password: <hidden>`, `secret: <hidden>`) and rathole wraps keys in a `MaskedString`; the tool does not recognise either idiom in the neighbouring derive-based structs, which is part of the CA010 noise.
- mongo-rust-driver and rust-postgres verify SCRAM server signatures with `hmac.verify_slice`, i.e. constant time, as expected. In the rauthy KV secret check I read, `constant_time_eq` is used.

I did not find a missed true bug of the kind the tool targets. That is a statement about what I happened to read, not about recall.

## Proposed fixes (not implemented)

1. CA064/CA065/CA066: do not flag when the disabling value is a variable, parameter, config field or builder method argument, or sits in a function named like `danger_*`/`allow_invalid_*`/`accept_invalid_*`, or in an impl of a `NoVerifier`-style type that is only reachable through such a branch. Flag only an unconditional literal `true`/`NONE` on a production path. Treat `testbench`/`testing` directories as test paths.
2. CA010/CA015: add a field filter. Skip fields typed `bool`, `Duration`, integer, `Url` or ending `_lifetime`, `_endpoint`, `_exp`, `_ttl`, `_url`, `_basic`, `_post`, `csrf*`; skip `Vec<u8>` fields whose struct also uses `EncValue`/`encrypt` for them; recognise `"<hidden>"`, `Redaction` and `MaskedString` patterns. Lower the default-view confidence of `Deserialize`-only request DTOs for CA015 (they are transient and zeroizing them rarely helps), and report CA010/CA015 on config structs as one hardening-class finding per struct instead of one per field set.
3. CA024/CA063: stay quiet when the file or crate is itself the implementation (impl of a trait named after the primitive, `fn md5*` in a `*-protocol` crate, code under an `authentication/` module of a database driver). Keep the finding when the primitive is applied to application data.
4. CA021: require the compared operand name to match `mac|hmac|digest|signature|token` as a whole word and exclude type names such as `EntityTag`, and the bare word `tag` / `tags` on its own. Optionally lower confidence when the other side is freshly nonce-bound.
5. CA018: do not flag `expect` with a message in startup/bootstrap/migration code or where the ciphertext comes from the application's own store; keep it for decrypt of request or network input.
6. CA071/CA072: honour `#[cfg(test)]` on statements and let-bindings (the `loco-new` case), and skip modules whose doc comment says "testing only".
7. CA014: skip a `println!`/`print!` of a value created a few lines earlier by a `generate_keypair`/`genkey` call in a function whose name contains `genkey`/`keygen`.
8. Rank within the default view so that TH-class rules (CA010, CA015 on config and DTOs) are separated from findings with a demonstrated sink (CA014, CA021, CA029); 18 of 19 positives this round were TH and would otherwise bury the single TP.

## Files

- `eval/blind/labels_round7.csv`: 49 labelled rows (`id,repo,commit,rule,confidence,location,label,reason`).
- Scratch (not in repo): clones, scans, `sample.json`, `mk.py`, `ctx.py`, `label.py` under the round-7 scratchpad `work/` directory.
