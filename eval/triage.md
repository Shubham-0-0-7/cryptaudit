# Evaluation triage log

Every finding on a real repository is labelled TP (true positive) or FP (false
positive) with a reason. Scans use the default `--min-confidence medium` unless
noted. Repositories are pinned so results reproduce.

| Repo | Commit | Role |
|---|---|---|
| ecies/rs | `ab35604` | known true positives (manual audit) |
| eth-keystore-rs | `85ea8cd` | known true positive (manual audit) |
| RustCrypto/AEADs | `f90367c` | calibration: expected quiet |
| RustCrypto/MACs | `e905def` | calibration: expected quiet |
| rusty_paseto | `186fac5` | calibration: expected quiet |

## Known true positives (recall)

| Repo | Location | Rule | Result |
|---|---|---|---|
| ecies/rs | `src/elliptic/secp256k1.rs:50` `impl Debug for SecretKey` prints raw bytes | CA010 | found, high |
| ecies/rs | `src/elliptic/secp256k1.rs:39` `PartialEq for SecretKey` compares with `==` | CA013 | found, high |
| eth-keystore-rs | `src/lib.rs:146` MAC compared with `!=` | CA021 | found, high |
| eth-keystore-rs | `src/lib.rs` no zeroization of derived key | CA015 | not yet implemented |

Recall on implemented rules: 3 of 3.

## Findings and false positives found during calibration

These were found with the first version of each rule and fixed; each fix has a
regression fixture.

| # | Repo | Finding | Verdict | Reason | Fix |
|---|---|---|---|---|---|
| 1 | RustCrypto/AEADs | CA019 `eax/src/online.rs:253` `self.imp.decrypt(msg);` | FP | unit-returning stream `decrypt`, no `Result` to discard | bare statement with a generic method name is now low confidence |
| 2 | rusty_paseto | CA010 `EncryptionKeySeparator` (derive + Display) | FP | domain-separation constant `&'static str`, not a secret | `&'static` references are never secret |
| 3 | ecies/rs | CA010 on `SecretKey` missed at first | FN | secret reached the formatter through a typed `let` binding and an opaque wrapper field | typed-let aliasing; `self.0.to_bytes()` counts as evidence |

## Current results

| Repo | Findings (default) | Hidden (low confidence) | TP | FP |
|---|---|---|---|---|
| ecies/rs | 2 | 0 | 2 | 0 |
| eth-keystore-rs | 1 | 0 | 1 | 0 |
| RustCrypto/AEADs | 0 | 1 | - | - |
| RustCrypto/MACs | 0 | 0 | - | - |
| rusty_paseto | 0 | 3 | - | - |
| cryptaudit (self) | 0 | 0 | - | - |

The 4 hidden findings are low confidence and are the shapes the confidence
levels exist for: a unit-returning `decrypt` (AEADs), and `&str` fields on a
type named `Token` or `Error` (rusty_paseto).

## Caveat

Precision here is measured on repositories that were chosen because they are
expected to be quiet, and the rules were tuned against them. The numbers show the
rules do not fire on well-written code; they are not an estimate of precision on
arbitrary crates. The next step is to scan unseen crates and triage blind.
