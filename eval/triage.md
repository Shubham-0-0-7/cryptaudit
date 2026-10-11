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
| rust-random/rand | `9e7d328` | stress test for the RNG rules (full of `SmallRng` and fixed seeds) |

## Known true positives (recall)

| Repo | Location | Rule | Result |
|---|---|---|---|
| ecies/rs | `src/elliptic/secp256k1.rs:50` `impl Debug for SecretKey` prints raw bytes | CA010 | found, high |
| ecies/rs | `src/elliptic/secp256k1.rs:39` `PartialEq for SecretKey` compares with `==` | CA013 | found, high |
| eth-keystore-rs | `src/lib.rs:146` MAC compared with `!=` | CA021 | found, high |
| eth-keystore-rs | `src/lib.rs:112` decrypt: derived key never zeroized | CA015 | found, medium |
| eth-keystore-rs | `src/lib.rs:202` encrypt: derived key never zeroized | CA015 | found, medium (a second instance of the same bug) |

Recall on implemented rules: 4 of 4 known bugs.

## Findings and false positives found during calibration

These were found with the first version of each rule and fixed; each fix has a
regression fixture.

| # | Repo | Finding | Verdict | Reason | Fix |
|---|---|---|---|---|---|
| 1 | RustCrypto/AEADs | CA019 `eax/src/online.rs:253` `self.imp.decrypt(msg);` | FP | unit-returning stream `decrypt`, no `Result` to discard | bare statement with a generic method name is now low confidence |
| 2 | rusty_paseto | CA010 `EncryptionKeySeparator` (derive + Display) | FP | domain-separation constant `&'static str`, not a secret | `&'static` references are never secret |
| 3 | ecies/rs | CA010 on `SecretKey` missed at first | FN | secret reached the formatter through a typed `let` binding and an opaque wrapper field | typed-let aliasing; `self.0.to_bytes()` counts as evidence |
| 4 | RustCrypto/AEADs | CA021 on `let digest = Sha256::digest(..); digest.as_slice() != x` was low | FN (confidence) | the MAC API call was in the `let`, the name only said `digest` | locals bound from a MAC-producing call keep that evidence |
| 5 | (fixtures) | CA027 on `let mut key = [0u8; 32]; kdf(&mut key); new(&key)` | FP | a zeroed buffer filled by a KDF or RNG is not a hardcoded key | a local passed as `&mut`, or mutated by a method, is no longer a constant |
| 6 | (fixtures) | CA071 on `let mut seed = [0u8; 32]; OsRng.fill_bytes(&mut seed); from_seed(seed)` | FP | same pattern for RNG seeds | same fix |
| 7 | eth-keystore-rs | CA015 `lib.rs:130` inner `key` returned as a block value | FP | the buffer leaves its block as the tail expression and is owned by the outer `let key` | follow block-tail moves; the outer binding inherits the buffer |
| 8 | rusty_paseto | CA015 `PasetoAsymmetricPrivateKey` (`key: &'a [u8]`), `PasetoNonce`, `PasetoAsymmetricPublicKey` | FP | borrowed slices: the struct does not own the bytes, and two are public material | borrowed fields are skipped; types named public/verifying are skipped |
| 9 | rusty_paseto | CA015 `raw_token` in three `raw_payload_impl` files (x3) | FP | `raw_token` is the assembled ciphertext (nonce, ciphertext, tag), which is public | names whose only secret-sounding word is `token` are skipped for locals |

## Findings that are true positives of the hardening kind

| Repo | Finding | Verdict | Note |
|---|---|---|---|
| RustCrypto/AEADs | CA015 `aes-siv/src/lib.rs:121` `SivAead { key }` | TP (hardening) | the sibling `Siv` type zeroizes its key behind a `zeroize` feature; the `SivAead` wrapper stores a raw copy with no wipe |
| RustCrypto/AEADs | CA015 `eax/src/lib.rs:171` `Eax { key }` | TP (hardening) | no `zeroize` dependency; the raw key stays in memory until freed |

These are defence-in-depth gaps, not vulnerabilities. They were not reported to
the maintainers.

## Design decisions made from the calibration

- `thread_rng()` is not flagged by CA023, although the taxonomy lists it:
  `ThreadRng` is documented as cryptographically secure, so flagging it would be a
  false positive on most Rust code.
- CA071 and CA072 are graded by what the generator is used for, not by the
  taxonomy's flat "high": `SmallRng::seed_from_u64(42)` for a simulation is common
  and harmless, and is only reported at low confidence unless the output reaches a
  key, nonce, IV, salt or secret.
- CA078 (predictable counter nonce) is not implemented: a counter nonce is
  legitimate when it is unique, which a syntactic check cannot tell.

## Current results

Default view (`--min-confidence medium`), all 16 rules:

| Repo | Findings | Hidden (low) | TP | FP |
|---|---|---|---|---|
| ecies/rs | 2 | 0 | 2 | 0 |
| eth-keystore-rs | 3 | 0 | 3 | 0 |
| RustCrypto/AEADs | 2 | 1 | 2 (hardening) | 0 |
| RustCrypto/MACs | 0 | 0 | - | - |
| rusty_paseto | 0 | 3 | - | - |
| rust-random/rand | 0 | 1 | - | - |
| cryptaudit (self) | 0 | 0 | - | - |

With `--include-tests` the rules fire where expected: RustCrypto/AEADs tests give
5 CA027 (hardcoded test keys) and 6 CA028 (fixed or reused nonces in tests and
benchmarks), and `rand`'s test modules give 5 CA071 (fixed seeds for test
vectors). That is why tests are skipped by default.

The hidden low-confidence findings are the shapes the confidence levels exist for:
a unit-returning `decrypt` (AEADs), `&str` fields on a type named `Token` or
`Error` (rusty_paseto), and an index type called `Element` (rand).

## Caveat

Precision here is measured on repositories that were chosen because they are
expected to be quiet, and the rules were tuned against them: 9 of the false
positives above were found and fixed this way. The numbers show the rules do not
fire on well-written code; they are not an estimate of precision on arbitrary
crates. The next step is to scan unseen crates and triage blind.
