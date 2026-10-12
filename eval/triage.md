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

## Blind evaluation (unseen crates)

Twelve repositories the rules were never tuned on were scanned with
`--no-suppress --min-confidence low`, and **every one of the 245 findings** was
labelled by reading the code. The labelled corpus is
[eval/blind/labels.csv](blind/labels.csv) (repo, pinned commit, rule, confidence,
location, label, reason). Nothing was fixed before labelling.

Labels: **TP** real problem; **TH** true but hardening only (a secret is never
wiped); **NP** true but in test or tool code, so not a vulnerability; **FP** the
claim is wrong. *Strict* precision counts TP + TH. *Lenient* also counts NP.

| Repo | Commit | Findings (all) | Default view |
|---|---|---|---|
| atuin | `3e1c10b` | 65 | 8 |
| rustls | `5535e9d` | 34 | 17 |
| orion | `f4b3db3` | 53 | 35 |
| jsonwebtoken | `11f83ab` | 29 | 2 |
| snow | `8ac60f5` | 20 | 16 |
| boringtun | `6dcc889` | 12 | 12 |
| rage | `b5b68c4` | 11 | 4 |
| magic-wormhole.rs | `41d78ae` | 9 | 9 |
| rust-openssl | `6a639a0` | 7 | 6 |
| curve25519-dalek | `97a020d` | 3 | 1 |
| password-hashes | `958527c` | 2 | 2 |
| sodiumoxide | `3057acb` | 0 | 0 |

### Precision per rule, default view (medium and high confidence)

| Rule | Findings | TP | TH | NP | FP | Strict | Lenient |
|---|---|---|---|---|---|---|---|
| CA010 | 20 | 7 | 0 | 1 | 12 | 35% | 40% |
| CA012 | 2 | 2 | 0 | 0 | 0 | 100% | 100% |
| CA013 | 6 | 3 | 0 | 0 | 3 | 50% | 50% |
| CA015 | 40 | 0 | 23 | 1 | 16 | 57% | 60% |
| CA018 | 3 | 0 | 0 | 2 | 1 | 0% | 67% |
| CA020 | 12 | 0 | 0 | 12 | 0 | 0% | 100% |
| CA021 | 9 | 0 | 0 | 0 | 9 | 0% | 0% |
| CA027 | 6 | 0 | 0 | 0 | 6 | 0% | 0% |
| CA028 | 14 | 0 | 0 | 7 | 7 | 0% | 50% |
| **All** | **112** | **12** | **23** | **23** | **54** | **31%** | **52%** |

CA011, CA016, CA019, CA023, CA071, CA072 and CA079 produced no default-view
findings on these repositories, so nothing can be said about their precision from
this sample. With `--min-confidence low` the total is 245 findings, 17 TP, 24 TH,
30 NP, 174 FP: the low-confidence tier is 120 FP in 133, which is what it is
hidden for.

Rules that found real problems (TP): CA010 (`preshared_key` and `chaining_key`
printed by `Debug` in boringtun, the key inside `Wormhole` in magic-wormhole,
`KeyIvPair` in rust-openssl, a CLI password in atuin), CA012 (`StaticSecret` is
serialisable behind a feature in x25519-dalek), CA013 (derived `PartialEq` on a
32-byte key in atuin and on a key+IV pair in rust-openssl).

### Why the false positives happen (default view)

| Count | Cause | Rules | Fixable? |
|---|---|---|---|
| 11 | name looks secret but is not (`key` as a map key or key binding, `pwd` as a directory) | CA010, CA013, CA015 | partly: skip clap/config types, `pwd` |
| 10 | public material with a secret-sounding name (HPKE `enc`, ML-KEM encapsulation key, JWK `n`/`e`) | CA010, CA013, CA015 | partly: name list for public parts |
| 9 | the type already protects itself (orion's tags compare in constant time, a redacted `Debug`, `SecretString`) | CA021, CA010 | only with type information; honour `derive_more::Debug` with `#[debug("..")]` |
| 6 | the check happens inside a macro the rule cannot see (`copy_slices!` fills the nonce, `zeroize_call!` wipes the buffer) | CA028, CA015 | yes: treat a macro that mentions the variable as a mutation / wipe |
| 6 | `hmac::Tag::new(..)` treated as a key constructor, or a zeroed placeholder in `Default` | CA027 | yes: `Tag::new` is not a key; ignore `Default::default` bodies |
| 12 | everything else (FFI structs, borrowed `Option<&[u8]>`, password hashes, zero nonce under a one-time key) | CA015, CA028, CA018, CA021 | mixed |

### What this says

- **Do not claim the earlier numbers.** The calibration showed 0 false positives
  because those repos were tuned against. On unseen crates the default view is 31%
  strict precision. The honest figure for the report is the blind one.
- **CA021 and CA027 have no true positive here.** Every CA021 hit is either a type
  with its own constant-time equality or not a MAC, and every CA027 hit is a
  placeholder or a `Tag::new`. Both need fixing before they are shown by default.
- **CA015 finds a lot of real hardening gaps** (23 of 40) but is noisy because it
  trusts names. It is a hardening rule and should probably be reported separately
  from the vulnerability rules.
- **CA020 and CA018 only fired in test helpers.** Test and tool code that is
  compiled as normal library code (orion's `test_framework`, rustls's `rustls-test`)
  is not recognised as test code.
- **Recall is not measured.** Labelling findings says nothing about bugs the
  rules missed. That needs a set of crates with known bugs.
- One labeller (the assistant that wrote the rules) read the code. Hard cases were
  decided by the surrounding code; a second reviewer would make the corpus
  stronger.

Suggested next step: fix the causes in the table, then re-scan **new** crates, not
these twelve, so the improvement is measured and not just tuned.

### Fixes made after round 1

Each has a regression fixture or test. Re-scanning the same twelve repos, the
default view went from 112 findings (31% strict precision) to 52 (67%), with all
12 TP and 23 TH kept. This is **measured on the repos the fixes were written
against**, so it shows the fixes work, not what precision is on new code.

| Cause | Fix |
|---|---|
| `Tag::new(..)` and `ShoHmacSha256::new(label)` read as key constructors; zeroed key in `impl Default` | `Tag`/`Output`/`Digest` and HMAC-type single-argument `new` are not key sinks; `default()` bodies are skipped |
| macros that fill a nonce (`copy_slices!`) or wipe a buffer (`zeroize_call!`) | a non-formatting macro that mentions a variable counts as changing it; `*zeroize*`/`*wipe*` macros count as a wipe |
| `self.encrypt(plaintext, ..)` read as a nonce reuse | receiver `self` is skipped |
| owner name made a neutral integer field secret (`Credential { expect_selected: isize }`) | named integer fields no longer inherit the owner's strength |
| `pwd` (working directory), `ocsp`, `cert`, `scheme`, ciphertext and KEM-encapsulation names | excluded or treated as public |
| `derive_more::Debug` with `#[debug("..")]` | recognised as redacted |
| `Option<&[u8]>` fields, `#[repr(C)]` structs | not owned / FFI values, so not CA015 |
| `File::open(..).unwrap()` read as a sealed-box `open` | file opens are skipped |
| crates that define `PartialEq` with `ct_eq` (orion) | `==` between two values of such a type is low confidence; explicit raw-byte conversions stay reported |
| `tests.rs`, `test.rs`, `bench/` and `#[cfg(test)] mod x;` files | skipped like `tests/` |

## Blind evaluation, round 2 (new crates, sampled)

Ten more repositories, scanned **after** the fixes above: rpgp, libsignal,
vodozemac, rust-secp256k1, RSA, KDFs, ring, kanidm, librespot, bitwarden
sdk-internal. They produced 2,116 findings (1,357 from sdk-internal alone), too
many to label by hand, so a seeded random sample of **12 default-view findings per
rule** (all of them where a rule had fewer) was labelled. The sample is
[eval/blind/labels_round2.csv](blind/labels_round2.csv). Nothing was changed before
labelling.

| Rule | Default-view findings in the 10 repos | Sampled | TP | TH | NP | FP | Strict precision |
|---|---|---|---|---|---|---|---|
| CA010 | 218 | 12 | 7 | 0 | 1 | 4 | 58% |
| CA011 | 12 | 12 | 10 | 0 | 0 | 2 | 83% |
| CA012 | 122 | 12 | 3 | 0 | 0 | 9 | 25% |
| CA013 | 155 | 12 | 4 | 0 | 0 | 8 | 33% |
| CA015 | 273 | 12 | 0 | 8 | 1 | 3 | 67% |
| CA018 | 15 | 12 | 0 | 0 | 12 | 0 | 0% (all test code) |
| CA021 | 11 | 11 | 9 | 0 | 0 | 2 | 82% |
| CA027 | 22 | 12 | 0 | 0 | 0 | 12 | 0% |
| CA028 | 9 | 9 | 0 | 0 | 1 | 8 | 0% |
| CA071 | 1 | 1 | 0 | 0 | 0 | 1 | 0% |

With 12 samples per rule, each percentage is only good to roughly +/- 25
points. They are not pooled, because the sample is stratified by rule, not
proportional to how often each rule fires.

What the sample shows:

- **CA011, CA021 and CA010 are useful on unseen code.** CA011 found `Copy` on
  keys in libsignal, secp256k1 and librespot; CA021 found nine real
  non-constant-time hash comparisons in kanidm's password verification, the
  first true positives of that rule.
- **CA012 and CA013 are noisy on application code.** Most hits are request and
  response structs whose purpose is to carry the value, or hashes and wrapped
  keys. They are fine on crypto libraries and weak on apps like bitwarden and
  kanidm.
- **CA018 only fired in test and bench code**, so it is correct but irrelevant
  there; those files are now skipped.
- **CA027 and CA028 had no true positive.** Causes: `ShoHmacSha256::new(label)`
  takes a domain-separation label, `value.encrypt(ctx, key)` is not a nonce, and
  several fixed keys and IVs are mandated by a protocol (Spotify's audio IV,
  the key-transparency commitment key).

### Fixes made after round 2

Applied after labelling, so the round 2 table above is the pre-fix result.
Re-scanning the labelled sample: 28 of 49 false positives and 13 of 15 test-code
findings disappeared; every TP and TH stayed except two CA013 hits in
OpenAPI-generated structs, which are now skipped on purpose.

| Cause | Fix |
|---|---|
| `#[cfg_attr(test, derive(Debug))]` treated as a production derive | skipped |
| `#[cfg(test)] mod x;` and `bench/` | module files and `bench/` skipped |
| OpenAPI and protobuf generated files | files that say `@generated` or `generated by` are skipped |
| `encrypted_*` and `wrapped_*` fields read as plaintext keys | treated as ciphertext |
| `HmacType::new(label)` and `encrypt(ctx, ..)` | not key / nonce sinks |

Not fixed: FFI assembly structs deriving `Copy` (CA011), protocol-fixed keys and
IVs (CA027), `Serialize` on types whose purpose is to carry a secret (CA012).
Those need annotations from the user, which is what inline suppression is for.

The honest numbers for the report are the **pre-fix** columns of both rounds. The
fixes were written against these repositories, so the next measurement needs a
third set of unseen crates.

## Caveat

Precision here is measured on repositories that were chosen because they are
expected to be quiet, and the rules were tuned against them: 9 of the false
positives above were found and fixed this way. The numbers show the rules do not
fire on well-written code; they are not an estimate of precision on arbitrary
crates. The blind evaluation above did that: strict precision in the default view is 31%.
