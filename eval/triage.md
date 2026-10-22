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

## Blind evaluation, round 3 (new crates, sampled)

The first measurement of the tool *after* the round 1 and round 2 fixes, on code
it had never seen: ten new repositories, none used in any earlier round or in
calibration: bitwarden-compatible server vaultwarden, russh, openmls, mls-rs,
matrix-rust-sdk, aws-lc-rs, cocoon, RustCrypto/SSH, RustCrypto/signatures and
ed25519-dalek. They produced 280 default-view findings (ed25519-dalek: none).
A seeded random sample (seed 20261013) of **12 per rule**, all of them where a
rule had fewer, gave 64 findings. They were labelled before any code changed:
[eval/blind/labels_round3.csv](blind/labels_round3.csv).

| Rule | Default-view findings in the 10 repos | Sampled | TP | TH | NP | FP | Strict precision |
|---|---|---|---|---|---|---|---|
| CA010 | 69 | 12 | 2 | 1 | 4 | 5 | 25% |
| CA011 | 1 | 1 | 0 | 0 | 0 | 1 | 0% |
| CA012 | 41 | 12 | 1 | 0 | 1 | 10 | 8% |
| CA013 | 39 | 12 | 9 | 0 | 0 | 3 | 75% |
| CA015 | 115 | 12 | 0 | 6 | 5 | 1 | 50% |
| CA016 | 2 | 2 | 0 | 0 | 0 | 2 | 0% |
| CA018 | 4 | 4 | 0 | 0 | 4 | 0 | 0% (all test code) |
| CA021 | 4 | 4 | 1 | 0 | 0 | 3 | 25% |
| CA028 | 5 | 5 | 0 | 0 | 0 | 5 | 0% |

The same caveats as round 2 apply: 12 samples per rule is good to about
+/- 25 points, the rows are not pooled, one person labelled, and findings in one
crate are correlated (10 of the 12 CA013 samples are from mls-rs, so that 75% is
mostly "mls-rs derives `PartialEq` on its secret types").

Two labelling judgements to be aware of. `Serialize` on a type whose job is to be
stored or sent (a request, a session record, a key export) is labelled FP, as in
round 2; `Serialize` on a plain secret-key type behind a `serde` feature is labelled
TP, as for `StaticSecret` in the calibration set. And `NP` covers test vectors and
test-support modules that live under `src/`, not only `tests/`.

### Strict precision across the three rounds (before any fix)

| Rule | Round 1 | Round 2 | Round 3 |
|---|---|---|---|
| CA010 | 35% (7/20) | 58% (7/12) | 25% (3/12) |
| CA011 | - | 83% (10/12) | 0% (0/1) |
| CA012 | 100% (2/2) | 25% (3/12) | 8% (1/12) |
| CA013 | 50% (3/6) | 33% (4/12) | 75% (9/12) |
| CA015 | 57% (23/40) | 67% (8/12) | 50% (6/12) |
| CA016 | - | - | 0% (0/2) |
| CA018 | 0% (0/3) | 0% (0/12) | 0% (0/4) |
| CA020 | 0% (0/12) | - | - |
| CA021 | 0% (0/9) | 82% (9/11) | 25% (1/4) |
| CA027 | 0% (0/6) | 0% (0/12) | - |
| CA028 | 0% (0/14) | 0% (0/9) | 0% (0/5) |
| CA071 | - | 0% (0/1) | - |

(Round 1 is every default-view finding in those twelve repositories; rounds 2 and 3
are stratified samples. A dash means the rule did not fire in the default view.)

What the three rounds say about each rule:

- **Useful as they are**: CA013 and CA021 when the type or the call really is a
  secret or a MAC (the kanidm password-hash comparisons, the mls-rs key schedule),
  and CA011 outside FFI code.
- **Mostly noise on application code**: CA010 and CA012. Both guess from names, and
  application structs are full of secret-sounding names that are not secrets or are
  carried on purpose.
- **Hardening, not bugs**: CA015 (every true hit is a "should be zeroized" gap).
- **No true positive in the default view in three rounds**: CA018, CA020, CA027, CA028. Their findings
  were test code, protocol constants or wrongly read arguments. They stay in the
  tool because they are cheap to suppress, but the write-up should not claim a
  detection rate for them.

### Fixes made after round 3

Applied after labelling, so the round 3 table above is the pre-fix result.
Re-scanning the labelled sample: every TP and TH is still reported (13 TP, 7 TH),
all 14 test-code findings are gone, and 16 of the 30 false positives are gone or
hidden; 14 false positives remain. Re-scanning rounds 1 and 2: no TP or TH lost in
round 1; in round 2 four are no longer in the default view (the two generated-code
hits already known from round 2, and the two CA012 findings below).

| Cause | Fix |
|---|---|
| test vectors and test support under `src/` (`tests_and_kats/`, `test_utils/`, `interop_test_vectors.rs`, `benchmark.rs`) | any directory or file whose name contains the word test, tests, testing, kat, kats, fuzz, bench or benchmark is skipped (`latest/` is not) |
| `sk_bytes: u32`, `n_secret: usize` read as secrets | an integer field named like a size or count (`n`, `num`, `bytes`, `max`, `min`, `limit`) is not a secret |
| `Credential`, `BasicCredential` read as secret types | `credential` is now a weak word (often a public identity in MLS and WebAuthn) |
| `Serialize` on a record that only has a secret-named field | CA012 is high only when the type itself is named like a secret (`SessionKey`, `StaticSecret`); otherwise low, so hidden by default. This costs the two CA012 true positives found in bitwarden in round 2 |
| a crate whose tag type compares with `equal_ct` or `ct_equal` | the crate-wide "constant-time `PartialEq`" detection recognises those names too |
| `self.sha.finalize()` compared with a hash of public data | a hash state kept in a struct field named `sha`, `md5` or `blake` is not treated as a MAC. A local `hasher` is deliberately still reported, because kanidm compares password hashes that way |
| `ff1.encrypt(&[], ..)`, `device.encrypt("m.dummy", ..)`, `node.encrypt(crypto, ..)` | an empty array and a text literal are not nonces; `crypto`, `provider`, `backend`, `rng`, `ciphersuite`, `event_type` are not nonce names |
| zeroing `sk[..n]` and then using `sk` again | CA016 is not reported if the variable is mentioned again after the wipe in the same function |

Not fixed: the type-level `Serialize` and `PartialEq` hits on secret-named types
that exist to carry the secret (CA012 on key exports and secret-sharing events),
public key material that is named like a secret (`encryption_key` that is an HPKE
public key, a FIDO key handle), and wiping a `&mut` parameter at the end of its
life (CA016). They need a human or a suppression comment.

Each fix has a fixture or a crate-context test. As in round 2, the post-fix
numbers were produced on the repositories the fixes were written against, so they
show the fixes work; they are not a precision estimate. A fourth set of unseen
crates would be needed for that.

## CA014, first evaluation

CA014 (secret passed to a logging, printing or error macro, or recorded by
`#[tracing::instrument]`) was added after round 3. It was run over every repository
from the calibration set and the three blind rounds, and **every** default-view
finding was labelled (39 of them, so this is the whole population, not a sample):
[eval/blind/labels_ca014.csv](blind/labels_ca014.csv). The rule had been written
from general knowledge and fixtures, not tuned against these repositories, so this
is its honest first measurement.

| Where | Default-view findings | TP | NP | FP | Strict precision |
|---|---|---|---|---|---|
| calibration set (6 repos) | 0 | | | | quiet, as expected |
| rounds 1-3 repos (32 repos) | 39 | 3 | 6 | 30 | 8% |

The three true positives are a kanidm bearer session token in a `trace!`, a librespot
login token in a `trace!`, and a kanidm `#[instrument]` that records a password and a
RADIUS secret. The six NP are command-line tools that print a password on purpose
and a developer-only `dangerous-crypto-debug` feature. The 30 false positives were
mostly one cause: bitwarden's `bitwarden_logging::instrument` is a wrapper that
skips every argument by default, and the rule treated it as `tracing::instrument`
(16 of 30).

Fixes made after labelling (so the table is the pre-fix result):

| Cause | Fix |
|---|---|
| `bitwarden_logging::instrument` and other wrappers | only `tracing::instrument` is reported: a path that does not start with `tracing`, or a bare `instrument` imported from another crate, is skipped |
| `{PASSWORD}` inside a message, a constant holding an option name | upper-case names are constants and are skipped, also in inline captures |
| `hex::encode(key)` of a map or storage key | encoding only raises confidence for clearly secret names (`secret_key`, `password`); a bare `key` stays low. `expose_secret()` still raises it |
| `secret_names` | `names` is an excluded word, like `name` |
| `let derived_key = k.public_key()` | a local initialised from something named public is skipped |
| `wrapping_key: SymmetricKeySlotId` | a type named like an id, slot, handle, index or ref is a handle, not a key |
| `print!` family | lowered one step: output for the person at the terminal is often the point |

After the fixes: all 3 true positives are still reported, 24 of the 30 false
positives are gone or hidden, and 6 remain (cross-signing public keys called
`master_key`, a snapshot key called `sk`, a shuffle seed, and a key type whose
`Debug` redacts). The default view over the 32 repositories drops from 39 to 14
findings. As in the other rounds, that second number was produced on the
repositories the fixes were written against; a fresh set of crates is needed to
measure it honestly. Re-scanning the earlier labelled corpora shows no true
positive or hardening finding lost by the CA014 work.

Not detected: a secret that reaches a log through a helper function, a struct whose
`Debug` is derived (that is CA010), and `format!` or `write!` (they build strings for
many other purposes).

## Blind evaluation, round 4 (new crates, sampled, after the round 3 fixes)

Twelve crates that none of the earlier rounds used: ockam, mullvadvpn-app, firezone,
rustdesk, mail-server, webauthn-rs, librustzcash, quinn, hickory-dns, sigstore-rs,
tendermint-rs and keyring-rs (keyring-rs produced no findings). Scans ran with
`--no-suppress --min-confidence low`; the default view of the 12 crates held 354
findings. A seeded sample (seed 20261014) of up to 12 default-view findings per rule,
all 16 for CA014, was labelled before any change: 91 findings in
[eval/blind/labels_round4.csv](blind/labels_round4.csv). Labels are TP, TH, NP and FP
as before, by one labeller.

This is the first measurement of the rules after the round 3 fixes on crates they
were not tuned on.

| Rule | n | TP | TH | NP | FP | Strict precision |
|---|---|---|---|---|---|---|
| CA010 | 12 | 5 | 1 | 0 | 6 | 50% |
| CA011 | 10 | 2 | 3 | 0 | 5 | 50% |
| CA012 | 11 | 0 | 0 | 0 | 11 | 0% |
| CA013 | 12 | 2 | 1 | 0 | 9 | 25% |
| CA014 | 16 | 1 | 0 | 0 | 15 | 6% |
| CA015 | 12 | 1 | 7 | 1 | 3 | 67% |
| CA018 | 3 | 0 | 0 | 0 | 3 | 0% |
| CA021 | 12 | 2 | 0 | 0 | 10 | 17% |
| CA071 | 3 | 0 | 0 | 1 | 2 | 0% |
| **All** | **91** | **13** | **12** | **2** | **64** | **27%** |

Strict precision is (TP + TH) / n. The true positives are real, for example a
`pinUvAuthToken` logged at trace level, an X25519 secret key compared with a derived
`==`, a password hash compared with `==`, and `Debug` derived on a Telegram bot token.
Low precision is not explained by clean code: the false positives are the rules
misreading harmless names.

Where the false positives come from:

| Cause | Examples | Rules |
|---|---|---|
| a secret-sounding name on something that is not a secret | Kafka `api_key` (an enum or number), a `session_key` that is a WebRTC id, a storage or ABCI `key`, an RSA public exponent `e`, a `private_tmp` path, an XOR obfuscation key | CA010, CA011, CA013, CA014 |
| a number named like a secret | `AccessToken(u32)`, a rollout seed, a shuffle seed | CA010, CA013, CA014, CA071 |
| a record that exists to be sent or stored | OAuth request, ICE credentials, a push subscription | CA012 |
| a hash of public data compared with `==` | a certificate pin, a DLL hash, a DNSSEC DS record, a TLSA record, a log entry hash | CA021 |
| not an authentication step | `File::open(..).expect(..)`, a HID device open, QUIC header protection | CA018 |
| test-only code | a `#[cfg(test)]` method inside an `impl` was not skipped | CA071 |

### Fixes made after round 4

| Cause | Fix |
|---|---|
| integers logged as secrets (`api_key_num: i16`, a seed) | CA014 skips integers unless the code calls `expose_secret()`; integer reads (`try_get_i16()`, `as u32`, `len()`) are inferred for untyped locals |
| a typed value built by a constructor (`ApiKey::try_from(n)?`) | CA014 skips locals built by `new`, `from`, `try_from`, `parse` or `from_*` on a named type, unless it is explicitly encoded or exposed: what such a value prints is decided by the type's own `Debug`, which CA010 checks |
| paths and handles | `tmp`, `temp`, `dir`, `directory`, `folder`, `handle`, `handles`, `slot`, `xor`, `obfuscation` are excluded words |
| RSA public exponent | a field called `e` does not inherit secrecy from its owner |
| `AccessToken(u32)` | an unnamed integer field inheriting a strong owner name is low, not medium |
| `VerificationKey` | `verification` is a public-material word, like `verifying` |
| CA012 on request and record types | high only when the type name is a clear secret (`SessionKey`, `StaticSecret`); `Credentials`, `TokenRequest` and similar are low |
| CA021 on hashes of public data | `Sha256::digest(..)`, `Sha1::digest(..)` and similar are unkeyed, so they count as weak evidence; a MAC, or a `hasher.finalize()` kept in a local (the password case) stays high; `key_tag` is not a tag. This reverses calibration fix 4 above for `Sha256::digest(..)` specifically: a hash of known data is not a MAC, and round 4 found it was the main CA021 false positive |
| CA018 on `open` | `open` with fewer than two arguments is a file or device open, not an AEAD `open` |
| test-only methods | `#[cfg(test)]` and `#[test]` items inside an `impl` block are removed before scanning |

Re-scanning the labelled samples after these changes:

| | Before | After |
|---|---|---|
| default-view findings, 12 round 4 crates | 354 | 299 |
| sampled TP and TH kept | 25 | 25 |
| sampled false positives still shown | 64 | 29 |
| strict precision of the sample | 27% | 45% |

No true positive or hardening finding in rounds 1-4 or the CA014 set was lost by the
round 4 fixes, except one CA012 true positive from round 2 that is now low: bitwarden's
`IdentityTokenPayloadResponse`, a response struct holding `access_token` and
`refresh_token`. Its type name is only weakly secret-sounding. This trade is
deliberate: with the type-name rule, CA012 is quiet on records that exist to be sent,
and that round 2 label is arguably inconsistent with how round 4 labels such records.

As in rounds 2 and 3, the after numbers were produced on the sample the fixes were
written against, so they show that the fixes work; they are not a precision estimate.
Findings that remain false positives are of these kinds: a `key: Vec<u8>` field that is
a storage or protocol key (CA010, CA013), signed blobs and public digests whose field
is called `digest` (CA021), a MAC address called `mac`, and Kafka `api_key` values held
in a struct field (the file does not show the type). A fifth set of crates is needed to
measure the result honestly.

A correction to an earlier note: the round 4 default view held 354 findings, not
about 450.

## Fixes made after the recall check

The recall check ([recall.md](recall.md)) found two known bugs that the rules missed. Both gaps were closed.

| Missed bug | Change |
|---|---|
| totp-rs 1.0.0: `self.generate(step_time) == token` (CA021) | a value produced by a `generate`, `compute` or `calculate` call, compared with `==` or `!=` against a name such as `token`, `code`, `otp` or `signature`, is reported at medium confidence with its own message ("one-time code or token compared with `==`"). Both halves are required; `generate_id()`, `generate_nonce()` and similar are not counted |
| cocoon 0.3.3: the RNG is cloned for each call, so every nonce is the same (CA028) | `let mut rng = self.rng.clone(); rng.fill_bytes(&mut nonce)`, and the same call chained directly, is reported at medium confidence when the buffer is named like a nonce, IV, salt or key. Known false positive: `ThreadRng` shares its state between clones |

Both are caught on the vulnerable release and silent on the patched one. They add no
finding on the 12 round 4 crates or the 6 calibration crates, so they cost no precision
on those sets. That also means no true positive of either kind was found there: these two shapes
did not occur in that code, so the rules rest on fixtures and two advisories.

## Blind evaluation, round 5 (new crates, sampled, after the round 4 fixes)

The point of this round is to measure precision on crates that no fix was written against.
Twelve crates that no earlier round used: application-services, aws-lc-rs, cargo, ente,
lldap, meilisearch, quiche, rust-bitcoin, s2n-quic, sudo-rs, tmkms, vodozemac. The scan used
`--no-suppress --min-confidence low` on the default branch heads of 2026-10-16
(commits in [blind/labels_round5.csv](blind/labels_round5.csv)). The default view has 269 findings.
A seeded sample (20261016, up to 12 per rule) gave 52 findings, labelled by one person
(the author of the tool, which is a bias; a second labeller is still to do) before any fix.

| Rule | n | TP | TH | NP | FP | Strict precision |
|---|---|---|---|---|---|---|
| CA010 | 12 | 5 | 0 | 1 | 6 | 42% |
| CA011 | 2 | 1 | 0 | 0 | 1 | 50% |
| CA012 | 8 | 0 | 4 | 0 | 4 | 50% |
| CA013 | 12 | 0 | 1 | 2 | 9 | 8% |
| CA015 | 12 | 0 | 5 | 2 | 5 | 42% |
| CA020, CA021, CA027, CA028, CA071 | 1, 2, 1, 1, 1 | 0 | 0 | 0 | 6 | 0% |
| **All** | **52** | **6** | **10** | **5** | **31** | **31%** (16/52) |

Strict precision is (TP + TH) / n. Counting true positives only it is 12% (6/52).

**Precision on unseen crates, by round:** 31% in round 1, 27% in round 4 before its fixes, 31% in round 5 after them.
The round 4 fixes lifted the number on the sample they were written against, from 27% to 45%, but
that did not carry over: on new crates it is back at about 31%. The fixes removed the
false-positive causes seen in round 4; round 5 found different ones. Shape of the tool's
problem: most false positives come from the name heuristic, and every set of crates brings new names.

### Why the false positives happen

| n | Cause | Rules | Fixable by name rules? |
|---|---|---|---|
| 14 | not a secret at all: a seed or token *count* in an OpenAI request, a path to a key file, the name of an environment variable, a timestamp, protocol version numbers, a database record key, a QUIC address-validation token, a search engine name, a form field name | CA010, CA011, CA012, CA013, CA015 | yes, more excluded words and a rule that `*_variable`, `*_path`, `*_location` name a place, not a value |
| 5 | derived `PartialEq` on a configuration, task or view record that holds an API key, never compared on attacker input | CA013 | partly: most CA013 false positives are records of this kind |
| 3 | a request or response body that exists to carry the secret to the server or the user | CA012 | yes: skip structs named `*Request` / `*Response` unless the type name is a clear secret |
| 3 | a hash or checksum of public data (a download, a known_hosts entry, an asset file) | CA020, CA021 | partly |
| 2 | a public protocol constant (an HKDF salt) or a deliberately reproducible seed | CA027, CA071 | no |
| 1 | a password and its confirmation compared in a browser form | CA013 | no |
| 1 | a qlog event type that exists to record key material | CA010 | no |
| 1 | a hand-written `Debug` that already redacts with a closure (`.map(|_| "[REDACTED]")`) | CA010 | yes |
| 1 | `self.encdec.encrypt(..)` treated as a nonce because the first argument is a field | CA028 | yes: `encdec`, `encryptor` are not nonces |

### What was found

True positives are all about secrets in types: a `String` access token, the private EC key of a push
subscription, a passkey recovery secret and a Meilisearch export API key, each printed by a derived `Debug`
(CA010), and a 256-bit ChaCha20 key that is `Copy` (CA011) in rust-bitcoin. CA012 and CA015 mostly give
hardening results here: keys that have to be serialised or held in memory, with no sink shown. CA013 is the
weakest rule on this set (8%): it needs a way to tell a secret compared on attacker input from a
record that merely holds one.

### Round 5 fix pass

These changes were written against the round 5 sample, so they cannot be measured on it. They
are checked two ways: no labelled true positive or hardening finding may disappear, and nothing
new may appear. A sixth set of crates is the only honest number.

| Change | Rule(s) | Removes |
|---|---|---|
| `location`, `variable`, `var`, `env`, `field`, `primary`, `phase`, `time`, `timestamp`, `changed`, `created`, `modified`, `updated` name a place, a counter or a time, not a secret | all name-based rules | `api_key_variable`, `PrivateKeyLocation`, `primary_key`, `time_password_changed`, `password_field` |
| Types named `*Paths`, `*Path`, `*Location` hold where a secret is, so they are skipped | CA010, CA011, CA012, CA013, CA015 | the TLS key-file paths struct |
| A type whose last word is `Request`, `Response`, `Args`, `Opts`, `Options`, `Params`, `Payload` or `Form` is a record; its name no longer makes it a secret, and an integer named `seed` in it is dropped | CA010, CA012, CA013, CA015 | `PasswordRequest`-style bodies, the OpenAI `seed` fields |
| A hand-written `Debug` that passes a field through a closure returning a literal (`.map(\|_\| "[REDACTED]")`) does not leak it | CA010 | `AuthResponse` in ente, and the same pattern in firezone and librustzcash |
| Derived `PartialEq` is low confidence unless the type is named like a secret, a leaking field holds bytes, or a field is a `password`, `passphrase` or `secret` | CA013 | the API-key records (meilisearch `Remote`, `EmbedderOptions`, task records) |
| `#[derive(Parser)]`, `Args` and `Subcommand` (clap) are command-line options, not secrets held in memory | CA015 | `CliOpts`, `AddArgs`, `RunOpts` |
| `build.rs` and `xtask/` are skipped like tests (`--include-tests` scans them) | all | a checksum of a public download, an asset-file checksum |
| `encdec`, `encryptor`, `encrypter`, `decryptor`, `cipher`, `aead` are not nonces, also when written `self.encdec` | CA028 | `self.encdec.as_ref()` |

**Checks.**

- Of the 52 labelled round 5 findings, all 16 true-positive and hardening findings are still reported.
  24 of the 36 false-positive and tool-code findings are gone; 28 findings remain, 16 of them correct.
  On this sample that reads 57%, which is what the fixes were written against and not a precision figure.
- Against the previous binary on the 12 round 4 and 12 round 5 crates, 79 findings at medium or high
  confidence disappear (568 to 489) and none appears. Of those 79, 28 were labelled false positive or
  tool code (23 and 5), none was labelled true positive or hardening, and 51 were never labelled. I read the
  51 by name: they are the same causes (redacting closures, request seeds, command-line options, API-key
  records dropped to low). That is one reader and not a labelling, so it is not counted in any number.
- One CA013 true-hardening finding from round 4 (a mail-server account whose `secret: Option<String>` is
  compared with the derived `==`) was lost by the first version of the CA013 change. The rule now keeps
  a `secret`, `password` or `passphrase` string at high confidence.

**Still wrong after the pass** (12 of the 52, the causes the name heuristic cannot see):
a diagnostic qlog event for key material; `seed` and token counts in a fine-tuning job record, which is not a
`*Request`; a schema copy in an upgrade tool; a server-sent TOTP secret in a response type; a password and its
confirmation in a browser form; a `Vec<u32>` of protocol versions in a type named `CredentialHello`; a database
record key buffer; a QUIC address-validation token; a field naming a private-browsing search engine; a
hash of a host name in a `known_hosts` check; a public protocol salt; and a deliberately reproducible seed.

## Blind evaluation, round 6 (new crates, released 0.5.0, after the round 5 fixes)

The round 5 fix pass was written against the round 5 sample, so round 6 is the first
measurement of it. It ran on twelve crates the tool had never seen (atuin, boringtun, chatmail-core,
core-crypto, crates.io, lighthouse, pingora, rbw, rustls, shadowsocks-rust, surrealdb, zebra) with the
released 0.5.0, built from the tag. 805 findings in all, 263 at medium or high confidence. The sample
is 55 findings (seed 20261017; 12 each for CA010, CA013 and CA015, every finding for the other seven
rules). The labeller is one AI agent, not a human. The full report, with the crate table and the
labels, is in [blind/round6_report.md](blind/round6_report.md) and
[blind/labels_round6.csv](blind/labels_round6.csv).

| Rule | n | TP | TH | NP | FP | Strict precision |
|---|---|---|---|---|---|---|
| CA010 | 12 | 2 | 6 | 1 | 3 | 67% |
| CA011 | 3 | 0 | 1 | 0 | 2 | 33% |
| CA012 | 9 | 0 | 0 | 0 | 9 | 0% |
| CA013 | 12 | 0 | 1 | 0 | 11 | 8% |
| CA014 | 3 | 3 | 0 | 0 | 0 | 100% |
| CA015 | 12 | 0 | 4 | 1 | 7 | 33% |
| CA021, CA027, CA028, CA071 | 4 | 0 | 0 | 1 | 3 | 0% |
| **All** | **55** | **5** | **12** | **3** | **35** | **30.9% (17/55)** |

Round 5 was 31% strict and 12% TP-only; round 6 is 30.9% and 9.1%. **The round 5 fix pass shows no
measurable gain on unseen crates.** The samples differ in size, crates and rule mix, so a few points
either way is noise; the honest reading is "no improvement shown". Round 6 also shows what the earlier
rounds hinted at: CA010 and CA014 are usable (67% and 3 of 3), and the three derive rules and CA015
are not (CA012 0 of 9, CA013 1 of 12, CA015 4 of 12).

The 35 false positives, by cause: a public or ordinary value with a secret-sounding name (11);
derived `PartialEq` on a config, database-row or syntax-tree struct that is never compared on attacker
input (8); a field that already holds ciphertext (6); a type whose purpose is to be serialised (4);
an error-message `String` in a variant named after a secret (2); a custom redacting derive that was not
recognised (1); an XML tag name matched as a MAC tag (1); a session id read as a nonce (1); the unused
fallback seed of a deterministic test RNG (1).

Five CA010 rows are real credentials in a derived `Debug` where no print of the struct was found. Round 6
labelled them TH; round 5 labelled the same pattern TP. Under the round 5 convention TP-only would be
18%. Strict precision does not depend on that choice, which is why it is the headline number.

True positives (5): a password in a public SDK credentials struct, and in shadowsocks-rust a config
struct with the password and keys that is printed with `trace!("{:?}")`, a SOCKS5 password logged on a
failed login, a configured password logged on a decoding error, and an accepted password traced.

**A missed bug seen while reading.** shadowsocks-rust compares the stored proxy password with the one the
client sent using `==` (`check_user`, in two files). No rule fired. That is one anecdote, not a recall
estimate, but it is the same class as the totp-rs miss in [recall.md](recall.md): a secret compared with
`==` where nothing is named like a MAC.

No fixes follow from round 6 yet. The report lists ten proposals (for example: CA013 should only fire
on a type that is itself a key or token newtype, or on a real `==` of a secret; CA012 should skip data
transfer types; the plain words `key`, `keys` and `credential` are too generic for CA011 and CA015).
They would be written against this sample, so a seventh round on new crates is needed to measure them.

## New rules after 0.5.0: CA024, CA025, CA062 to CA066

Seven rules were added to the working tree after the 0.5.0 release: broken ciphers and hashes (CA024),
ECB mode (CA025), weak password-hashing work factor (CA062), a fast hash applied to a password (CA063),
TLS certificate validation off (CA064), TLS hostname verification off (CA065) and JWT signature
checking off (CA066). Each has fixtures with a good, a bad and a tricky case (`tests/fixtures/ca0NN`).

**This is a probe, not a blind round.** They were run on the 36 crates already cloned for rounds 4, 5
and 6, and the rules were adjusted after reading what they found, so none of this is a precision
figure. A blind round on new crates must come before any number is quoted. The readings below are one
reader's (Claude), made after looking at the code.

| Rule | Default-view findings on 36 crates | What they were |
|---|---|---|
| CA064 | 11 (8 high, 3 medium) | every one is real "accept any certificate" code, and none looks like a forgotten test switch. Deliberate and documented in 2 (Mullvad domain fronting, where an inner TLS layer carries the security), opt-in or configurable in 6 (a resolver option, an insecure mail client, an explicit `verify = false` in a proxy, an account setting), test or example code in 3 (a QUIC example, a QUIC benchmark, the BoGo TLS test shim) |
| CA065 | 1 (medium) | the same chat client, as an opt-in |
| CA063 | 6 (medium) | six `hasher.update(password)` calls in one remote-desktop client that hashes the connection password with SHA-256 for a challenge. Real, and by design in that protocol, so hardening at best |
| CA024 | 5 (medium) | all five are inside aws-lc-rs, a cryptography library that implements DES and 3DES. False positives of the kind "a library implements the primitive". 24 low-confidence MD5 and SHA-1 uses, hidden by default, are checksums and protocol hashes |
| CA025 | 0 at default view, 4 low | the low ones are a library's mode table and QUIC header protection, which uses single-block AES-ECB on purpose |
| CA062, CA066 | 0 | nothing to report in these crates |

Changes made while probing, each with a fixture: a type alias and the calls through it count as one
finding; a verifier impl is not reported where a named accept-all verifier is already reported in the
same file; OpenSSL `set_verify_hostname(false)` next to `add_host` is a hand check, not a switch-off;
one PBKDF2 round is a derivation step (the Bitwarden login hash), not password hashing; names in
`SCREAMING_CASE` and names containing `legacy` are skipped; `set_verify(NONE)` in only one branch of
an `if` is medium, not high.

**Known limits.** CA024 will flag a cryptography library's own implementation of a legacy cipher.
CA062 only sees a literal or a same-file constant, so a work factor read from configuration is not
checked. CA063 reads names: a password called `pw` or `secret` is missed. CA064 cannot tell a test
helper outside a `tests/` directory from production code.

## Round 6 fix pass, and CA029

Round 6 said the name heuristic is not enough for the three derive rules and CA015, so this pass
changes how they decide instead of adding words. Written against the round 6 sample, so it cannot
be measured on it; round 7 on new crates is the test.

| Change | Rule | Why |
|---|---|---|
| Always low confidence (hidden by default) | CA012 | 4 of 22 reports useful across rounds 5 and 6 (the four were root keys and account secrets); the rest were request bodies, keystore rows and ciphertext. Serialising is what these types are for |
| Fire only on a newtype (one field) or a type named like a clear secret; any other struct is low | CA013 | 11 of 12 round 6 reports were settings, database-row or syntax-tree records compared when they change |
| A field secret only through `key`, `token` or `credential` in a type whose own name says nothing is low, unless it is `[u8; 16/24/32/48/64]`; a neutral field inheriting a weak type name is low | CA011, CA013, CA015 | database keys, lexer tokens, public credentials, a signature hash in a `CacheKey` |
| A local buffer called only `key` is low unless a KDF or an RNG visibly filled it (`fill_bytes(&mut key)`, `expand(.., &mut key)`, `pbkdf2(.., key.as_mut_slice())`) | CA015 | a database row key built from an index, a vector of result indices |
| `#[sensitive]`, `#[redact]`, `#[redacted]`, `#[masked]` on a field hide it; a field whose doc comment says "public" or "non-sensitive" is skipped | CA010 and the derive rules | a custom redacting derive; fields documented as public |
| A tuple variant of an enum named `*Error` holds the message, not the secret | CA010 | `InvalidJwtSecret(String)` |
| `#[cfg(any(test, debug_assertions))]` is test code | all | a key in a test-only constructor |

**Checks.** Against the 0.5.0 binary on the 36 crates cloned for rounds 4, 5 and 6, 208 findings at
medium or high confidence disappear (745 to 537) and none appears. Of the 208, 38 were labelled false
positives, 9 were labelled true hardening, none was labelled a true positive, and 161 were never
labelled. The nine hardening findings lost are four root keys and account secrets serialised (CA012),
a push-subscription record and a mail account compared with the derived `==` (CA013), a post key, a
certificate key, and a WireGuard peer that is `Copy`. That is the price of the change.

On the labelled samples the fixes were written against (so, in-sample, not a precision figure):
round 6, 25 shown of which 16 true or hardening (64%); round 5, 17 shown of which 10 (59%); round 4,
42 shown of which 23 (55%).

**CA029, password compared with `==`.** The shadowsocks-rust miss from round 6. It looks for a function
named like a check (`check_user`, `verify_token`, `authenticate`, `login`, `is_valid`) that returns a
bool, and a parameter named `password`, `token`, `secret` or similar compared with `==` or `!=` against a
value that is not a parameter, a literal or a constant. Two parameters compared with each other
(a confirm-password field) are skipped; a file that already uses `ct_eq` gets low confidence. On the 36
crates it reports 3: the two `check_user` functions in shadowsocks-rust (the bug round 6 found by hand), and a
client in firezone that compares the credentials it is handed with the ones it holds, to see whether they
changed, which is not an attacker's guess. Two of three, in a probe where the rule was written knowing the
first two; not a precision figure.

## Blind evaluation, round 7 (new crates, round 6 fix pass and the new rules)

Round 7 measures the build after the round 6 fix pass, with the new rules CA024, CA025, CA029 and CA062
to CA066, on twelve crates the tool had never seen: actix-web, Rocket, loco, rauthy, reqwest,
mongo-rust-driver, rust-postgres, lettre, bdk, rathole, rustic and trussed. The scanner was a frozen copy
of the working tree (version 0.5.0, 25 rules). 524 findings, 180 at medium or high confidence. The sample
is 49 findings (seed 20261018). The labeller is one AI agent, not a human. The full report is in
[blind/round7_report.md](blind/round7_report.md), the labels in [blind/labels_round7.csv](blind/labels_round7.csv).

| Round | Sampled | Strict precision | TP-only |
|---|---|---|---|
| 5 | 52 | 31% | 12% |
| 6 (released 0.5.0) | 55 | 30.9% | 9.1% |
| 7 (this build) | 49 | **38.8% (19/49)** | **2.0% (1/49)** |

**Reading it honestly.** Strict precision rose by eight points, but with about 50 findings a round that is
inside sampling noise (a 95% interval on 19/49 is roughly 26 to 53%), and all of the gain is hardening:
18 of the 19 positives are TH, none shows a sink. TP-only fell to one finding in 49. One crate dominates:
rauthy gave 123 of the 180 default-view findings and 22 of the 49 sampled rows, so the numbers are close to
"rauthy plus a few others". bdk produced no findings. CA011, CA012 and CA013 produced no default-view findings
at all (111 low-confidence CA012 and 26 low-confidence CA013 stayed hidden), so the fix pass's effect on them
shows as silence, which this sample cannot judge as right or wrong.

| Rule | n | TP | TH | NP | FP | Strict |
|---|---|---|---|---|---|---|
| CA010 | 12 | 0 | 8 | 0 | 4 | 67% |
| CA015 | 12 | 0 | 9 | 0 | 3 | 75% |
| CA014 | 2 | 1 | 0 | 0 | 1 | 50% |
| CA021 | 4 | 0 | 1 | 0 | 3 | 25% |
| CA018 | 3 | 0 | 0 | 0 | 3 | 0% |
| CA024 | 4 | 0 | 0 | 0 | 4 | 0% |
| CA063 | 2 | 0 | 0 | 0 | 2 | 0% |
| CA064 | 8 | 0 | 0 | 1 | 7 | 0% |
| CA071 | 2 | 0 | 0 | 1 | 1 | 0% |
| **All** | **49** | **1** | **18** | **2** | **28** | **38.8%** |

**The new rules found nothing real.** Fourteen default-view findings, none a true positive: CA064 flagged
code that implements an opt-in switch for self-signed certificates in reqwest, the MongoDB driver, lettre
and rauthy (7 of 8; the eighth is a Rocket test client); CA024 flagged a feature-gated 3DES mechanism
inside an embedded key service (4); CA063 flagged the MD5 exchange the Postgres wire protocol requires
(2). CA025, CA029, CA062 and CA066 did not fire, and CA065 gave six low-confidence findings. Silence is the
right answer when a crate has no such code; whether the rules would fire on bad code is a recall question
this round cannot answer. What it does show is that CA064, CA024 and CA063 are noisy on libraries that
implement the thing they are named for, which was the known limit written into their documentation.

The 28 false positives, by cause: TLS verification off inside code that implements an opt-in switch (7);
a field that is not a secret (a duration, a URL, a hash of a one-time password, ciphertext, a CSRF token)
(6); a library implementing the primitive it is named for (6); a public value compared by a `tag` name,
HTTP ETags and replica-set tags (3); `unwrap` on the application's own stored ciphertext (3); intended
output or documented design (2); a `Debug` that already redacts (1).

**The one true positive:** rathole logs the expected `SHA-256(token || nonce)` digest at debug level when
authentication fails. Its comparison of the same digest with `!=` was labelled TH, not TP: the nonce is fresh
per connection, so a timing attack has no stable target. No bug the tool should have caught turned up while
reading about fifty code regions, which is an anecdote and not a recall measurement.

**What round 7 says about the project.** Across rounds 5, 6 and 7 (156 labelled findings) strict precision
is 31%, 31% and 39%, and TP-only 12%, 9% and 2%. Two fix passes written against a sample did not move the
number on the next sample. The rules that keep their value are CA014 (3 of 3, then 1 of 2) and, for
hardening, CA010 and CA015. The rest of the default view is mostly noise on libraries and config structs. The
eight fixes proposed in the report would again be written against this sample.

## Structural fixes after round 7

Round 6 and round 7 showed that fixing names one sample at a time does not carry over. These changes are
about structure instead: what the code is, not what a variable is called. None of them is measured on unseen
crates; the numbers below are on the round 7 crates that the changes were written from.

- **A switch is not a mistake.** CA064 and CA065 are low (hidden by default) when the code is only reached
  because a setting about verification says so: `if config.certs_verification`, `if vars.pg_tls_no_verify`,
  `if let Some(true) = allow_invalid_certificates`, `if skip_hostname_check`. That is a library or an
  application honouring a choice its own caller made (reqwest's `danger_accept_invalid_certs`, the MongoDB
  driver's `tlsAllowInvalidCertificates`, rauthy's `pg_tls_no_verify`). A literal `true` with no such
  condition is still high, and a condition about something else (`url.starts_with(..)`) is still medium. The
  installation of a verifier named like `NoVerifier` used to be high whatever surrounded it; it now follows
  the same grading. A verifier that is only defined in a file, not installed there, is low: the installing
  call is where the choice is made.
- **A library offering the primitive.** CA024 and CA025 are low inside a trait, struct, enum, module or
  `impl` named for the primitive (`trait Tdes`, `impl MechanismImpl for Tdes`, `mod rc4`), in a file named
  for it (`tdes.rs`), and in every file of a crate (nearest `Cargo.toml`) that declares such a type or an enum
  variant (`AlgorithmId::Tdes`, `DesForLegacyUseOnly`). A workspace's application crate is not excused by
  the library next to it. CA063 is low inside a public function named after a hash (`pub fn md5_hash(user,
  password, salt)`), which is how a protocol crate offers the scheme the protocol mandates.
- **Hardening is listed apart.** CA010, CA011, CA012, CA013, CA015 and CA016 describe a weakness that matters
  only if something else goes wrong (a derive that would print the key, a buffer that is not wiped). They
  are now printed under their own heading after the findings, counted separately in the summary, carry
  `"class": "hardening"` in JSON and SARIF, and do not make the exit status 1 unless `--fail-on-hardening`
  is given. This is a change in behaviour for anyone who gated CI on the old default.
- **`testbench` directories** are skipped like `tests`.

**What it does on the round 7 crates.** Scanning the eight crates that held round 7's false positives with
the old and new build: 18 findings drop to low (CA064 7, CA024 9, CA063 2), none rises and none appears. Of
the 13 that were in the round 7 sample, all 13 had been labelled false positives (7 CA064, 4 CA024, 2
CA063); the other 5 are aws-lc-rs, a library implementing DES that I read but nobody else labelled. The
Rocket test client was labelled NP and is covered by the new `testbench` rule, which was tested on a fixture
and not on Rocket itself. So all 14 default-view findings that the new rules produced in round 7 would no
longer show. That is by construction: the changes were written after reading those findings, so it says
nothing about how the rules behave on a crate not yet seen.

**What it costs.** An application that really does ship an `--insecure` flag, wired to
`danger_accept_invalid_certs(insecure)`, used to be medium and is now low, because the code cannot be told
apart from a library offering the same flag. A crate that declares an `Md5` type is excused from CA024
everywhere, including an unrelated misuse in the same crate. Both are false negatives by design, to be
checked in the next blind round.

## Blind evaluation, round 8 (new crates, after the structural fixes)

Twelve crates nobody had looked at, chosen before any scan, scanned with a frozen build of the committed tree
(`55c1d2a`, 25 rules). Two of the twelve (oauth2-rs and openidconnect-rs) returned 404 on clone and were
replaced, before scanning, by the reserves sozu and x25519-dalek. The crates are yubikey.rs, ureq, hudsucker,
warpgate, alloy, nostr, fedimint, iroh, lemmy, realworld-axum-sqlx, sozu and x25519-dalek. 1,015 findings,
211 in the default view (25 findings, 186 hardening). hudsucker had none. Seeded sample (seed 20261019),
at most 12 rows per rule and, new this round, at most 4 per crate per rule: 57 rows, labelled by one AI agent
(report: [blind/round8_report.md](blind/round8_report.md), labels:
[blind/labels_round8.csv](blind/labels_round8.csv)). The numbers below were recomputed from the CSV.

| Slice | n | TP | TH | NP | FP | Strict | TP-only |
|---|---|---|---|---|---|---|---|
| Findings (every rule except CA010-CA013, CA015, CA016) | 24 | 7 | 3 | 1 | 13 | 41.7% (10/24) | 29.2% (7/24) |
| Hardening (CA010-CA013, CA015, CA016) | 33 | 1 | 22 | 0 | 10 | 69.7% (23/33) | 3.0% (1/33) |
| **All** | **57** | **8** | **25** | **1** | **23** | **57.9% (33/57)** | **14.0% (8/57)** |

**Read the overall figure with care.** 57.9% looks like a jump from 38.8%, but it is mostly a change in the
mix of rows, not in the tool. Strict precision depends heavily on how many rows are hardening, and hardening
rows count as positives when the type really holds a secret (all 12 CA015 rows were TH). Split the same way,
round 7 was 71% for hardening (17/24, no TP) and 8% for findings (2/25, one TP). So hardening is flat
(70% then 70%), and the finding class is the one that moved (8% then 42%), on 24 rows from different crates.
The intervals are wide and one cluster matters: 4 of the 7 finding-class true positives are one vendored
library (warpgate's sspi Kerberos code, which logs the new password and Kerberos keys at trace level).
Counting that cluster once, the finding class has four distinct true positives in 21 rows. Warpgate also
supplies 26 of the 57 rows (46%), 14 of them from its vendored third-party code, so the cap of four rows per
crate per rule did not stop one crate from dominating.

**What the tool found that was real (8 rows, 5 distinct problems):**
- sspi's trace-level logging of the new password and Kerberos keys (CA014, 4 rows, vendored in warpgate).
- nostr compares a NIP-44 HMAC with `!=` (CA021).
- sozu stores Basic-auth credentials as an unsalted `sha256(password)` (CA063).
- lemmy installs an accept-any-certificate verifier on every TLS database connection, with no option to turn
  verification on (CA064).
- iroh's relay prints its configuration with `{:#?}`, which reaches bearer tokens held by a sibling type
  (CA010; the tool flagged the config enum, not the type that is printed).

CA063 and CA064 were added after 0.5.0, and these are their first real hits in a blind round (round 7 had one
true positive in 49 rows, and none from the new rules).

**By rule:** CA014 4/4 (all one cluster), CA015 12/12 TH, CA010 6/12 (1 TP, 5 TH), CA013 4/8, CA021 2/10, CA063
1/4, CA064 2/3, CA029 1/1, CA062 0/1 (NP), CA066 0/1. CA021 is the noisiest rule: 8 of 10 were false
positives, 4 of them public `tags` (nostr and sozu), the same cause as in round 7 and still not fixed.

**False positives (23):** not a secret or a MAC by meaning (17: public keys, a database key, signed
transactions, `tag` fields, public digests); a hand-written `Debug` that already prints `[redacted]` (1); a
protocol that mandates the construct (4: the MySQL `caching_sha2_password` scramble, vendored CredSSP); a
guard the tool does not see (1, an HMAC rejected before `Validation::new(header.alg)`).

**Did the structural fixes carry over?** Partly, and one cost showed up.
- **Verification switches gated by a setting (CA064, CA065): carried over.** It applied correctly to ureq's
  `disable_verification`, to warpgate's `tls.verify` and `accept_invalid_*` parameters, and to test-only
  verifiers in iroh and sozu. **One real cost:** warpgate's RDP target option `verify_tls` defaults to off, so
  RDP server certificates are not verified by default. It is documented, and CredSSP binds the server key
  separately, but my gate demoted it to low. This is the false negative the change was documented to risk.
  lemmy's `sslmode=require` condition stayed medium, and the real finding there was high.
- **Libraries offering the primitive (CA024, CA025): carried over.** CA024 had four false positives in
  round 7 and no default-view findings in round 8; all 55 low ones are libraries or protocol code. CA025 never
  fired, so it was not tested.
- **Public function named after the hash (CA063): not demonstrated.** No `md5_hash`-style function occurred,
  and a near-miss showed the limit: warpgate's `pub fn compute_sha2_auth_challenge_response` (the MySQL scramble)
  stayed medium and gave three false positives, because `sha2` is not in the list of hash names, while its
  SHA-1 sibling in the same file went low.
- The agent read all 74 low CA024, CA063, CA064 and CA065 findings and found none that looked like real
  misuse in application code, apart from the warpgate RDP case above.

**Missed by the tool (anecdote, not a recall measurement):** warpgate RDP verifies no certificate by default
(above); fedimint's gateway migration hashes the gateway password as one salted SHA-256 (historical code, CA063
did not fire); iroh's `examples/auth-hook.rs:343` compares a bearer token with `==` (example code; CA029 needs a
function named like a check); nostr NIP-04 is AES-CBC with no MAC (it is the specification, and no rule covers it).

**What round 8 says.** The default view held more real findings than in round 7 (one true positive in 49 rows):
five distinct real problems in 57 rows, though on different crates and a different sampling cap. Two things are still wrong. Hardening is flat at about 70% strict with almost no
TP, which is what hardening should look like. And the finding class is still noisy (CA021 2 of 10, CA063 1 of
4), dominated by the same causes as before. The six suggestions in the report (skip `tag` and public-key
names, recognise `[redacted]`, widen the CA063 hash list, and so on) are untested and would again be written
against this sample.

## After 0.6.0: CA021 and CA063

Round 8 found CA021 right 2 times in 10, with the same causes as round 7 (3 of 4 then, 4 of 8 now were public
`tags`). Two small structural changes, made after reading those rows, so they are in-sample:

- **CA021 no longer treats a plural `tags` as evidence of a MAC.** A MAC is one value; `tags` is a list of
  labels (routing tags, replica-set tags, HTML tags). And when both sides carry the same generic name
  (`a.tag == b.tag`, `a.material_digest == b.material_digest`) the comparison is two values of one kind being
  checked for equality, not a presented tag against a computed one: low instead of medium. `tag` against
  `received_tag` stays medium, and any comparison with a `.finalize()` or `.digest()` result is unchanged.
- **CA063's "public function named after the hash" now counts the family** (`sha`, `sha1`, `sha2`, `sha3`,
  `md2`, `blake2`, `ripemd`), so `compute_sha2_auth_response` is low like its SHA-1 sibling.

On the round 8 crates, old build against new: 8 findings change and nothing appears or rises. Three CA021 findings
disappear (nostr's event-tag comparison, two sozu routing-tag comparisons), two drop to low (sozu's certificate
digest, yubikey's TLV `tag`), and three CA063 drop to low (warpgate's MySQL scramble). All 8 had been labelled
false positives in round 8. The CA021 true positive (nostr's NIP-44 HMAC) and true-but-hardening row are
unchanged. Three CA021 false positives remain, all in warpgate's vendored picky code (public digests compared
with a digest of public content). A change written against the rows it removes says nothing about new crates;
round 9 is the test.

## Second labeller on round 5

A second, independent labeller labelled the same 52 round 5 findings without seeing the first labels
(an AI agent, not a human; the file is [blind/labels_round5_second.csv](blind/labels_round5_second.csv)).
Rahul has not labelled yet; a human second opinion is still open.

| First \ second | TP | TH | NP | FP |
|---|---|---|---|---|
| TP | 0 | 6 | 0 | 0 |
| TH | 0 | 6 | 1 | 3 |
| NP | 0 | 0 | 3 | 2 |
| FP | 0 | 1 | 0 | 30 |

- **Exact agreement on the four labels: 39 of 52 (75%), Cohen's kappa 0.54.**
- **Agreement on "counts toward strict precision" (TP or TH) against "does not" (NP or FP): 47 of 52
  (90%), kappa 0.76.** Strict precision was 31% (16/52) by the first labeller and 25% (13/52) by the second.
- **TP versus TH is not stable.** The second labeller gave no TP at all: it would only call a finding a
  true positive if it saw a secret reach a sink, and for each of the first labeller's six TPs (secrets
  in a derived `Debug`) it saw no print. TP-only was 12% against 0%. This is the same boundary that moved
  between round 5 and round 6, so TP-only should not be quoted without saying so.
- The five disagreements on strict precision: two root keys that are serialised only for an encrypted
  pickle (TH against FP), a TOTP secret in a response type (FP against TH), a stored record with a derived
  `==` that is never compared on input (TH against FP), and a TOTP secret in a command-line model (TH
  against NP).

The headline, strict precision, holds up under a second reader (31% against 25%); the TP-only figure does not.

## Caveat

Precision here is measured on repositories that were chosen because they are
expected to be quiet, and the rules were tuned against them: 9 of the false
positives above were found and fixed this way. The numbers show the rules do not
fire on well-written code; they are not an estimate of precision on arbitrary
crates. The blind evaluation above did that: strict precision in the default view is 31% in round 1 and 27% in round 4, before the fixes of each round.
