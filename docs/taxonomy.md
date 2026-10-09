# Rust Cryptographic Misuse Taxonomy

Companion artifact to `cargo-cryptaudit`.
Team: Shubham Chhatbar, Rahul Paul

---

## How to read this document

Every pattern carries five fields:

| Field | Meaning |
|---|---|
| **Tier** | Build cost. A = pure `syn` AST match (hours). B = local dataflow / heuristics (days). C = manifest & dependency graph. D = needs type resolution (`dylint`/rustc). E = catalogued, deliberately not implemented. |
| **Surface** | Where the evidence lives: `AST`, `Manifest`, `Types`, `Runtime`. |
| **Rust-specific** | `yes` = arises from Rust's ownership model, trait system, derive macros, async runtime, or compiler behaviour, and has no Java analogue. These are the project's research contribution. `no` = shared with CryptoGuard/CogniCrypt's rule sets, but usually *cheaper* to detect in Rust because RustCrypto's API paths are stable. |
| **Sev** | Impact if exploited. |
| **Conf** | How confident a positive is. Drives default CLI filtering — see "Severity × Confidence" at the end. |

**Tier is build cost, not importance.** Several of the highest-value Rust-specific patterns are Tier A precisely because derive macros and ownership moves are syntactically visible. That is a lucky break, not a coincidence to skip past.

**Status** marks what ships in the semester MVP: `MVP` · `v2` · `stretch` · `catalogued`.

---

## Master index

### Tier A — AST-detectable, no type information required

| ID | Pattern | Rust-specific | Sev | Conf | Status |
|---|---|---|---|---|---|
| CA010 | `#[derive(Debug)]` on secret-holding struct | yes | High | High | MVP |
| CA011 | `#[derive(Clone, Copy)]` on secret type | yes | Med | High | MVP |
| CA012 | `#[derive(Serialize, Deserialize)]` on secret type | yes | High | High | MVP |
| CA013 | `#[derive(PartialEq)]` on secret type | yes | Med | Med | MVP |
| CA014 | Secret passed to `println!`/`format!`/`tracing`/`log` | yes | High | Med | MVP |
| CA015 | Secret struct missing `Zeroize`/`ZeroizeOnDrop` | yes | Med | Med | MVP |
| CA016 | Manual zeroing without `zeroize` (optimiser-elided) | yes | Med | High | MVP |
| CA017 | `mem::forget` / `Box::leak` / `ManuallyDrop` on secret | yes | Med | High | v2 |
| CA018 | `.unwrap()`/`.expect()` on crypto `Result` | yes | Med | High | MVP |
| CA019 | Verification result discarded (`let _ =`, `if let Ok(_)`) | yes | High | High | MVP |
| CA020 | `assert_eq!` on MAC/tag | yes | Med | High | MVP |
| CA021 | `==` on `.finalize()`/`.tag()`/digest output | no | High | High | MVP |
| CA022 | Raw stream cipher used without AEAD | no | High | Med | MVP |
| CA023 | Non-CSPRNG for key/nonce generation | no | High | High | MVP |
| CA024 | Weak primitive constructed (MD5, SHA-1, DES, RC4) | no | High | Med | MVP |
| CA025 | ECB mode on multi-block data | no | High | Med | MVP |
| CA026 | `static`/`OnceLock`/`lazy_static` holding key material | yes | Med | Med | v2 |
| CA027 | Hardcoded key/IV literal reaching a crypto constructor | no | High | Med | MVP |
| CA028 | Nonce reuse, intra-function | no | Crit | Med | MVP |
| CA060 | Password used directly as key (no KDF) | no | High | Med | v2 |
| CA061 | Missing, static, or reused salt | no | High | High | v2 |
| CA062 | Weak KDF work factor (PBKDF2 iters, Argon2 params) | no | Med | High | v2 |
| CA063 | Fast hash (SHA-256) for password storage | no | High | Med | v2 |
| CA064 | TLS certificate validation disabled | no | Crit | High | MVP |
| CA065 | Hostname verification disabled / permissive verifier | no | Crit | High | MVP |
| CA066 | JWT `alg: none` or attacker-controlled algorithm | no | Crit | Med | v2 |
| CA067 | Raw hash used as MAC (length-extension) | no | High | Med | v2 |
| CA068 | CBC mode without accompanying MAC | no | High | Med | v2 |
| CA069 | Hardcoded password/credential literal | no | High | Med | MVP |
| CA071 | Fixed or predictable RNG seed | no | Crit | High | MVP |
| CA072 | RNG seeded from system time | no | Crit | High | MVP |
| CA074 | Decryption/verification error message leaks cause | no | Med | Low | v2 |
| CA078 | Predictable nonce (sequential from zero, counter from input) | no | Crit | Med | v2 |
| CA079 | Fixed/hardcoded IV for CBC | no | High | High | MVP |

### Tier B — local dataflow or curated heuristics

| ID | Pattern | Rust-specific | Sev | Conf | Status |
|---|---|---|---|---|---|
| CA030 | Secrets in `Vec<u8>`/`String` rather than fixed-size zeroizing types | yes | Med | Low | v2 |
| CA031 | `unsafe` block touching a secret buffer | yes | Med | Low | v2 |
| CA032 | Key copy proliferation (`.clone()`, `.to_vec()` on secrets) | yes | Med | Low | v2 |
| CA033 | AAD omitted where context binding is required | no | High | Low | stretch |
| CA034 | FFI boundary (`extern "C"`, `#[no_mangle]`) carrying secrets | yes | Med | Med | stretch |
| CA035 | Shared nonce counter across threads without atomics | yes | Crit | Low | v2 |
| CA070 | Key length below algorithm requirement | no | High | Med | stretch |
| CA073 | Home-rolled crypto instead of vetted primitives | no | High | Low | catalogued |
| CA075 | Branching on secret data | no | Med | Low | stretch |
| CA076 | Same key reused across purposes (encrypt + MAC/sign) | no | High | Low | stretch |
| CA077 | MAC-then-encrypt ordering | no | High | Low | stretch |

### Tier C — manifest and dependency graph

A second analysis surface. Cheap to build, and no existing Rust tool does crypto-aware manifest analysis.

| ID | Pattern | Rust-specific | Sev | Conf | Status |
|---|---|---|---|---|---|
| CA040 | Feature flags disabling constant-time backends | yes | High | Med | MVP |
| CA041 | Raw cipher crate in deps with no AEAD crate present | yes | Med | Med | MVP |
| CA042 | Incompatible major versions of RustCrypto trait crates | yes | Low | High | v2 |
| CA043 | Crypto crate version with a RustSec advisory | no | High | High | MVP (delegate to `cargo-audit`) |
| CA044 | Unmaintained/abandoned crypto crate in tree | no | Med | High | v2 |
| CA080 | Secrets in committed config files / `.env` | no | High | Med | v2 |

### Tier D — requires type resolution (`dylint` stretch)

| ID | Pattern | Rust-specific | Why deferred |
|---|---|---|---|
| CA050 | Generic `impl Cipher` bound without AEAD guarantee | yes | Needs trait resolution to know what the bound guarantees |
| CA051 | Interprocedural nonce flow | no | Needs whole-program dataflow |
| CA052 | Key length silently truncated by `from_slice` | no | Needs const evaluation |

### Tier E — catalogued, deliberately not implemented

Documenting why a pattern is *not* detectable is part of the contribution.

| ID | Pattern | Why not |
|---|---|---|
| CA090 | Timing leaks across `.await` points | Scheduler-dependent; no tractable static formulation |
| CA091 | Secrets paged to disk (no `mlock`) | OS/runtime property, not visible in source |
| CA092 | Trait default impl silently insecure | Library-side defect; reduces to CA021 applied inside default method bodies |
| CA093 | `RUSTFLAGS`/profile hazards | Lives in the build environment, not the scanned source |
| CA094 | Deprecated TLS versions permitted | Usually runtime/config, not source-visible in Rust TLS stacks |

---

## Detailed entries — Tier A

### CA010 — `#[derive(Debug)]` on a secret-holding struct
**Tier** A · **AST** · **Rust-specific: yes** · Sev High · Conf High

```rust
#[derive(Debug)]              // compiler generates a Debug impl over every field
struct Session { key: [u8; 32], id: u64 }

tracing::info!("session: {:?}", session);   // raw key bytes land in the log
```

The derive macro is applied reflexively by most Rust developers. Nothing in the logging call looks dangerous — the leak was introduced by an attribute on a different line, often in a different file.

**Fix:** implement `Debug` manually and redact, or wrap the field in `secrecy::Secret<T>`, whose `Debug` prints `[REDACTED]`.

```rust
impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session").field("key", &"[redacted]").field("id", &self.id).finish()
    }
}
```

**Why existing tools miss it:** Java has no derive macros. CogniCrypt has no rule shape that can express "an attribute silently synthesises a method that reads a secret field."

---

### CA011 — `#[derive(Clone, Copy)]` on a secret type
**Tier** A · **AST** · **Rust-specific: yes** · Sev Med · Conf High

`Copy` makes every assignment and every by-value function call an implicit duplication of key material. Zeroizing one owner leaves every other copy resident in memory. Worse, `Copy` types cannot implement `Drop` at all, so `ZeroizeOnDrop` is structurally impossible on them — the compiler forbids the fix.

**Fix:** never derive `Copy` on secrets. Derive `Clone` only when genuinely required, and pair with `ZeroizeOnDrop`.

---

### CA012 — `#[derive(Serialize, Deserialize)]` on a secret type
**Tier** A · **AST** · **Rust-specific: yes** · Sev High · Conf High

```rust
#[derive(Serialize)]
struct Config { api_key: String, secret_key: [u8; 32] }
```

One `serde_json::to_string(&config)` writes the key into a log line, a metrics payload, an error response, or a cache entry. Same mechanism as CA010, wider blast radius — serialised output routinely crosses a network boundary.

**Fix:** `#[serde(skip)]` on secret fields, or a newtype with a redacting `Serialize` impl.

---

### CA013 — `#[derive(PartialEq)]` on a secret type
**Tier** A · **AST** · **Rust-specific: yes** · Sev Med · Conf Med

The derived `==` compares field-by-field with early exit. Any comparison of the type is now a timing oracle, and the call site looks completely ordinary.

**Fix:** implement `subtle::ConstantTimeEq`, and do not derive `PartialEq` on key/tag types.

---

### CA014 — Secret reaching a logging or formatting macro
**Tier** A · **AST** · **Rust-specific: yes** · Sev High · Conf Med

Covers `println!`, `eprintln!`, `format!`, `panic!`, `tracing::*`, `log::*`, and `.expect("... {key}")`. CA010 catches the derive; this catches explicit `{:?}`/`{}` of a secret ident even where no derive is involved.

**Detection:** token-scan macro arguments for idents in the secret set.

---

### CA015 — Secret struct missing `Zeroize`/`ZeroizeOnDrop`
**Tier** A · **AST** · **Rust-specific: yes** · Sev Med · Conf Med

Rust's ownership model moves a key through many owners — function arguments, struct fields, closure captures, `Vec` elements. Each drop point without zeroization leaves bytes behind.

**Detection:** struct has a field whose type path is a known key type (`Key`, `SecretKey`, `Nonce`) or whose name matches `key|secret|seed|password|token`, and the struct has no `Zeroize`/`ZeroizeOnDrop` derive and no manual `Drop`.

**Known weakness:** the name heuristic is the FP source. Document it; do not hide it.

---

### CA016 — Manual zeroing without `zeroize`
**Tier** A · **AST** · **Rust-specific: yes** · Sev Med · Conf High

```rust
let mut key = derive_key(pw);
use_key(&key);
key.fill(0);          // LLVM may delete this entirely
```

The buffer is dead after the write, so the store is dead, so the optimiser removes it. The developer sees defensive code; the binary contains none. This is precisely why `zeroize` uses `write_volatile` plus a compiler fence.

**Fix:** `use zeroize::Zeroize; key.zeroize();`

**Why existing tools miss it:** the defect is introduced by the compiler backend, not the source. No Java tool models this because the JVM does not present the same hazard.

---

### CA018 — `.unwrap()`/`.expect()` on a crypto `Result`
**Tier** A · **AST** · **Rust-specific: yes** · Sev Med · Conf High

```rust
let pt = cipher.decrypt(nonce, ct).unwrap();   // tampered ciphertext -> panic
```

An authentication failure is an *expected* condition — it is the AEAD working correctly. Converting it to a panic hands an attacker a remote DoS by submitting garbage ciphertext. `unwrap()` is the path of least resistance in Rust, which is why this is endemic.

---

### CA019 — Verification result discarded
**Tier** A · **AST** · **Rust-specific: yes** · Sev High · Conf High

```rust
let _ = mac.verify(tag);                 // failure silently ignored
if let Ok(_) = sig.verify(msg, &pk) { }  // Err arm falls through
```

The check is present in the source and absent in effect. Reads as verified code during review — this is the rule most likely to find something real in a downstream crate.

---

### CA020 — `assert_eq!` on a MAC or tag
**Tier** A · **AST** · **Rust-specific: yes** · Sev Med · Conf High

Two defects at once: non-constant-time comparison, and a panic message that prints both the expected and actual tag.

---

### CA021 — `==` on digest or MAC output
**Tier** A · **AST** · **Rust-specific: no** · Sev High · Conf High

```rust
if computed.finalize().as_slice() == expected { ... }
```

Byte-by-byte with early exit. An attacker measuring response latency recovers the tag one byte at a time.

**Fix:** `subtle::ConstantTimeEq::ct_eq`, or the crate's own `verify_slice`.

---

### CA022 — Raw stream cipher without AEAD
**Tier** A · **AST** · **Rust-specific: no** (but the *shape* is: RustCrypto splits cipher-only and AEAD into separate crates, so this is a one-line import mistake) · Sev High · Conf Med

```rust
use chacha20::ChaCha20;        // confidentiality only
cipher.apply_keystream(&mut buf);
```

No integrity. Ciphertext is malleable — flipping a bit flips the corresponding plaintext bit.

**Fix:** `chacha20poly1305::ChaCha20Poly1305`.

**FP source:** hand-rolled encrypt-then-MAC. Flag with Medium confidence and discuss in the evaluation.

---

### CA023 — Non-CSPRNG for key or nonce generation
**Tier** A · **AST** · **Rust-specific: no** · Sev High · Conf High

Flags `thread_rng`, `SmallRng`, `StdRng::seed_from_u64`, `rand::random()` at key/nonce generation sites where `OsRng` is the convention. `SmallRng` is explicitly documented as not cryptographically secure.

---

### CA027 — Hardcoded key or IV literal
**Tier** A · **AST** · **Rust-specific: no** · Sev High · Conf Med

```rust
let key = [0u8; 32];
let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
```

**Detection:** byte-array or byte-string literal bound to a local that reaches `Key::from_slice`, `Nonce::from_slice`, `new_from_slice`, or `::new`, within one function body.

**FP source:** test fixtures legitimately hardcode keys. Suppress under `#[cfg(test)]`, `tests/`, `benches/`, `examples/` — and report the suppression rate, since a "test" key shipped in a release binary is itself a finding.

---

### CA028 — Nonce reuse, intra-function
**Tier** A · **AST** · **Rust-specific: no** · Sev **Critical** · Conf Med

```rust
let nonce = Nonce::from_slice(b"unique nonce");
let c1 = cipher.encrypt(nonce, m1.as_ref())?;
let c2 = cipher.encrypt(nonce, m2.as_ref())?;   // same key, same nonce
```

ChaCha20 derives its keystream from `(key, nonce, counter)`. Identical key and nonce yield an identical keystream, so `c1 XOR c2 == m1 XOR m2` — the keystream cancels and both plaintexts are recoverable. Root cause of the PS3 signing-key disclosure (2010) and multiple TLS session breaks.

**Detection:** a nonce-typed local reaching two or more `.encrypt()` calls with no intervening reassignment, or bound from a literal, a `const`, or `SystemTime::now`/`Instant::now`.

**The timestamp objection.** "Use a timestamp as the nonce" fails in four documented ways: two nodes in a distributed system collide at the same tick; nanosecond granularity still collides under throughput because OS timer resolution is coarser than the request rate; timestamps are sequential and therefore predictable where freshness is required; and concurrent threads can read the same instant (see CA035). This is the motivating example for the entire project.

**Fix:** a CSPRNG-generated nonce per message, or a strictly monotonic counter with atomic increment and rekeying before wrap.

---

### CA064 / CA065 — TLS certificate and hostname validation disabled
**Tier** A · **AST** · **Rust-specific: no** · Sev **Critical** · Conf High

```rust
reqwest::Client::builder().danger_accept_invalid_certs(true).build()?;
```

Also: a `rustls::client::ServerCertVerifier` impl whose `verify_server_cert` returns `Ok(..)` unconditionally. Both are trivially matchable and both reduce TLS to unauthenticated encryption. Frequently introduced to unblock local development and never removed.

Semgrep's `p/rust` ruleset covers the `reqwest` case (`reqwest-accept-invalid`) — cite that as partial prior coverage and as a baseline datapoint.

---

### CA071 / CA072 — Fixed or time-seeded RNG
**Tier** A · **AST** · **Rust-specific: no** · Sev **Critical** · Conf High

`StdRng::seed_from_u64(42)`, or seeding from `SystemTime::now()`. Time-seeded generators have a search space of seconds — brute-forceable in moments given an approximate window.

---

### CA079 — Fixed IV for CBC
**Tier** A · **AST** · **Rust-specific: no** · Sev High · Conf High

A constant IV makes CBC deterministic: identical plaintext prefixes produce identical ciphertext prefixes, leaking equality across messages.

---

## Detailed entries — selected Tier B and C

### CA035 — Shared nonce counter without atomics
**Tier** B · **AST + heuristics** · **Rust-specific: yes** · Sev Critical · Conf Low

```rust
static mut COUNTER: u64 = 0;                 // or a plain u64 behind Arc
```

Two tasks read the same value before either increments. This is the Rust-idiomatic form of nonce reuse and the direct rebuttal to "just use a timestamp" — concurrency defeats timestamp uniqueness regardless of clock resolution.

**Detection (narrow shapes only):** `static mut` counters used at nonce construction sites; a non-atomic integer field in a struct held behind `Arc` without `Mutex`/`RwLock`. The general case needs interprocedural concurrency analysis and is out of scope.

---

### CA040 — Feature flags disabling constant-time backends
**Tier** C · **Manifest** · **Rust-specific: yes** · Sev High · Conf Med

Several RustCrypto and dalek crates select an implementation backend by Cargo feature or target feature. A downstream manifest can silently fall back to a portable software path with different timing characteristics — **with no change to any line of source code.** No AST analysis can see this.

**Detection:** curated table of `(crate, feature, hazard)`, checked against the resolved feature set from `cargo metadata`.

This is the strongest argument for the tool having a manifest analysis surface at all, and it has no Java analogue — Java has no equivalent of conditional compilation selecting a cryptographic backend.

---

### CA041 — Raw cipher crate present, no AEAD crate
**Tier** C · **Manifest** · **Rust-specific: yes** · Sev Med · Conf Med

The dependency-graph counterpart to CA022. Catches the mistake at the `Cargo.toml` level before any code is written.

---

## Contribution summary

Of the ~55 patterns catalogued, **21 are Rust-specific** — they arise from derive macros, the ownership model, the trait system, the async runtime, conditional compilation, or LLVM's treatment of dead stores. None can be expressed in CryptoGuard's or CogniCrypt's rule languages, because the language constructs that create them do not exist in Java.

The clearest examples, and the ones to lead with:

1. **CA016** — zeroization removed by the optimiser. The defect is introduced by the compiler backend after the source is written and correct.
2. **CA010 / CA012** — a derive macro silently synthesises a method that reads secret fields. Attribute-induced leak, no call site looks wrong.
3. **CA040** — a Cargo feature flag changes the constant-time properties of the binary with zero source diff.
4. **CA011** — `Copy` on a secret makes `ZeroizeOnDrop` structurally impossible; the compiler rejects the fix.

The remaining ~34 are shared with prior Java work but are, in most cases, *cheaper* to detect in Rust: RustCrypto's API paths are stable and explicit, where Java's `Cipher.getInstance("AES/ECB/PKCS5Padding")` hides the mode inside a runtime string that demands string-constant propagation to recover.

---

## Severity × Confidence

Findings carry both axes. The tool defaults to `--min-confidence medium`.

| | Low conf | Med conf | High conf |
|---|---|---|---|
| **Critical** | report, flag for review | report | report, fail CI |
| **High** | suppress by default | report | report, fail CI |
| **Medium** | suppress by default | report | report |
| **Low** | suppress | suppress by default | report |

Rationale: CA027 (hardcoded key) is high-severity but medium-confidence — test fixtures legitimately hardcode keys. CA010 (`derive(Debug)`) is high-confidence — the derive is either present or it is not. Collapsing both onto one axis produces a noisy first run, and first run is the only one most users grant a new tool.

---

## Sources

- Rahaman et al., *CryptoGuard: High Precision Detection of Cryptographic Vulnerabilities in Massive-sized Java Projects*, ACM CCS 2019.
- Krüger et al., *CogniCrypt: Supporting Developers in Using Cryptography*, ASE 2017.
- Egele et al., *An Empirical Study of Cryptographic Misuse in Android Applications*, ACM CCS 2013.
- Ami et al., *Mutation-based Evaluation of Cryptographic API Misuse Detectors* (MASC), arXiv:2107.07065.
- *An Empirical Security Evaluation of LLM-Generated Cryptographic Rust Code*, arXiv:2604.27001, EASE 2026 — the only prior Rust-specific crypto analyzer; unreleased, evaluated on LLM-generated samples rather than real crates.
- RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols.
- `zeroize` crate documentation — rationale for volatile writes and compiler fences.
- RustSec Advisory Database.
