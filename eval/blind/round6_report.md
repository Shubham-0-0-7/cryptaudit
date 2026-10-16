# Blind evaluation, round 6

Round 6 measures the round 5 fix pass on crates the tool has never seen. The scanner
is the released v0.5.0 (built from `git archive v0.5.0`, reports `cargo-cryptaudit 0.5.0`).
The rows are in [labels_round6.csv](labels_round6.csv).

## How to read these numbers

- The labeller is one AI agent (Claude), not a human. No second labeller checked the
  labels, so the label boundaries (especially TP versus TH) are one agent's judgement.
- The sample is seeded (seed 20261017) and stratified by rule: up to 12 default-view
  findings per rule, sorted by (repo, path, line) before `random.sample`.
- Precision is therefore measured per rule on at most 12 findings each. Six of the ten
  rules that fired have 1 to 3 findings in total, so their percentages say very little.
- Every row was labelled by reading the code around the finding, not the tool's message.
- Scan command: `cargo-cryptaudit cryptaudit <dir> --format json --min-confidence low
  --fail-on critical`, default scope (tests, benches, examples, xtask and build.rs not
  scanned). "Default view" means confidence medium or high.
- Labels: TP real problem; TH true but hardening only; NP true pattern in test, example,
  tool or CLI-dev code; FP the claim is wrong. Strict precision = (TP+TH)/n.
  TP-only = TP/n.

## The 12 crates

| Crate | Kind | Commit | Rust lines | Findings (all) | Default view |
|---|---|---|---|---|---|
| atuin | shell history sync, e2e encryption | 10b1141 | 207,017 | 75 | 3 |
| boringtun | WireGuard VPN | 6dcc889 | 7,965 | 11 | 11 |
| chatmail-core | messenger (Delta Chat core) | dce6438 | 119,784 | 71 | 29 |
| core-crypto | messenger crypto (Wire) | b6806ae | 56,958 | 77 | 48 |
| crates.io | registry, auth and token server | 26c169c | 81,944 | 42 | 6 |
| lighthouse | Ethereum consensus client | 6db6ae9 | 352,529 | 91 | 29 |
| pingora | proxy / TLS | 4487f7b | 112,185 | 40 | 4 |
| rbw | password manager CLI | 77464d4 | 19,063 | 74 | 39 |
| rustls | TLS library | bb2165f | 84,767 | 20 | 6 |
| shadowsocks-rust | proxy | a1bb242 | 103,126 | 45 | 33 |
| surrealdb | database | 18971ff | 502,528 | 196 | 31 |
| zebra | Zcash node | 6ef98aa | 252,666 | 63 | 24 |
| Total | | | | 805 | 263 |

Default-view findings by rule (the sampling frame): CA010 95, CA015 112, CA013 37,
CA012 9, CA011 3, CA014 3, CA021 1, CA027 1, CA028 1, CA071 1. The sample is 55 findings:
12 each for CA010, CA013, CA015, and every finding for the other seven rules (CA011, CA012, CA014, CA021, CA027, CA028, CA071).
Sampled per crate: core-crypto 13, lighthouse 8, shadowsocks-rust 8, rbw 7, surrealdb 5,
zebra 5, chatmail-core 4, one each for atuin, boringtun, crates.io, pingora, rustls.

Note on crate choice: pingora and rustls are TLS-facing but are not pure primitive
libraries. Two scans exited 1 under `--fail-on critical` (core-crypto, surrealdb); that
is the tool's exit code, not an error.

## Per-rule results

| Rule | n | TP | TH | NP | FP | Strict precision | TP-only |
|---|---|---|---|---|---|---|---|
| CA010 derived Debug prints secret | 12 | 2 | 6 | 1 | 3 | 8/12 = 67% | 2/12 = 17% |
| CA011 Copy on secret | 3 | 0 | 1 | 0 | 2 | 1/3 = 33% | 0% |
| CA012 Serialize on secret | 9 | 0 | 0 | 0 | 9 | 0/9 = 0% | 0% |
| CA013 derived PartialEq on secret | 12 | 0 | 1 | 0 | 11 | 1/12 = 8% | 0% |
| CA014 secret passed to log macro | 3 | 3 | 0 | 0 | 0 | 3/3 = 100% | 3/3 = 100% |
| CA015 never zeroized | 12 | 0 | 4 | 1 | 7 | 4/12 = 33% | 0% |
| CA021 MAC compared with == | 1 | 0 | 0 | 0 | 1 | 0/1 = 0% | 0% |
| CA027 hardcoded key | 1 | 0 | 0 | 1 | 0 | 0/1 = 0% | 0% |
| CA028 reused nonce | 1 | 0 | 0 | 0 | 1 | 0/1 = 0% | 0% |
| CA071 constant RNG seed | 1 | 0 | 0 | 0 | 1 | 0/1 = 0% | 0% |
| All | 55 | 5 | 12 | 3 | 35 | 17/55 = 30.9% | 5/55 = 9.1% |

## Against round 5

| | Round 5 | Round 6 |
|---|---|---|
| Sampled | 52 | 55 |
| Strict precision | 31% | 30.9% (17/55) |
| TP-only | 12% | 9.1% (5/55) |

Strict precision did not move (31% to 30.9%) and TP-only fell (12% to 9.1%). The
round 5 fix pass shows no measurable gain on unseen crates. The samples are different
sizes, are drawn from different crates and have a different rule mix, and with n of 52
and 55 a difference of a few points is within sampling noise either way; the honest
reading is "no improvement shown", not "got worse".

Borderline labelling that affects TP-only. Five CA010 rows (ids 2, 5, 7, 8, 9) are real
credentials printed by a derived Debug on a type with no format call found. I labelled
them TH because no sink was shown. Round 5 labelled the same pattern TP (for example
an access token in a derived-Debug struct). Under the round 5 convention those five
would be TP and TP-only would be 10/55 = 18%. Strict precision is unaffected by that
choice. I kept the stricter reading as instructed.

## False-positive causes (35 FP rows)

| Cause | FP rows | Rules affected | Ids |
|---|---|---|---|
| Not a secret: public value or ordinary data with a secret-sounding name (sighash, Sapling ephemeral key, Sprout paying key, withdrawal address, DB scan keys and key buffers, slasher and pubkey-cache keys, public MLS credential, vector of result indices; one struct whose comment says the fields are public) | 11 | CA011, CA013, CA015 | 12, 14, 24, 29, 32, 40, 43, 45, 46, 48, 50 |
| Derived PartialEq on a config, DB-row, vault-entry or SQL-AST struct that is never compared to attacker input | 8 | CA013 | 25, 26, 27, 30, 31, 33, 34, 35 |
| Field already holds ciphertext (encrypted cipher strings from the vault, structs named `...Encrypt` whose field is encrypted before serialising) | 6 | CA012, CA015 | 15, 18, 19, 20, 21, 41 |
| Serialising is the purpose of the type (login request body; keystore rows that are persisted into the encrypted keystore, zeroized and Debug-obfuscated) | 4 | CA012 | 16, 17, 22, 23 |
| Error-message String in an error variant named after a secret (`InvalidJWTSecret(String)`, `UnableToReadPasswordFromUser(String)`) | 2 | CA010 | 0, 11 |
| Custom redacting derive not recognised (`core_crypto_macros::Debug` with `#[sensitive]`) | 1 | CA010 | 3 |
| XML end-tag name compared with `==`, matched as a MAC/digest (`tag`) | 1 | CA021 | 51 |
| Variable is a session id, not a nonce, in an interop test binary | 1 | CA028 | 53 |
| Constant seed is an inactive fallback of a deterministic-test RNG (real draws use the per-thread RNG unless a seed env var or `reseed` is set) | 1 | CA071 | 54 |

Name-based secret detection (a field called `key`, `credential`, `password`, `secret`
or `sighash`) is behind most of the FP rows. Almost all of them came from three rules
(CA013, CA012, CA015); CA010 and CA014 are the rules with usable precision.

## True positives found (5)

| Id | Crate | Location | Problem |
|---|---|---|---|
| 4 | surrealdb | surrealdb/src/opt/auth.rs:52 | public SDK `Database` credentials struct holds the password and derives Debug |
| 10 | shadowsocks-rust | crates/shadowsocks/src/config.rs:404 | `ServerConfig` derives Debug with password, `enc_key` and identity keys, and startup code does `trace!("{:?}", config)` (server, local, manager) and the DNS path traces `svr_cfg` |
| 36 | shadowsocks-rust | crates/shadowsocks-service/src/local/socks/server/socks5/tcprelay.rs:157 | `error!` logs the SOCKS5 password supplied on a failed login (the returned error repeats it) |
| 37 | shadowsocks-rust | crates/shadowsocks-service/src/manager/server.rs:555 | `error!` logs the configured user password when base64 decoding fails |
| 38 | shadowsocks-rust | crates/shadowsocks-service/src/local/socks/server/socks5/tcprelay.rs:144 | `trace!` logs the accepted SOCKS5 password |

All three CA014 findings were real. CA014 is the only rule that reached 100%, on n=3.

Recall observation (outside the sample, not part of the measurement). While reading
shadowsocks-rust I saw `check_user` in `local/http/config.rs:157` and
`local/socks/config.rs:126` compare the stored proxy password with the client-supplied
one using `pwd == password.as_ref()`. That is a non-constant-time comparison of a
secret against attacker input. The scan did not flag it (CA021 had one finding in the
whole default view, an XML tag). This is one anecdote, not a recall estimate.

## Proposals (not implemented)

1. CA013: stop firing on a bare `#[derive(PartialEq)]`. Fire only when a secret-typed value
   is compared with `==`/`!=` against a non-constant value in function code, or when the
   type is itself a key/MAC/token newtype (single field, no other data). 11 of 12 sampled
   rows were config/row/AST structs. Failing that, demote it to low.
2. CA012: do not fire on a type that derives both Serialize and Deserialize as an API or
   storage DTO; fire when the Serialize output reaches a log, file or response. Skip
   structs whose names end in `Encrypt`/`Encrypted`/`Request`/`Req`, and fields holding
   cipher strings. All 9 sampled rows were FP.
3. CA015 and CA011: tighten the secret-name list. Plain `key`, `keys` and `credential` are
   too generic (database keys, public MLS credentials). Drop findings where the buffer is
   filled from an integer index (`to_be_bytes`) or an address, honour doc comments that
   say "public" or "non-sensitive", and require a stronger name (`secret`, `private`,
   `seed`, `mnemonic`, `password`) or a key-typed value.
4. CA010: recognise a derive macro whose last path segment is `Debug` (for example
   `core_crypto_macros::Debug`) and any `#[sensitive]`/`#[redact]` style attribute as
   redacting. Ignore `String` fields in an error enum variant when the variant is the
   `map_err` target of a read/parse call (the string is the error text).
5. CA010: when the crate has a `{:?}` format of the containing type in a log macro (as in
   shadowsocks-rust), raise to high. Without a sink, consider low or TH-style wording,
   because six of the twelve sampled rows were real credentials with no sink shown.
6. CA021: require the compared operand to be named like a MAC/tag/digest/hmac/signature
   and not match the bare word `tag` (XML or HTML tag names). Add `pwd == password` style
   checks, where one side comes from a request, as a separate confidence tier.
7. CA028: require the reused variable to be named `nonce`/`iv` (or flow into a nonce
   argument); skip files under `interop/`, `examples/` and test tools.
8. CA071: do not fire when the constant seed is in the `None` or fallback arm of a seed
   configuration, or in a function documented as test or bench only.
9. CA027: treat `#[cfg(any(test, debug_assertions))]` as test code (it was NP here).
10. Evaluation practice: round 6 gives n of 1 to 3 for six rules. Measuring those needs a
    run over more crates (or a targeted scan for just those rules) before any precision
    claim.
