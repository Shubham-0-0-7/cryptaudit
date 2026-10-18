# Blind evaluation, round 8

Build measured: the frozen scanner built from committed HEAD `55c1d2a` (reports version 0.5.0, lists 25 rules). It includes the three structural changes written after round 7 and the new `class` field (`finding` or `hardening`; CA010, CA011, CA012, CA013, CA015 and CA016 are hardening). Scanned with `--format json --min-confidence low --no-suppress --fail-on critical`; "default view" means confidence medium or high.

## Method and caveats (read first)

- The labeller is one AI agent (Claude), not a human. Every label comes from reading the code around the finding. The labels were not cross-checked by a second labeller, and the TP/TH boundary is known to be unstable between readers (see the round 5 second-labeller result in `eval/triage.md`).
- Sample seeded with 20261019. For each rule the default-view findings were sorted by (repo, path, line), shuffled with Python `random.Random("20261019:<rule>")` (string seed per rule), then walked in shuffled order accepting a row unless its crate already had 4 rows for that rule, stopping at 12 rows. Rules with 12 or fewer findings are therefore taken whole unless the 4-per-crate cap bites. The cap bit in one place: CA021 had 5 default-view findings in warpgate, so one was dropped (`vendor/picky/src/putty/ppk/encryption.rs:208`, high, never labelled). CA010 (83 default-view) and CA015 (94) were the only rules drawn at random; each got 12 rows.
- Low-confidence findings were counted but not labelled, with one deliberate exception: all low-confidence CA024, CA063, CA064 and CA065 findings (74) were read in full to answer the structural questions below. Those reads are not in the CSV or the precision numbers.
- The cap helped but did not stop dominance: warpgate still supplies 26 of 57 rows (45.6 percent), because it has findings under nearly every rule. 14 of the 57 rows are in warpgate's `vendor/` directory (vendored picky, sspi, ironrdp, vnc-rs), which is shipped third-party code, not warpgate's own. I labelled it on the merits, not as NP. All four CA014 TPs are one cluster (vendored sspi Kerberos), so "4 of 4" is one code base, not four independent confirmations.
- Small n: nine rules have n of 1 to 4. A single row moves them by 25 to 100 points. Only CA010 and CA015 have n=12.
- No repo build scripts or code were run. Scans ran from the scratchpad directory.

## The crates, and the swaps

Decided before any scan. `ramosbe/oauth2-rs` (#7) and `ramosbe/openidconnect-rs` (#12) returned "Repository not found" (HTTP 404, not a hang) on `git clone --depth 1`. Per the reserve rule they were replaced, in order, by `sozu-proxy/sozu` and `dalek-cryptography/x25519-dalek`. No other clone failed. No crate was swapped because of its findings. The first clone attempt failed in my shell for a local reason (no `timeout` command on macOS), so I redid all clones with a perl alarm of 180 s; none timed out.

Rust lines = all `.rs` lines in the clone (tests, examples and vendored code included). Findings = all confidence levels, default view, low.

| Crate | Commit | Kind | Rust lines | Files scanned | All | Default | Low | Rows sampled | Share of rows |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| yubikey.rs | bc96158 | PIV smart card, 3DES | 7,682 | 26 | 14 | 1 | 13 | 1 | 1.8% |
| ureq | 3f18f90 | HTTP client, TLS options | 19,962 | 37 | 8 | 2 | 6 | 0 | 0.0% |
| hudsucker | 7b7baf3 | MITM proxy | 4,262 | 13 | 0 | 0 | 0 | 0 | 0.0% |
| warpgate | 5d4d8da | SSH/HTTP/RDP bastion (vendors picky, sspi, ironrdp, vnc-rs) | 186,866 | 710 | 357 | 92 | 265 | 26 | 45.6% |
| alloy | eb2289c | Ethereum signers and keystores | 132,169 | 389 | 69 | 12 | 57 | 4 | 7.0% |
| nostr | de3031a | keys, NIP-04/44 | 77,520 | 241 | 34 | 8 | 26 | 3 | 5.3% |
| fedimint | 8c9d15c | federated e-cash | 202,113 | 470 | 231 | 42 | 189 | 8 | 14.0% |
| iroh | c6fba1b | QUIC networking, relay | 58,526 | 100 | 45 | 14 | 31 | 1 | 1.8% |
| lemmy | fc640cf | web app, bcrypt, JWT | 75,171 | 516 | 139 | 27 | 112 | 5 | 8.8% |
| realworld-axum-sqlx | f1b2565 | small app, argon2 | 2,129 | 12 | 6 | 3 | 3 | 2 | 3.5% |
| sozu (reserve) | 43844cc | HTTP reverse proxy | 329,201 | 152 | 111 | 10 | 101 | 7 | 12.3% |
| x25519-dalek (reserve) | 2ddda07 | X25519 library | 682 | 2 | 1 | 0 | 1 | 0 | 0.0% |
| **Total** | | | **1,096,283** | | **1,015** | **211** | **804** | **57** | |

Of the 1,015 findings, 211 are default view; by class, 25 default-view findings are `finding` and 186 are `hardening` (low confidence: 125 finding, 679 hardening). The default view is 88 percent hardening.

## Headline: strict precision by class

Strict precision = (TP+TH)/n. TP-only = TP/n. NP stays in the denominator, as in earlier rounds.

| Slice | n | TP | TH | NP | FP | Strict precision | TP-only |
|---|---:|---:|---:|---:|---:|---:|---:|
| **class = finding** | 24 | 7 | 3 | 1 | 13 | **41.7% (10/24)** | **29.2% (7/24)** |
| **class = hardening** | 33 | 1 | 22 | 0 | 10 | **69.7% (23/33)** | **3.0% (1/33)** |
| **All** | 57 | 8 | 25 | 1 | 23 | **57.9% (33/57)** | **14.0% (8/57)** |

Counting only non-NP rows (56), strict precision is 58.9 percent.

Reading it honestly:

- The class split does what it was meant to. The two classes behave very differently: hardening rows are mostly true-but-no-sink (22 of 33 TH), findings are much more often a real problem (7 of 24 TP) but also contain most of the pure false positives by count (13 of 24).
- Rule mix drives the overall number. Hardening is 33 of 57 rows only because CA010 and CA015 have a large pool and each contributes 12. CA015 was 12 of 12 TH this round, which lifts the overall figure. The overall 57.9 percent is not comparable with round 7's 38.8 percent without noting that round 7 had 24 hardening rows and this round 33.
- Round 7 split by the same classes (computed from `labels_round7.csv`): hardening 17 of 24 strict (70.8 percent, 0 TP), findings 2 of 25 strict (8.0 percent, 1 TP). So hardening precision is flat (70.8 vs 69.7 percent) and finding precision rose from 8 to 42 percent. With n of 24 or 25 the 95 percent intervals on the finding class are wide (roughly 22 to 63 percent for 10/24), and the new crates differ from the round 7 ones, so I would not claim a fix effect. Four of the seven finding-class TPs come from one vendored library cluster (sspi trace logging) that no earlier round could have contained.
- 8 TP in 57 is the best TP-only figure since round 5 (12 percent), but TP-only is the unstable label (round 5 second labeller gave 0 TP where the first gave 6).

| Round | Sampled | Strict precision | TP-only |
|---|---:|---:|---:|
| 5 | 52 | 31% | 12% |
| 6 (released 0.5.0) | 55 | 30.9% | 9.1% |
| 7 | 49 | 38.8% | 2.0% |
| 8 (this build) | 57 | 57.9% (33/57) | 14.0% (8/57) |

## Per-rule results (sampled rows)

Default-view total is across all 12 crates; low is the count of low-confidence findings (not labelled). Rules not listed produced no findings at all.

| Rule | Class | Default total | Low | n | TP | TH | NP | FP | Strict | TP-only |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| CA010 secret-in-debug | hardening | 83 | 285 | 12 | 1 | 5 | 0 | 6 | 50.0% | 8.3% |
| CA011 copy-on-secret | hardening | 1 | 17 | 1 | 0 | 1 | 0 | 0 | 100% | 0% |
| CA013 partialeq-on-secret | hardening | 8 | 150 | 8 | 0 | 4 | 0 | 4 | 50.0% | 0% |
| CA015 secret-not-zeroized | hardening | 94 | 84 | 12 | 0 | 12 | 0 | 0 | 100% | 0% |
| CA014 secret-in-log | finding | 4 | 41 | 4 | 4 | 0 | 0 | 0 | 100% | 100% |
| CA021 mac-compared-with-eq | finding | 11 | 4 | 10 | 1 | 1 | 0 | 8 | 20.0% | 10.0% |
| CA029 password-compared-with-eq | finding | 1 | 0 | 1 | 0 | 1 | 0 | 0 | 100% | 0% |
| CA062 weak-password-hash-cost | finding | 1 | 1 | 1 | 0 | 0 | 1 | 0 | 0% | 0% |
| CA063 fast-hash-of-password | finding | 4 | 5 | 4 | 1 | 0 | 0 | 3 | 25.0% | 25.0% |
| CA064 tls-certificate-validation-disabled | finding | 3 | 11 | 3 | 1 | 1 | 0 | 1 | 66.7% | 33.3% |
| CA066 jwt-verification-disabled | finding | 1 | 0 | 1 | 0 | 0 | 0 | 1 | 0% | 0% |
| CA012 serialize-on-secret | hardening | 0 | 143 | 0 | | | | | n/a | n/a |
| CA019 | finding | 0 | 6 | 0 | | | | | n/a | n/a |
| CA024 weak-primitive | finding | 0 | 55 | 0 | | | | | n/a | n/a |
| CA065 tls-hostname-verification-disabled | finding | 0 | 2 | 0 | | | | | n/a | n/a |
| **All** | | **211** | **804** | **57** | **8** | **25** | **1** | **23** | **57.9%** | **14.0%** |

CA025, CA016, CA018, CA071 and the other rules not listed produced nothing. (CA018 and CA071 fired in round 7 and not here; the two unwrap and fixed-seed shapes simply did not occur, or were not matched, in these crates.)

## False-positive causes (23 FP rows, plus 1 NP)

| Rule | FP rows | Causes |
|---|---:|---|
| CA010 | 6 | Not a secret by meaning: a database key in a KV wrapper (fedimint redb, row 0); a secp256k1 public key (`PreimageKey`, row 3); a load-balancer hash seed (sozu Maglev, row 6); an HTTP header name (sozu `HeaderEdit`, row 7); X.509 key identifiers and key-usage flags (picky `CertificateBuilderInner`, row 9). Hand-written Debug that already prints `[redacted]` plus a length (sozu `HttpFrontendConfig`, row 5). |
| CA013 | 4 | Not a secret by meaning: a raw signed transaction in an RPC request (alloy, row 14); a DB key in the empty example module (row 16); the same public `PreimageKey` (row 17); an unparseable secret-reference string, which is a pointer (warpgate `MaybeSecretRef::Malformed`, row 19). |
| CA021 | 8 | The operand is not a MAC: nostr event `tags` (row 37), sozu replica/frontend `tags` twice (rows 39, 40), a TLV `tag` byte in yubikey.rs (row 46); a certificate `material_digest` compared for dedup (row 41); public digests with no secret (Authenticode message digest and CA name MD5, rows 44, 45); an unencrypted PPK file whose MAC key anyone can derive (row 43). The `tag` word match again accounts for 4 of the 8, the same cause as round 7. |
| CA063 | 3 | One protocol-mandated function: the MySQL `caching_sha2_password` client scramble (warpgate-protocol-mysql, rows 50-52). It is a challenge-response computed by a client, not a stored hash. |
| CA064 | 1 | Vendored sspi CredSSP: TLS certificate is intentionally not PKI-validated; the protocol binds the server public key inside the authentication exchange (row 54). |
| CA066 | 1 | `Validation::new(header.alg)` with the HMAC family rejected on the line above and the key taken from the issuer JWKS, so no algorithm confusion (row 56). The tool does not see the guard. |
| CA014, CA015, CA011, CA029 | 0 | |

By cause, the 23 are: the flagged operand or field is not a secret or MAC by meaning or is public (17: CA010 5, CA013 4, CA021 8); a hand-written redaction the tool does not recognise (1: CA010); the protocol mandates the construct (4: CA063 3, CA064 1); a guard the tool does not see (1: CA066).

## True positives and near-misses

8 TP, all low severity in practice, but each shows a secret reaching a sink or a check that can really be abused:

- CA014, warpgate vendored sspi (rows 21-24): `#[instrument(level = "trace", ret)]` on `generate_krb_priv_request` records `new_password`; `trace!(?encryption_key ...)` and `trace!(plain = ?encoded_krb_priv ...)` log the Kerberos subkey and the plaintext KRB_PRIV part that holds the new password; `trace!(?sub_session_key)` logs the DCE sub-session key. Trace level only, but a reviewer would remove them.
- CA010, iroh `iroh-relay/src/main.rs:161` (row 4): the flagged type is the config enum `AccessConfig`, whose `SharedToken(Vec<String>)` holds bearer tokens. The leak that actually exists is `debug!("{relay_config:#?}")` at line 606, which prints `RelayConfig.access`, an `Arc<dyn DynAccessControl>` with a `Debug` supertrait; `SharedTokenAccess(Vec<String>)` (line 280) derives Debug, so the tokens are printed at debug level when shared-token auth is configured. The tool found it on the sibling type, not on the type that is printed.
- CA021, nostr `nips/nip44/v2.rs:288` (row 38): NIP-44 decrypt checks the HMAC with `mac != calculated_mac.as_slice()` on attacker-supplied payloads. The spec asks for a constant-time check.
- CA063, sozu `lib/src/protocol/mux/auth.rs:151` (row 49): HTTP Basic auth credentials are configured as unsalted `username:hex(sha256(password))` (documented in `doc/configure.md`). The runtime compare is constant time; the stored format is the weakness.
- CA064, lemmy `crates/diesel_utils/src/connection.rs:208` (row 53): for every TLS database connection (`sslmode=require`, the only supported mode) a `NoCertVerifier` is installed, and no option exists to verify. This mirrors libpq's `require` semantics, so it is a design limit, not an opt-in switch. Note this is the case where structural change (a) did not demote (condition is the sslmode string); I think medium was right here.

TH worth noting: warpgate `healthcheck.rs:16` (CA064, high) is an unconditional `danger_accept_invalid_certs(true)` but sends no secret to its own loopback endpoint (TH). nostr-connect `client.rs:455` (CA029) compares the NIP-46 connect secret with `==` (TH: real, but timing has to cross nostr relays).

## Did the three structural changes carry over to unseen crates?

I read all 74 low-confidence CA024 (55), CA063 (5), CA064 (11) and CA065 (2) findings, not a sample. None of them is real misuse in application code. The one borderline case is under (a).

**(a) CA064/CA065 low when a verification setting gates the switch. Carried over, with one gap and one borderline.**
- Applied as designed: ureq (`if tls_config.disable_verification`, a library option, CA064 and CA065, 3 low rows); warpgate `client_cache.rs:45` and `kubernetes/server/auth.rs:464` (`if !options.tls.verify`; the config defaults to `verify: true`), `warpgate-tls/src/rustls_helpers.rs:181,199` (`accept_invalid_certs` and `accept_invalid_hostnames` parameters), and the RDP client (`verify` parameter, 3 rows). Test-only verifiers (iroh `no_cert_verifier` behind `test-utils`, sozu e2e mock) are low. None of the 11 CA064 low rows was a verifier installed unconditionally on a production path.
- Did not apply where it arguably should have: nothing in the settings-gated class. One medium CA064 (vendored sspi CredSSP `NoCertificateVerification`, row 54) is protocol design, not a switch; it stayed medium and was a FP.
- Borderline, possibly wrongly demoted: warpgate's RDP target option `verify_tls` defaults to `false` (`warpgate-common/src/config/target.rs:307`, documented as "RDP servers commonly use self-signed certificates, so this is off by default"). So with default settings the RDP client (`warpgate-protocol-rdp/src/client/tls.rs:129,264,270`) does not verify the target's certificate. These are the 3 low findings. CredSSP/NLA channel-binds the server public key, which mitigates it when NLA is used, so I would call it a documented insecure default, not a clear bug; but a gate on a setting whose default is "off" is not the same as an opt-in switch.
- Wrong direction: lemmy's `sslmode=require` (TP above) stayed medium, which I think is right.

**(b) CA024/CA025 low for libraries offering the primitive. Carried over; no default-view CA024 at all (round 7 had 4 FP).** All 55 low CA024 findings are libraries or wire-protocol code: vendored picky (MD5/SHA-1/RC2/3DES for PKCS#12, PPK, SSH fingerprints, JWE OAEP), vendored sspi (MD4/MD5/RC4 for NTLM and Kerberos), vnc-rs (DES for VNC auth), warpgate's MySQL protocol code (SHA-1 scramble, RSA-OAEP-SHA1), the VNC server (MD5 for Apple Remote Desktop), iroh's WebSocket handshake (SHA-1, RFC 6455), and yubikey.rs (3DES for PIV management keys, plus a PBKDF2-SHA1 10000 CA062 that the PIV format mandates). No application-side misuse among them. Two things I could not tell: why the warpgate MySQL and VNC protocol files (a different `Cargo.toml` from the vendored picky) went low, since the stated mechanism is "type or variant named for the primitive in the crate"; I did not trace it. And CA025 produced nothing, although warpgate's VNC server has an `aes128_ecb_decrypt` for the ARD credential blob (`warpgate-protocol-vnc/src/server/rfb.rs`, near line 235); whether CA025 would have fired and been demoted, or simply did not match, I do not know.

**(c) CA063 low for a public function named after the hash. Not demonstrated; one near-miss that looks like a gap.**
- There was no `pub fn md5_hash`-style function in this sample, so the rule was not exercised as designed.
- Near-miss, wrongly left at medium: warpgate-protocol-mysql `common.rs` has `pub fn compute_sha2_auth_challenge_response` (the MySQL `caching_sha2_password` scramble, lines 25-37) which produced 3 medium FP rows (rows 50-52). Its sibling `compute_auth_challenge_response` (SHA-1 `mysql_native_password`, lines 8-21) produced 3 low CA063 rows. Same file, same kind of function, different grade; the name contains `sha2` but not the exact hash name the rule looks for.
- Not wrongly demoted: sozu's real weak-hash finding (row 49) stayed medium. The remaining low CA063 rows (picky PPK KDF, SHA-1 over passphrase, a format the library implements) are correct to be low.

## Real crypto problems the tool did not report (anecdote, not recall)

From reading roughly 60 code regions plus targeted greps for fixed nonces/seeds, `==` on tokens and secrets, and weak password hashing. Little turned up.

- warpgate RDP: `verify_tls` defaults to off (`warpgate-common/src/config/target.rs:307`; use at `warpgate-protocol-rdp/src/client/tls.rs:115-128`). Reported by the tool only as low. See (a).
- fedimint `gateway/fedimint-gateway-server-db/src/lib.rs:693-700`: the v1 migration hashes the gateway password as a single salted SHA-256 (`hash_password`, using bitcoin_hashes `sha256::Hash::hash`). CA063 did not fire. It is a historical migration helper and I found no later use of `hashed_password`, so low importance.
- iroh `iroh/examples/auth-hook.rs:343`: `if token == self.token` compares a bearer token read from the network. It is example code, and CA021/CA029 do not match the name `token`. Example only (NP-like).
- nostr `nostr/src/nips/nip04/impl.rs` (lines 26-27, 85, 137): AES-256-CBC with no MAC. This is the NIP-04 specification (known-weak, superseded by NIP-44), so not a bug in the crate; no rule covers unauthenticated CBC.
- warpgate `warpgate-protocol-vnc/src/server/rfb.rs` `aes128_ecb_decrypt`: AES-ECB over a 128-byte credential blob under an MD5-derived key. That is the Apple Remote Desktop authentication protocol, so mandated; CA025 did not report it.
- Things done right that I read: fedimint `ApiAuth::verify` uses `subtle::ConstantTimeEq`; lemmy runs a dummy bcrypt verify on unknown users for constant timing and decodes JWTs with `Validation::default()`; the realworld app uses argon2; warpgate's own hash helper uses `Argon2::default()` outside tests.

hudsucker and x25519-dalek gave nothing (0 and 1 low CA012 on a `StaticSecret` that offers Serialize behind a feature flag). I did not find a clearly missed true bug of the kind the tool targets.

## Proposals (untested; not validated against this sample)

These are suggestions only. None has been run against any crate.

1. CA010/CA013: skip fields whose type or name says they are not secrets by meaning (`Preimage`-style public keys, `seed`, header names, DB `key` in a KV wrapper). Recognise `"[redacted]"` in hand-written Debug impls. Untested.
2. CA021: require the whole word `mac|hmac|digest|signature|token` and exclude the bare word `tag`/`tags` (4 of 8 FPs here, 3 of 4 in round 7). Untested; this is the same proposal as round 7 and still not applied.
3. CA063: widen "named after the hash" to the whole family (`sha1`, `sha2`, `sha256`) and to a `compute_*_challenge_response`/scramble shape, or exclude `*protocol*` crates. Untested.
4. CA066: do not flag `Validation::new(header.alg)` when an earlier statement rejects the HMAC family. Untested.
5. CA010: when the finding is a config enum holding a secret, check whether a type that derives Debug and is part of a debug-printed struct holds the same secret; the true leak in iroh was on the sibling type. Untested.
6. For CA064/CA065, consider keeping a verification setting whose default is off (warpgate RDP) at medium. Untested and probably noisy.

## Files

- `eval/blind/labels_round8.csv`: 57 labelled rows (`id,repo,commit,rule,confidence,class,location,label,reason`). Locations are paths inside each clone at the given short SHA.
- Scratch (not in the repo): clones, scan JSON and the sampling and labelling scripts under `.../scratchpad/round8/` (`repos/`, `scans/`, `work/`).
