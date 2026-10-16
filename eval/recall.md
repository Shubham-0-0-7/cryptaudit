# Recall on crates with known bugs

The blind rounds measure precision: of the findings shown, how many are real. This page measures recall: of bugs that are known to exist, how many does the tool find.

## Method

1. Take advisories from the [RustSec advisory database](https://github.com/rustsec/advisory-db) that describe a misuse our rules are meant to catch: a secret leaked through `Debug` or logs, a non-constant-time comparison, a reused nonce.
2. Download the last vulnerable release and the first patched release from crates.io.
3. Run `cargo cryptaudit` (0.4.1 plus SARIF, `--min-confidence low`) on both.
4. Count a bug as **caught** only if a finding sits on the code the fix changed and is gone, or reduced, in the patched release. A finding somewhere else in the crate does not count.

The advisory list was filtered by keyword (`debug`, `log`, `constant time`, `nonce`), so it is not a random sample. Nine advisories were found; one is outside what any rule claims to cover.

## Results

| Advisory | Crate (vulnerable → fixed) | Bug | Rule | Result |
|---|---|---|---|---|
| RUSTSEC-2022-0086 | slack-morphism 0.40.0 → 0.41.0 | OAuth and signing secrets printed by derived `Debug` | CA010 | **Caught**: high-confidence findings on the config structs whose `String` secret fields the fix retyped; gone in 0.41.0 |
| RUSTSEC-2023-0125 | aws-sigv4 0.55.0 → 0.55.1 | `SigningParams` derives `Debug` with the secret key | CA010 | **Caught**: high on `SigningParams` (`lib.rs:32`); gone in 0.55.1 |
| RUSTSEC-2026-0225 | nostr 0.44.6 → 0.44.7 | `Debug` exposes NIP-46 and NIP-60 credentials | CA010 | **Caught**: 4 high findings on the 4 types the fix gave a hand-written `Debug`; 0 in 0.44.7 |
| RUSTSEC-2022-0087 | slack-morphism 1.3.1 → 1.3.2 | webhook URL (a secret) written to the debug log | CA014 | Missed |
| RUSTSEC-2026-0275 | azure_core 0.21.0 → 0.22.0 | `debug!("... {request:#?}")` writes the `authorization` header | CA014 | Missed |
| RUSTSEC-2024-0358 | object_store 0.10.1 → 0.10.2 | web-identity token request logged | CA014 | Missed |
| RUSTSEC-2022-0018 | totp-rs 1.0.0 → 1.1.0 | `self.generate(t) == token` compares a 2FA code with `==` | CA021 | Missed; **caught after the fix below** (`lib.rs:157`, medium, none in 1.1.0) |
| RUSTSEC-2023-0068 | cocoon 0.3.3 → 0.4.0 | the RNG is cloned for every encryption, so every nonce is the same | CA028 | Missed; **caught after the fix below** (`lib.rs:725-731`, medium, none in 0.4.0) |
| RUSTSEC-2024-0010 | svix 1.16.0 → 1.17.0 | hand-written constant-time compare ignores length | none | Out of scope |

**In scope: 3 of 8 caught (38%) on the first pass.** Counting the out-of-scope case, 3 of 9.

**After the two rule changes below: 5 of 8 (63%).** Be careful with this second number: the two rules were written after seeing these two bugs, so it shows the gaps are closed, not that recall on new bugs is 63%. The first-pass 38% is the honest estimate; the remaining three misses are the ones that need knowledge the tool does not have.

## What the misses have in common

The three catches are all `#[derive(Debug)]` on a struct with a field named like a secret. That is the case the name heuristic is built for. Every miss is a case where nothing in the code is *named* like a secret:

- **slack-morphism 1.3.1, azure_core, object_store.** The secret is a URL, an HTTP request object or a header. Whether it is sensitive is a fact about what the program does at run time (`is_sensitive_url`, an `authorization` header), not about a name.
- **totp-rs.** The compared value is called `token` and the other side is the result of `generate(..)`. CA021 only recognises MAC and digest names.
- **cocoon.** The nonce is produced correctly, but from a cloned RNG, so the same bytes come out each time. CA028 looks for the same nonce variable used twice, not for an RNG whose state is thrown away.

## Rule changes made

- **CA021 (done):** `==` between a value from `generate`, `compute` or `calculate` and a parameter named `token`, `code`, `otp` or `signature`. Medium confidence, own message.
- **CA028 (done):** an RNG that is `.clone()`d and then used to fill a buffer named like a nonce, IV, salt or key. Medium confidence.
- **CA014 (not done):** flag `{:?}` or `{:#?}` of a value whose type is an HTTP request or header map. Three of the misses are of this kind, but it would risk many false positives and needs its own blind check first.

Both finished changes were also run on the 12 round 4 crates and the 6 calibration crates: no new finding there, so no precision cost on those sets. Details are in [triage.md](triage.md).

## Limits

Nine advisories is a small sample, so 38% should be read as "recall is well below precision, and concentrated in name-based cases", not as a precise rate. Advisories also over-represent bugs that someone noticed and reported, which are not the same as the bugs that exist. Both numbers should be reported next to each other, with this caveat.
