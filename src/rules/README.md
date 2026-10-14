# Rule files

| File | Rules |
|---|---|
| `ca010.rs` | CA010 (also holds item/field helpers shared by CA011-013 and CA015) |
| `derives.rs` | CA011 `Copy`, CA012 `Serialize`, CA013 `PartialEq` on secret types |
| `logging.rs` | CA014 secret passed to a logging, printing or error macro, or recorded by `#[instrument]` |
| `zeroize.rs` | CA015 missing zeroization, CA016 optimiser-elided wipe |
| `results.rs` | CA018 `unwrap` on decrypt/verify, CA019 discarded verify result |
| `compare.rs` | CA020 `assert_eq!` on MACs, CA021 `==` on MACs |
| `rng.rs` | CA023 weak RNG, CA071 fixed seed, CA072 time seed |
| `keys.rs` | CA027 hardcoded key, CA079 fixed CBC IV |
| `nonce.rs` | CA028 nonce reuse or fixed nonce |
| `bytes.rs` | helper, not a rule: "is this expression a constant byte string?" |

Register new rules in `mod.rs`. Fixtures live in `tests/fixtures/caNNN/`.
