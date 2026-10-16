# Blind evaluation corpus

`labels.csv` has one row per finding from the blind scan of twelve unseen crates
(see "Blind evaluation" in [../triage.md](../triage.md)).

Columns: `repo`, `commit` (short SHA the scan ran on), `rule`, `confidence`,
`location` (path inside the repo and line), `label`, `reason`.

Labels: `TP` real problem, `TH` true but hardening only, `NP` true but in test or
tool code, `FP` wrong claim. The scans ran with
`--no-suppress --min-confidence low`. Clone each repo at its commit to check a row.

`labels_round2.csv` is round 2: a seeded sample (12 default-view findings per rule)
from ten more crates, labelled before the round-2 fixes. Columns as above, plus
`id`.

`labels_round3.csv` is round 3: a seeded sample (seed 20261013, 12 default-view
findings per rule) from ten more crates, labelled before the round-3 fixes. Same
columns as `labels_round2.csv`.

`labels_ca014.csv` is the first evaluation of CA014: every default-view finding in
the calibration repos and the repos of rounds 1-3, labelled before the CA014 fixes.

`labels_round4.csv` is round 4: a seeded sample (seed 20261014, up to 12 default-view
findings per rule, all 16 for CA014) from twelve more crates, labelled before the
round-4 fixes. Same columns as `labels_round2.csv`.

`labels_round5.csv` is round 5: a seeded sample (seed 20261016, up to 12 default-view
findings per rule, 52 in all) from twelve more crates, labelled after the round 4
fixes and before any round 5 fix. Same columns as `labels_round2.csv`. The crates
are application-services, aws-lc-rs, cargo, ente, lldap, meilisearch, quiche,
rust-bitcoin, s2n-quic, sudo-rs, tmkms and vodozemac. The scan ran on the default
branch heads on 2026-10-16; the `commit` column gives each SHA.
