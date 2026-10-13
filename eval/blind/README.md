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
