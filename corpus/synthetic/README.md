# Synthetic corpus

A small, hand-authored seed set for the evaluation harness. It is deliberately
tiny: enough to exercise the harness end to end and to serve as a fixture for
recall/precision tests, not a statistically meaningful benchmark.

## Contents

`rust/` holds one seed file and three mutated variants:

- `seed.rs` — a few tiny functions plus a trivial getter.
- `type1.rs` — `seed.rs` with only whitespace and comment changes (Type-1).
- `type2.rs` — `seed.rs` with renamed identifiers and changed literals (Type-2).
- `type3.rs` — `seed.rs` with one extra statement in one function (Type-3).
- `labels.json` — a `LabelSet` describing the expected clone pairs between the
  seed and each variant, plus one deliberate non-clone (the getter boilerplate).

## Line ranges

The line ranges in `labels.json` are evaluation input only. Stable identity in
codehelion is fingerprint-based, never line- or position-based, so these ranges
never feed into any stable ID. When editing a `.rs` file, update the matching
ranges in `labels.json`.

## Roadmap

This is a kickoff seed set authored by hand. A reproducible mutation generator
that derives variants (and their labels) from a seed will replace the manual
variants later; until then, keep this set small and its labels exact.
