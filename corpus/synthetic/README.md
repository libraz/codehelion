# Synthetic corpus

A small seed set for the evaluation harness. It is deliberately tiny: enough to
exercise the harness end to end and to serve as a fixture for recall/precision
tests, not a statistically meaningful benchmark.

The variant sources and their labels are **generated** from a seed plus a
declarative mutation spec, so the labels can never drift out of sync with the
sources. Do not hand-edit the generated files; edit the spec and regenerate.

## Contents

Each case is one directory holding a hand-authored `seed`, a `spec.json`
mutation spec, the generated variant sources and the generated `labels.json`:

- `rust/` — Rust Type-1/2/3 variants of a few tiny functions plus a getter
  non-clone. The reference case.
- `rust-graded/` — one larger function mutated at graded Type-3 change rates
  (~5/10/20/30%) for degradation-curve measurement.
- `rust-literals/` — per-category Type-2 variants (integer, float, string, char
  literal changed one at a time) for literal-normalization measurement.
- `rust-partial/` — donor fragments transplanted into unrelated host functions
  for partial-clone measurement: two labelled partial clones (a verbatim Type-1
  loop body, a renamed Type-2 statement run) plus two `non_clone` idiom copies
  (a verbatim parse-error block) that mark an idiom-suppression target rather
  than a structural non-clone.
- `c/` and `cpp/` — the Rust reference case ported to C and C++.

Within a case:

- `spec.json` declares, per variant, the clone type and the edits
  (comment/whitespace for Type-1, identifier/literal substitution for Type-2,
  statement insert/delete with a target change rate for Type-3). A per-item
  `type` override marks an item a variant leaves untouched (an unmutated item is
  a Type-1 clone of the seed). An item may also declare `transplants`, each
  copying a donor item's fragment (anchored `from`..`to`) into the item after an
  `after` anchor, optionally renamed, to build partial clones; a labelled
  transplant emits a fragment-level `clone_pair`, a `non_clone` one instead
  marks a suppression target. `language` selects the item scanner
  (`rust` | `c` | `cpp`).
- `labels.json` is the generated `LabelSet`: clone pairs (seed fragment ↔
  variant fragment, with the clone type) plus any deliberate non-clones. Line
  ranges are computed from the edits the generator applied.

## Generating and checking

The generator is the `codehelion-corpus-gen` binary in the `codehelion-eval`
crate:

```sh
# Regenerate variants + labels from the spec (overwrites the generated files):
cargo run -p codehelion-eval --bin codehelion-corpus-gen -- \
  generate --spec corpus/synthetic/rust/spec.json --out-dir corpus/synthetic/rust

# Verify the committed files match the spec (drift guard; non-zero on mismatch):
cargo run -p codehelion-eval --bin codehelion-corpus-gen -- \
  check --spec corpus/synthetic/rust/spec.json --dir corpus/synthetic/rust
```

Output is deterministic: the same seed and spec always produce byte-identical
files. The `check` subcommand is the mechanical drift guard — run it after
editing any seed or spec.

## Line ranges

The line ranges in `labels.json` are evaluation input only. Stable identity in
codehelion is fingerprint-based, never line- or position-based, so these ranges
never feed into any stable ID.
