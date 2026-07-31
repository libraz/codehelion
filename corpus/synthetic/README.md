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
  (~5/10/20/30%) for degradation-curve measurement. Its mutations insert
  straight-line statements, which leaves the control-flow and call dimensions
  untouched.
- `rust-divergent/` — the axes the graded case cannot reach: variants that add a
  guard branch, nest a loop, replace the early exits, rename every callee, and
  one that does all of it at once. One axis per variant, so a dimension can be
  read in isolation, and the composites land on both sides of the Type-3
  acceptance threshold.
- `rust-replaced/` — the same graded idea along the axis the graded case cannot
  reach: statements replaced *in place* (~10/20/40%), so the sequence keeps its
  length and one position holds something else. Deleting a statement and
  inserting another elsewhere leaves two gaps an alignment can close
  separately; a replacement leaves none, which is the commonest real Type-3
  edit.
- `rust-literals/` — per-category Type-2 variants (integer, float, string, char
  literal changed one at a time) for literal-normalization measurement.
- `rust-partial/` — donor fragments transplanted into unrelated host functions
  for partial-clone measurement: two labelled partial clones (a verbatim Type-1
  loop body, a renamed Type-2 statement run) plus two `non_clone` idiom copies
  (a verbatim parse-error block) that mark an idiom-suppression target rather
  than a structural non-clone.
- `rust-negative/` — four functions built on one skeleton that compute
  different things, plus a file of verbatim copies of all four. The copies are
  the clones; every pairing of two different functions is a labelled
  `non_clone`. Precision measurement: what must come out is one group per
  function and nothing that mixes two of them.
- `c/` and `cpp/` — the Rust reference case ported to C and C++.
- `rust-cpp-semantic/` — a hand-labelled, compiler-backed Rust/C++ porting
  corpus for restricted-semantic rules. It covers a SOURCE/COLLECT
  correspondence, an Option/optional validation correspondence, and a
  deliberately unregistered sequence transformation. Unlike the structural
  mutation cases, this case is maintained directly because its evidence is
  compiler resolution and an explicitly selected cross-language comparison.
- `rust-cpp-result-expected-semantic/` — a hand-labelled C++23 `expected` /
  Rust `Result` corpus. It measures the closed identity-propagation and
  validation rules, plus altered-success-value and compound-condition
  negatives.
- `rust-restricted-semantic/` — a hand-labelled Rust corpus for every initial
  same-language restricted-semantic rule. It keeps direct-adapter,
  validation, lifecycle, serialization round-trip, and operation-sequence
  negatives beside their positive counterparts, then measures them through the
  Rust helper.
- `cpp-restricted-semantic/` — a hand-labelled C++ corpus for the closed
  `std::to_string` / `std::stoull` serialization round trip and its
  same-operation negative, measured through the Clang helper.
- `cpp-loop-restricted-semantic/` — a hand-labelled C++ corpus for the closed
  direct `std::vector` range-for collection and numeric reduction forms. It
  keeps transformed arguments and accumulations as nearby negative cases.
- `rust-cpp-loop-semantic/` — a hand-labelled Rust/C++ porting corpus for the
  same direct loop forms. The correspondence uses compiler-confirmed
  constructs rather than recovering an API name, and transformed operands are
  negative cases.

Within a case:

- `spec.json` declares, per variant, the clone type and the edits
  (comment/whitespace for Type-1, identifier/literal substitution for Type-2,
  statement insert/delete/replace with a target change rate for Type-3; a
  replacement counts twice, once for the statement that went and once for the
  one that arrived). A per-item
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
- A `non_clone` pairs a seed function with the variant's copy of it — a
  recurring idiom that must not be reported — or, when it names a
  `counterpart`, with a *different* function the variant carries, which is how
  a genuine negative pair is expressed.

## What reads the labels

Two harnesses. One scores a scan against them — how much of what is labelled is
recovered, how much of what is reported is labelled. The other edits the corpus
with them: the pairs that share a seed fragment are one unit written several
times, so removing all of them and leaving the seed's text in a file of its own
is an extraction the labels define rather than a script hard-codes. Scanning
either side of that edit and auditing one against the other is how the audit
states are checked at corpus scale rather than on a two-file fixture.

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
