# Evaluation corpus

Ground-truth data for measuring detector accuracy (precision/recall, findings
per KLOC, false positives per KLOC, result stability). Unlike throwaway
prototypes, this corpus is a lasting asset: later work keeps measuring against
it, so treat changes here as changes to the ground truth.

## Layout

```text
corpus/
  synthetic/   generated mutation cases (seed code + mutation scripts). Committed.
  labeled/     hand-labelled real code snippets with clone annotations. Committed.
  external/    checkouts of real OSS repositories. NOT committed (git-ignored).
  scripts/     fetch/generate helpers run manually by developers.
```

`external/` holds snapshots of third-party repositories used for
`precision@top-k` evaluation. These are **not redistributed**: they are cloned
locally by a script in `scripts/`, pinned to a recorded commit hash, and never
committed. codehelion itself performs no network access — fetching is an
explicit developer action, separate from the tool.

## Label format

Labels are machine-readable YAML so they can be checked by a script rather than
maintained as prose tables. One label file describes the expected clones (and
the deliberate non-clones) among a set of source files.

Line ranges are used **only** as evaluation input. Stable identity in
codehelion is fingerprint-based, never line- or position-based, so ranges never
feed into any stable ID.

```yaml
schema_version: 0
language: rust            # rust | c | cpp
# Source files this label set refers to, relative to this file's directory.
files:
  - a.rs
  - b.rs

# Positive examples: fragment pairs that SHOULD be reported as clones.
# Drives recall.
clone_pairs:
  - id: cp-001
    type: type-2          # type-1 | type-2 | type-3 | restricted-semantic
    fragments:
      - { file: a.rs, start_line: 10, end_line: 24 }
      - { file: b.rs, start_line: 5, end_line: 19 }

# Negative examples: fragments that must NOT be reported as clones.
# Boilerplate such as getters/setters, trait impls, and test fixtures.
# Drives precision (false-positive control).
non_clones:
  - id: nc-001
    reason: getter-boilerplate
    fragments:
      - { file: a.rs, start_line: 30, end_line: 33 }
      - { file: b.rs, start_line: 40, end_line: 43 }
```

The concrete detection-result format that the evaluation harness compares
against these labels is defined alongside the harness itself.

## License policy for corpus contents

- `external/` snapshots are never redistributed; only a fetch script and the
  pinned commit hash live in the repository.
- Any snippet copied into `labeled/` must be under an Apache-2.0-compatible
  license, so that the committed corpus stays compatible with this project's
  Apache-2.0 distribution. Record the source and its license next to the
  snippet.
