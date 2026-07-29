# codehelion

[![CI](https://github.com/libraz/codehelion/actions/workflows/ci.yml/badge.svg)](https://github.com/libraz/codehelion/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/codehelion.svg)](https://crates.io/crates/codehelion)
[![codecov](https://codecov.io/gh/libraz/codehelion/branch/main/graph/badge.svg)](https://codecov.io/gh/libraz/codehelion)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)

A fully local command-line tool that audits Rust, C and C++ codebases for
duplicate logic and tracks how those findings change over time. It never sends
your source or results anywhere, needs no network access, and never executes
the code it analyses.

The current release ships two build-free analysis modes. **Fast** is
token-level Type-1 (identical) and Type-2 (renamed identifiers / changed
literals) detection that scans hundreds of thousands of lines in seconds and
millions in a couple of minutes.
**Structural** adds syntax-structural Type-3 detection — clones that differ by
added, removed or changed statements — and reports the per-dimension similarity
each finding was judged on. Semantic analysis and optional compiled-artifact
analysis arrive in later releases.

## Highlights

- **Build-free scanning** — an error-tolerant lexer processes Rust, C and C++
  sources directly; no compiler, build system or `compile_commands.json` needed.
- **Stable finding IDs** — findings are identified by content fingerprints, not
  line numbers, so unrelated edits don't churn your audit history.
- **Evidence, not a single score** — a gapped clone reports lexical,
  structural, control-flow, type and API similarity separately; a dimension the
  mode cannot measure is reported as absent rather than guessed.
- **Local audit history** — every scan is snapshotted into a SQLite database;
  text, JSON and SARIF reports are exports, the database is the canonical
  record. `audit` reports what became of each group since the previous scan.
- **Separated priority measures** — findings are ordered by clone confidence,
  maintenance risk and refactoring difficulty reported side by side, never by
  one opaque score, and every measure shows the inputs it was derived from.
- **Deterministic output** — the same input produces byte-identical reports, and
  a tree nobody touched is reported from the run that read it rather than
  analysed again.
- **Visible limits** — every resource ceiling that fires (file size, parse
  timeout, candidate budget) is counted in the report, never silently applied.
  On a tree large enough for the candidate budget to stop the search, the
  report says how many pairs it left unexamined rather than presenting a
  partial answer as a complete one.

## Installation

```sh
# From a checkout (crates.io, PyPI and Homebrew packages are planned):
cargo install --path crates/codehelion-cli
```

The result is a single self-contained binary; SQLite is bundled.

## Usage

```sh
codehelion scan               # scan the current directory, text report
codehelion scan --mode structural           # also detect gapped (Type-3) clones
codehelion scan --format json --output report.json path/to/repo
codehelion scan --format sarif --output report.sarif   # SARIF 2.1.0 log
codehelion scan --verbose     # list every clone group and member
codehelion scan --no-reuse    # analyse even if a recorded run read exactly this tree
codehelion scan --untrusted   # read a tree nobody vouches for under lowered ceilings
codehelion audit              # what became of the duplication since last time
codehelion explain <ID>       # show a finding from the audit database
codehelion baseline           # manage accepted-findings baselines
codehelion cache status       # audit-database location and size
codehelion config init        # write a commented codehelion.toml template
codehelion doctor             # report available analysis components
```

Findings are grouped into clone groups; each group and member carries a stable
ID you can suppress, baseline or look up later with `explain`.

`codehelion audit` compares two recorded scans and says what each group did:
whether it is new, unchanged, resolved, gained or lost occurrences, moved,
drifted apart or changed clone type. Groups are connected by content, not by
line number, so reindenting a file or adding a comment above a clone leaves the
history intact.

Once a finding is accepted, `codehelion baseline create` freezes it and later
scans report only what came after. When a release changes the rules that make
identifiers — a different literal-folding strategy, a new normalization — every
recorded ID moves, and a baseline that silently matched nothing would look
exactly like one that worked. Such a change is reported rather than applied
quietly, and `codehelion baseline migrate` rewrites the frozen judgements and
the history onto the new identifiers, naming any entry it could not carry
across instead of dropping it. Changes that only affect the order findings are
read in leave every identifier alone and cost you nothing.

## Configuration

`codehelion scan` reads an optional `codehelion.toml` from the scan root.
`codehelion config init` writes a fully commented template; the main knobs:

```toml
# min-clone-tokens = 20             # smallest clone reported, in tokens
# literal-normalization = "full"    # "preserve", "category" or "full"
# database = ".codehelion/audit.db" # audit-database location

[languages]
# headers = "detect"                # grammar for a bare ".h": "detect", "c", "cpp"

[priority]                          # whole numbers, read as shares
# maintenance-risk = 2              # only the composition is settable; what a
# refactoring-ease = 1              # duplication costs is a question about the code

[suppression]
# paths = []                        # path globs to hide; vendored trees go here
# symbols = []                      # globs over the name of the enclosing unit
# clone-ids = []                    # stable clone ids (hex, prefix allowed)
# generated-markers = ["@generated", "do not edit", "automatically generated"]
                                    # banners flagging machine output, matched
                                    # without regard to case; replaces defaults

[limits]                            # resource ceilings, all reported when hit
# max-file-bytes = 2097152
# parse-timeout-ms = 10000
# posting-cap = 64                  # unset: each mode keeps its own default
# pair-budget = 1000000             # per pairing pass, not shared between them
# max-component = 1024
```

`.h` is the one extension C and C++ share, and the grammar it is read with
decides what the analysis can see inside it: a C++ header read as C recovers
into shapes that declare nothing, which both hides its real duplication and
invents duplication between class bodies. `detect` counts the files whose
extension is not in doubt and follows the majority; where a tree has none —
a header-only library — it reads the headers themselves for something only C++
spells, and one of them saying so settles the run. The choice is part of the
run's build variant, so results read one way are never compared with results
read the other.

## Development

Common tasks are wrapped in the `Makefile` (`make help` for the full list):

```sh
make format        # auto-fix: clippy --fix + cargo fmt
make format-check  # verify formatting
make lint          # clippy with warnings as errors
make test          # run the test suite
make check         # format-check + lint + test + doc
make audit         # cargo-deny (advisories, bans, licenses)
make coverage      # HTML coverage report (needs cargo-llvm-cov)
make hooks         # install the pre-commit git hook
```

Guardrails: `rustfmt` with a pinned config; `clippy` `pedantic` + `nursery`
with warnings as errors and `unsafe` forbidden; `cargo-deny` bans network and
process-spawning crates to enforce the fully-local design; tests are written
alongside the code they cover and a pre-commit hook runs the whole `make check`
suite.

## Project layout

```text
crates/
  codehelion-cli/            command-line interface, config, reporters
  codehelion-core/           discovery, clone engine, fingerprints, doctor
  codehelion-store/          SQLite audit store (snapshots, baselines)
  codehelion-frontend-rust/  build-free Rust lexer frontend
  codehelion-frontend-c/     build-free C lexer frontend
  codehelion-frontend-cpp/   build-free C++ lexer frontend
  codehelion-eval/           accuracy-evaluation harness (internal)
corpus/                      labeled evaluation corpus (see corpus/README.md)
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
