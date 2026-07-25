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
literals) detection that scans hundreds of thousands of lines in seconds.
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
  record.
- **Deterministic output** — the same input produces byte-identical reports.
- **Visible limits** — every resource ceiling that fires (file size, parse
  timeout, candidate budget) is counted in the report, never silently applied.

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
codehelion explain <ID>       # show a finding from the audit database
codehelion baseline           # manage accepted-findings baselines
codehelion config init        # write a commented codehelion.toml template
codehelion doctor             # report available analysis components
```

Findings are grouped into clone groups; each group and member carries a stable
ID you can suppress, baseline or look up later with `explain`.

## Configuration

`codehelion scan` reads an optional `codehelion.toml` from the scan root.
`codehelion config init` writes a fully commented template; the main knobs:

```toml
# min-clone-tokens = 20             # smallest clone reported, in tokens
# literal-normalization = "full"    # "preserve", "category" or "full"
# database = ".codehelion/audit.db" # audit-database location

[suppression]
# paths = []                        # path globs to hide; vendored trees go here
# symbols = []                      # globs over the name of the enclosing unit
# clone-ids = []                    # stable clone ids (hex, prefix allowed)
# generated-markers = ["@generated", "DO NOT EDIT"]

[limits]                            # resource ceilings, all reported when hit
# max-file-bytes = 2097152
# parse-timeout-ms = 10000
# posting-cap = 64
# pair-budget = 1000000
# max-component = 1024
```

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
