# codehelion

[![CI](https://github.com/libraz/codehelion/actions/workflows/ci.yml/badge.svg)](https://github.com/libraz/codehelion/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/codehelion.svg)](https://crates.io/crates/codehelion)
[![codecov](https://codecov.io/gh/libraz/codehelion/branch/main/graph/badge.svg)](https://codecov.io/gh/libraz/codehelion)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)

A fully local command-line tool that audits Rust, C and C++ codebases for
duplicate logic (Type-1 through Type-3 clones) and compiled-artifact bloat, and
tracks how those findings change over time. It never sends your source or
results anywhere and needs no network access by default.

> Early development. The source-clone engine is being built out; today the CLI
> ships the `doctor` diagnostic. Optional compiler and artifact backends arrive
> in later releases.

## Installation

```sh
cargo install codehelion   # installs the `codehelion` command
# or, from a checkout:
cargo install --path .
```

## Usage

```sh
codehelion doctor   # report which analysis components are available
codehelion --help
```

## Development

The project ships with a full set of guardrails. Common tasks are wrapped in the
`Makefile`:

```sh
make format        # auto-fix: clippy --fix + cargo fmt
make format-check  # verify formatting (CI parity)
make lint          # clippy with warnings as errors
make test          # run the test suite
make check         # format-check + lint + test + doc
make audit         # cargo-deny (advisories, bans, licenses)
make coverage      # HTML coverage report (needs cargo-llvm-cov)
make hooks         # install the pre-commit git hook
```

### Guardrails

- **Formatting** — `rustfmt` with a pinned config.
- **Linting** — `clippy` with `pedantic` + `nursery` groups, plus denies on
  `unwrap`/`expect`/`panic`/`todo` in production code. `unsafe` is forbidden.
- **Tests** — unit tests next to the code and end-to-end tests that run the
  compiled binary. Tests are written alongside the code they cover.
- **Supply chain** — `cargo-deny` gates advisories, license policy and
  duplicate dependencies.
- **CI** — formatting, clippy, docs, tests on Linux/macOS/Windows, an MSRV
  build and coverage.
- **pre-commit hook** — blocks commits that fail fmt/clippy/test.

## Project layout

```text
src/
  main.rs      thin binary entry point
  lib.rs       command dispatch (unit-testable)
  cli.rs       clap command definitions
  core/        engine layer (in-crate stand-in for the future codehelion-core)
    doctor.rs  environment diagnostics
tests/
  cli.rs       end-to-end tests against the built binary
  fixtures/    small inputs for unit and integration tests
corpus/        evaluation corpus for detector accuracy (see corpus/README.md)
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
