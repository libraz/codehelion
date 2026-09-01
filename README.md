# codehelion

[![CI](https://img.shields.io/github/actions/workflow/status/libraz/codehelion/ci.yml?branch=main&label=CI)](https://github.com/libraz/codehelion/actions)
[![crates.io](https://img.shields.io/crates/v/codehelion.svg)](https://crates.io/crates/codehelion)
[![codecov](https://codecov.io/gh/libraz/codehelion/branch/main/graph/badge.svg)](https://codecov.io/gh/libraz/codehelion)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/libraz/codehelion/blob/main/LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.98%2B-orange?logo=rust)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](https://github.com/libraz/codehelion)
[![docs](https://img.shields.io/badge/docs-guides-0a5ca8)](docs/en/introduction.md)

Find duplicated logic in Rust, C and C++ — and keep finding the same duplication
across scans.

codehelion reads sources directly: no build, no compilation database, no
network. It detects identical, renamed and gapped copies, judges each one on
several measures it reports side by side, and names every finding by a
content-derived identifier that survives unrelated edits — so duplication you
have already ruled on stays ruled on, and a scan months later can be measured
against the one before it.

Everything runs on the machine you start it on. Sources and results are never
sent anywhere, the tool has no network dependency, and it does not execute the
code it reads unless you pass a flag that permits a specific class of execution.

codehelion is pre-1.0. The command-line surface, the report formats and the
on-disk database layout can change between releases.

## What a report looks like

Structural mode, run against codehelion's own tree, showing the first two
groups:

```text
codehelion scan · structural mode · ~/src/codehelion

 #1  0.67  type-1 ×2  240 tokens  0f5065d5
     ├─ ◆ crates/codehelion-cli/src/scan/store.rs:221-249  tree_changes
     └─   crates/codehelion-cli/src/scan/structural/store.rs:161-189  tree_changes

 #2  0.63  type-1 ×2  192 tokens  cabfd679 [narrower cut of baf4e127]
     ├─ ◆ crates/codehelion-cli/src/scan/structural/reporting.rs:584-605
     └─   crates/codehelion-cli/src/scan/structural/reporting.rs:691-712

... and 1173 more groups (--limit 0 lists every one)

1,511 groups (type-1 86, type-2 196, type-3 1229) · 335 suppressed · sorted by priority
396 files, 190,744 lines, 1,001,215 tokens · run 1 (replay: codehelion report --run 1)
◆ the occurrence a group is measured against · ×N the number of occurrences
open one: codehelion explain 0f5065d5 · list every group: --limit 0
```

Every field, and what `-v` and `-vv` add:
[Reading a report](docs/en/reading-a-report.md).

## How one scan works

![What one scan does](docs/images/pipeline.svg)

Sources are lexed and normalized, indexed by content, paired into candidates,
verified by alignment, and grouped around a canonical member. The run is
recorded into a local SQLite database, and the text, JSON and SARIF reports are
exports of that record. Every resource ceiling that fires is counted in the
report, so a run that could not finish the search says what it left unexamined.

![What each analysis mode measures](docs/images/modes.svg)

## Highlights

- **Build-free scanning** — an error-tolerant lexer reads Rust, C and C++
  sources directly, so a mixed-language tree is scanned once, on one basis. No
  compiler, build system or `compile_commands.json` is required.
- **Stable finding IDs** — findings are named by content fingerprints, not line
  numbers. The same input always produces the same identifiers and the same
  group order, which is what makes suppressions and baselines hold across
  refactors.
- **Evidence, not a single score** — a gapped clone reports lexical,
  structural, control-flow, type and API similarity separately, and clone
  confidence, maintenance risk and refactoring difficulty side by side. A
  dimension the mode cannot measure is reported as absent rather than guessed.
- **Visible limits** — every resource ceiling that fires (file size, parse
  timeout, candidate budget) is counted in the report.
- **Local by construction** — the ban on network access and on executing the
  scanned tree is enforced by lints and dependency policy, not by convention:
  `clippy.toml` disallows process spawning and sockets in the scan path, and
  `cargo-deny` refuses the common HTTP stacks outright.

## Install

```sh
cargo install codehelion
```

The result is a single self-contained binary named `codehelion`; SQLite is
bundled. Everything here requires Rust 1.98 or newer, the optional Rust semantic
helper included.

```sh
codehelion scan --mode structural     # read the tree, report the duplication
codehelion explain 0f5065d5           # open one group
codehelion report --format json --output report.json
```

Semantic mode additionally needs a helper per language
(`cargo install codehelion-backend-rust`, `codehelion-backend-clang`);
`codehelion doctor` reports what this machine has. Full setup:
[Getting started](docs/en/getting-started.md).

## Documentation

Start here: [Introduction](docs/en/introduction.md),
[Getting started](docs/en/getting-started.md),
[Analysis modes](docs/en/analysis-modes.md).

Reading the output: [Reading a report](docs/en/reading-a-report.md),
[Clone types](docs/en/clone-types.md), [Grouping](docs/en/grouping.md),
[Stable identifiers](docs/en/stable-ids.md), [Glossary](docs/en/glossary.md).

Using it on a project: [The refactoring loop](docs/en/refactoring-workflow.md),
[Baselines](docs/en/baselines.md), [Suppression](docs/en/suppression.md),
[Configuration](docs/en/configuration.md),
[The command line](docs/en/cli.md).

Artifacts: [Artifact analysis](docs/en/artifact-analysis.md),
[Calibration](docs/en/calibration.md).

Before you rely on it: [Limitations](docs/en/limitations.md),
[Accuracy](docs/en/accuracy.md),
[Local execution and trust](docs/en/security.md),
[Architecture](docs/en/architecture.md).

## What it does not claim

A finding measures maintainability, not size: it names code a reader has to keep
in step, not bytes a compiler emits. Optimisers fold identical code that is still
duplicated in the source, and the compressed size of an artifact moves far less
than its uncompressed size does.
[`codehelion artifact analyze`](docs/en/artifact-analysis.md) measures that side
separately. codehelion is not a mirror-consistency checker either: it reports the
duplication it finds without claiming to have found every copy. The whole list is
in [Limitations](docs/en/limitations.md), and the measured precision and recall
are in [Accuracy](docs/en/accuracy.md).

## Development

```sh
make format        # auto-fix: clippy --fix + cargo fmt
make check         # format-check + lint + boundary checks + test + doc
make eval          # detection accuracy over the corpora
```

`make help` lists the rest. Guardrails: `rustfmt` with a pinned config, `clippy`
`pedantic` + `nursery` with warnings as errors, `unsafe` forbidden, `cargo-deny`
over advisories, bans and licences, and two boundary checks that fail if the
clone engine gains a dependency on the artifact reader or a compiler API reaches
the CLI. Tests are written alongside the code they cover.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a security issue, follow
[SECURITY.md](SECURITY.md) rather than opening a public issue.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
