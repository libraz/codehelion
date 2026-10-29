# codehelion

[![CI](https://img.shields.io/github/actions/workflow/status/libraz/codehelion/ci.yml?branch=main&label=CI)](https://github.com/libraz/codehelion/actions)
[![crates.io](https://img.shields.io/crates/v/codehelion.svg)](https://crates.io/crates/codehelion)
[![codecov](https://codecov.io/gh/libraz/codehelion/branch/main/graph/badge.svg)](https://codecov.io/gh/libraz/codehelion)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/libraz/codehelion/blob/main/LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.98%2B-orange?logo=rust)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](https://github.com/libraz/codehelion)

**codehelion finds duplicated logic in Rust, C and C++, and keeps tracking the same duplication from one scan to the next.** It reads sources as they are, with no build, no compilation database and no network, and names every finding by an identifier derived from its content, so a decision you made about a duplicate stays attached to it through unrelated edits. Nothing leaves the machine, and the tool does not run the code it reads.

**Reach for it when you need to:**

- **Scan a tree you cannot easily build** — mixed Rust, C and C++, vendored code or a half-finished port, read by one error-tolerant lexer with no compiler.
- **Pay down duplication over months** — record where you start in a baseline, suppress what you decided to keep, and see what each later scan adds.
- **Stop new copies in CI** — fail on duplication the baseline does not carry, not on a percentage, and upload SARIF to a code-scanning view.
- **Keep paired files in step** — declare a seam such as two frontends or an en/ja document pair, and `guard` reports a change that touched one side only.
- **Explain why a binary or WASM module grew** — split its code bytes between your code and the toolchain, total template bodies under one name stem, and compare two builds.

📖 **[Documentation](https://github.com/libraz/codehelion/blob/main/docs/en/introduction.md)** &nbsp;·&nbsp; **[Getting started](https://github.com/libraz/codehelion/blob/main/docs/en/getting-started.md)** &nbsp;·&nbsp; **[Limitations](https://github.com/libraz/codehelion/blob/main/docs/en/limitations.md)**

> codehelion is pre-1.0. Fast and Structural scanning, the text and JSON reports and `artifact analyze` are settled; the rest can change between releases ([Maturity](https://github.com/libraz/codehelion/blob/main/docs/en/introduction.md#maturity)). Report security issues through [SECURITY.md](https://github.com/libraz/codehelion/blob/main/SECURITY.md).

## What a report looks like

Structural mode, run against codehelion's own tree, showing the first two groups:

```text
codehelion scan · structural mode · ~/src/codehelion

 #1  0.56  type-1 ×2      109 tokens  64f5bc34
     ├─ ◆ corpus/synthetic/rust/seed.rs:30-49                   values_equal
     └─   corpus/synthetic/rust/type1.rs:35-54                  values_equal

 #2  0.54  type-1 run ×2  106 tokens  53c92308
     ├─ ◆ crates/codehelion-cli/src/scan/structural.rs:159-171  run_with
     └─   crates/codehelion-cli/src/scan.rs:61-73               run

... and 1305 more groups (--limit 0 lists every one)

seams: frontend-c-cpp 12 asymmetric changes, 7 breaches (last 6e014d86), 394 findings
       readme-en-ja 1 asymmetric change, 1 breach (last 634aa5c9)
       artifact-fixture-scripts 3 asymmetric changes, 1 breach (last 6f5d63c3)

1,702 groups (type-1 85, type-2 204, type-3 1413) · 395 suppressed · sorted by priority
supplemental: 556 siblings (--show-siblings; 116 dropped by search ceilings), 1,000 near misses (--show-near-misses; 6,746 dropped by the retention cap)
569 files, 220,783 lines, 1,167,009 tokens · run 12 (replay: codehelion report --run 12)
◆ the occurrence a group is measured against · "run" a repeated stretch of statements, not a whole unit · ×N the number of occurrences
open one: codehelion explain 64f5bc34 · list every group: --limit 0
```

Every field is explained in [Reading a report](https://github.com/libraz/codehelion/blob/main/docs/en/reading-a-report.md).

## What's inside

- **Build-free scanning** — an error-tolerant lexer reads Rust, C and C++ directly, so a mixed-language tree is scanned once on one basis; Semantic mode adds compiler evidence through separate helpers. [Analysis modes](https://github.com/libraz/codehelion/blob/main/docs/en/analysis-modes.md)
- **Stable finding IDs** — content fingerprints rather than line numbers, so the same input gives the same IDs in the same order and suppressions and baselines hold across refactors. [Stable identifiers](https://github.com/libraz/codehelion/blob/main/docs/en/stable-ids.md) · [Baselines](https://github.com/libraz/codehelion/blob/main/docs/en/baselines.md) · [Suppression](https://github.com/libraz/codehelion/blob/main/docs/en/suppression.md)
- **Evidence, not one score** — lexical, structural, control-flow, type and API similarity reported separately, with a measure the mode cannot take shown as absent. [Reading a report](https://github.com/libraz/codehelion/blob/main/docs/en/reading-a-report.md) · [Clone types](https://github.com/libraz/codehelion/blob/main/docs/en/clone-types.md)
- **An ordered report** — on eight labelled snapshots of real projects nothing false reaches the first ten findings (p@10 1.0000, MAP 0.9290); read end to end, precision is 0.5920. [Accuracy](https://github.com/libraz/codehelion/blob/main/docs/en/accuracy.md)
- **Seams and CI gates** — `guard` checks files that must change together, and `scan --fail-on-findings` gates on what a change added. [Seam tracking](https://github.com/libraz/codehelion/blob/main/docs/en/seam-tracking.md) · [Continuous integration](https://github.com/libraz/codehelion/blob/main/docs/en/continuous-integration.md)
- **Artifact size** — WASM, ELF, Mach-O and PE/COFF read without running them: code bytes by owner, the functions that keep toolchain code linked in, name stems, compressed size, and a comparison of two builds. [Artifact analysis](https://github.com/libraz/codehelion/blob/main/docs/en/artifact-analysis.md)
- **Local by construction** — no network and no execution of the scanned tree, enforced by lints and dependency policy, and every resource ceiling that fires is counted in the report. [Local execution and trust](https://github.com/libraz/codehelion/blob/main/docs/en/security.md)

## Installation

Every [release](https://github.com/libraz/codehelion/releases) attaches a prebuilt, self-contained `codehelion` binary with SQLite bundled, and `SHA256SUMS` beside it.

| platform | archive |
|---|---|
| Linux x86-64 | `codehelion-<version>-linux-x86_64.tar.gz` |
| Linux ARM64 | `codehelion-<version>-linux-aarch64.tar.gz` |
| macOS Apple silicon | `codehelion-<version>-macos-aarch64.tar.gz` |
| Windows x86-64 | `codehelion-<version>-windows-x86_64.zip` |

```bash
cargo install codehelion   # from source; requires Rust 1.98 or newer
```

Semantic mode also needs a helper per language. See [Getting started](https://github.com/libraz/codehelion/blob/main/docs/en/getting-started.md) for the helpers and `codehelion doctor`.

## Quick start

```bash
codehelion scan --mode structural     # read the tree, report the duplication
codehelion explain 64f5bc34           # open one group
codehelion artifact analyze app.wasm  # where the bytes of a build go
```

→ [Getting started](https://github.com/libraz/codehelion/blob/main/docs/en/getting-started.md) · [The command line](https://github.com/libraz/codehelion/blob/main/docs/en/cli.md)

## Build from source

```bash
make check   # format-check + lint + boundary checks + test + doc
make eval    # detection accuracy over the corpora
```

`make help` lists the rest. Conventions and guardrails are in [CONTRIBUTING.md](https://github.com/libraz/codehelion/blob/main/CONTRIBUTING.md).

## Documentation

- **Learn** — [Introduction](https://github.com/libraz/codehelion/blob/main/docs/en/introduction.md) · [Getting started](https://github.com/libraz/codehelion/blob/main/docs/en/getting-started.md) · [Analysis modes](https://github.com/libraz/codehelion/blob/main/docs/en/analysis-modes.md) · [Glossary](https://github.com/libraz/codehelion/blob/main/docs/en/glossary.md)
- **Reading the output** — [Reading a report](https://github.com/libraz/codehelion/blob/main/docs/en/reading-a-report.md) · [Clone types](https://github.com/libraz/codehelion/blob/main/docs/en/clone-types.md) · [Grouping](https://github.com/libraz/codehelion/blob/main/docs/en/grouping.md) · [Stable identifiers](https://github.com/libraz/codehelion/blob/main/docs/en/stable-ids.md)
- **Using it on a project** — [The refactoring loop](https://github.com/libraz/codehelion/blob/main/docs/en/refactoring-workflow.md) · [Baselines](https://github.com/libraz/codehelion/blob/main/docs/en/baselines.md) · [Suppression](https://github.com/libraz/codehelion/blob/main/docs/en/suppression.md) · [Configuration](https://github.com/libraz/codehelion/blob/main/docs/en/configuration.md) · [Seam tracking](https://github.com/libraz/codehelion/blob/main/docs/en/seam-tracking.md) · [Continuous integration](https://github.com/libraz/codehelion/blob/main/docs/en/continuous-integration.md) · [The command line](https://github.com/libraz/codehelion/blob/main/docs/en/cli.md)
- **Artifacts** — [Artifact analysis](https://github.com/libraz/codehelion/blob/main/docs/en/artifact-analysis.md) · [Calibration](https://github.com/libraz/codehelion/blob/main/docs/en/calibration.md)
- **Details** — [Limitations](https://github.com/libraz/codehelion/blob/main/docs/en/limitations.md) · [Accuracy](https://github.com/libraz/codehelion/blob/main/docs/en/accuracy.md) · [Local execution and trust](https://github.com/libraz/codehelion/blob/main/docs/en/security.md) · [Architecture](https://github.com/libraz/codehelion/blob/main/docs/en/architecture.md)

## Non-goals

codehelion measures maintainability, not size: removing a reported clone need not make the built artifact smaller. It does not claim to find every copy, prove semantic equivalence, check coding style or vulnerabilities, or refactor code for you, and it has no GUI or hosted service. See [Limitations](https://github.com/libraz/codehelion/blob/main/docs/en/limitations.md).

## License

[Apache-2.0](https://github.com/libraz/codehelion/blob/main/LICENSE)
