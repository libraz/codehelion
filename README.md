# codehelion

[![CI](https://github.com/libraz/codehelion/actions/workflows/ci.yml/badge.svg)](https://github.com/libraz/codehelion/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/codehelion.svg)](https://crates.io/crates/codehelion)
[![codecov](https://codecov.io/gh/libraz/codehelion/branch/main/graph/badge.svg)](https://codecov.io/gh/libraz/codehelion)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)

A fully local command-line tool that audits Rust, C and C++ codebases for
duplicate logic. It never sends
your source or results anywhere, needs no network access, and does not execute
the code it analyses by default.

The tool provides two build-free analysis modes and an optional compiler-assisted
mode. **Fast** is
token-level Type-1 (identical) and Type-2 (renamed identifiers / changed
literals) detection that scans hundreds of thousands of lines in seconds and
millions in a couple of minutes.
Comments and whitespace are excluded before clone comparison, so comment-only
edits do not make otherwise identical code different findings.
**Structural** adds syntax-structural Type-3 detection — clones that differ by
added, removed or changed statements — and reports the per-dimension similarity
each finding was judged on. **Semantic** uses separately installed Rust and
Clang helpers to include compiler-resolved type and name information without
linking compiler APIs into the main CLI. The optional `artifact` commands read
WASM, ELF, Mach-O, PE/COFF and static archives locally to report observed size,
duplicate code/data, retained-size and source-location evidence. They never
load or execute the inspected artifact.

## Highlights

- **Build-free scanning** — an error-tolerant lexer processes Rust, C and C++
  sources directly; no compiler, build system or `compile_commands.json` needed.
- **Optional compiler-assisted scanning** — Semantic mode runs Rust and Clang
  helpers as separate processes and records exactly which files they could not
  answer for. By default it does not run a project's build scripts or other
  executable build inputs; each allowed execution class is an explicit CLI flag.
- **Stable finding IDs** — findings are identified by content fingerprints, not
  line numbers, so unrelated edits do not change their identity.
- **Evidence, not a single score** — a gapped clone reports lexical,
  structural, control-flow, type and API similarity separately; a dimension the
  mode cannot measure is reported as absent rather than guessed.
- **Local current-scan storage** — the latest scan is stored in SQLite; text,
  JSON and SARIF reports are exports from that current snapshot. A scan
  replaces the one before it, so there is no history to page through and no
  lineage between scans; a baseline is what carries one scan forward for a
  later one to measure itself against.
- **Local artifact inspection** — `artifact analyze` and `artifact compare`
  read supported binary formats without running them. Debug companions are
  accepted only after the matching ELF build ID, Mach-O UUID or PE CodeView/PDB
  identity has been verified.
- **Separated priority measures** — findings are ordered by clone confidence,
  maintenance risk and refactoring difficulty reported side by side, never by
  one opaque score, and every measure shows the inputs it was derived from.
- **Deterministic output** — the same input produces byte-identical reports.
- **Visible limits** — every resource ceiling that fires (file size, parse
  timeout, candidate budget) is counted in the report, never silently applied.
  On a tree large enough for the candidate budget to stop the search, the
  report says how many pairs it left unexamined rather than presenting a
  partial answer as a complete one.
- **A maintainability measure, not a size one** — a finding names code a reader
  has to keep in step, not bytes a compiler emits. Optimisers routinely fold
  identical code that is still duplicated in the source, so removing a reported
  clone need not make the built artifact any smaller.

## Installation

```sh
# From a checkout (crates.io, PyPI and Homebrew packages are planned):
cargo install --path crates/codehelion-cli
```

The result is a single self-contained binary; SQLite is bundled.

Semantic scanning additionally needs the helper for each language you want to
analyse. Install the helpers onto `PATH`, then use `doctor` to confirm their
protocol and compiler availability:

```sh
cargo install --path crates/codehelion-backend-rust
cargo install --path crates/codehelion-backend-clang # also needs a system libclang
codehelion doctor
```

## Usage

```sh
codehelion scan               # scan the current directory, text report
codehelion scan --mode structural           # also detect gapped (Type-3) clones
codehelion scan --mode semantic             # compare on what a compiler resolved (needs a helper)
codehelion scan --format json --output report.json path/to/repo
codehelion scan --format sarif --output report.sarif   # SARIF 2.1.0 log
codehelion scan --verbose     # list every clone group and member
codehelion scan --untrusted   # read a tree nobody vouches for under lowered ceilings
codehelion explain <ID>       # show a finding from the local database
codehelion baseline           # manage accepted-findings baselines
codehelion cache status       # local-database location and size
codehelion config init        # write a commented codehelion.toml template
codehelion doctor             # report available analysis components
codehelion artifact analyze path/to/binary
codehelion artifact compare before/binary after/binary
```

Artifact inspection parses local bytes and never executes the inspected
program. It rejects inputs above 512 MiB by default, runs parsing in a worker
with a 30-second deadline, and accepts `--max-bytes` and `--timeout-seconds`
when a deliberate adjustment is needed. On Linux,
`--max-memory-bytes <bytes>` also enforces a worker virtual-memory ceiling;
other platforms reject that option rather than silently ignoring it.

Findings are grouped into clone groups; each group and member carries a stable
ID you can suppress, baseline or look up later with `explain`.

Once a finding is accepted, `codehelion baseline create` freezes it and later
scans hide it. Because the database holds one scan at a time, a baseline is
also how a before and an after are compared:

```sh
codehelion scan                       # read the tree
codehelion baseline create .          # record where you are starting from
# ... remove some duplication ...
codehelion scan --baseline codehelion-baseline.json --baseline-mode compare
```

`compare` hides nothing. It reports each group as one the baseline froze or one
it did not, and puts the tokens that went beside the tokens that arrived —
without both, four large duplications resolved into twenty small ones reads as
a regression. Removing a duplication also rewrites the code around it, so the
groups that come out of the rearrangement carry new ids; one standing in the
places an entry has just left is reported as standing there rather than as
duplication somebody added.

If the build variant or detector versions differ, create a fresh baseline for
the current scan rather than carrying it across.

## Configuration

`codehelion scan` reads an optional `codehelion.toml` from the scan root.
`codehelion config init` writes a fully commented template; the main knobs:

```toml
# min-clone-tokens = 20             # smallest clone reported, in tokens
# literal-normalization = "full"    # "preserve", "category" or "full"
# database = ".codehelion/audit.db" # local-database location

[languages]
# headers = "detect"                # grammar for a bare ".h": "detect", "c", "cpp"

[priority]                          # whole numbers, read as shares
# maintenance-risk = 2              # only the composition is settable; what a
# refactoring-ease = 1              # duplication costs is a question about the code

[suppression]
# paths = []                        # path globs to hide
# vendored-paths = [...]            # trees the project vendors rather than
                                    # writes, hidden by default; set to [] to
                                    # read them, or pass --include-vendored
# symbols = []                      # globs over the name of the enclosing unit
# clone-ids = []                    # stable clone ids (hex, prefix allowed)
# generated-markers = ["@generated", "do not edit", "automatically generated"]
                                    # banners flagging machine output, matched
                                    # without regard to case; replaces defaults

[limits]                            # resource ceilings, all reported when hit
# max-file-bytes = 2097152
# parse-timeout-ms = 10000
# helper-timeout-ms = 300000       # Semantic helper response deadline
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
  codehelion-store/          SQLite current-scan store (snapshots, baselines)
  codehelion-frontend-rust/  build-free Rust lexer frontend
  codehelion-frontend-c/     build-free C lexer frontend
  codehelion-frontend-cpp/   build-free C++ lexer frontend
  codehelion-eval/           accuracy-evaluation harness (internal)
corpus/                      labeled evaluation corpus (see corpus/README.md)
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
