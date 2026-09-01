# Getting started

## Install

```sh
cargo install codehelion
```

The result is a single self-contained binary named `codehelion`; SQLite is
bundled. To build from a checkout instead:

```sh
cargo install --path crates/codehelion-cli
```

Everything here requires Rust 1.98 or newer, the optional Rust semantic helper
included. The analysis libraries that helper is built on set the floor, and it
is one floor rather than one per component.

## The first scan

```sh
codehelion scan
```

With no arguments this reads the current directory in Fast mode and prints a
text report. On any tree of real size, run Structural mode instead: it detects
gapped copies, and it is the mode whose suppression policies produce a list
worth reading from the top.

```sh
codehelion scan --mode structural
```

A report opens with what was read, lists the highest-ranked groups, and closes
with the totals:

```text
codehelion scan · structural mode · ~/src/project

 #1  0.67  type-1 ×2  240 tokens  0f5065d5
     ├─ ◆ crates/codehelion-cli/src/scan/store.rs:221-249  tree_changes
     └─   crates/codehelion-cli/src/scan/structural/store.rs:161-189  tree_changes

 #2  0.63  type-1 ×2  192 tokens  cabfd679 [narrower cut of baf4e127]
     ├─ ◆ crates/codehelion-cli/src/scan/structural/reporting.rs:584-605
     └─   crates/codehelion-cli/src/scan/structural/reporting.rs:691-712

... and 1173 more groups (--limit 0 lists every one)

1,511 groups (type-1 86, type-2 196, type-3 1229) · 335 suppressed · sorted by priority
supplemental: 517 siblings (--show-siblings), 1,000 near misses (--show-near-misses)
396 files, 190,744 lines, 1,001,215 tokens · run 1 (replay: codehelion report --run 1)
◆ the occurrence a group is measured against · ×N the number of occurrences
open one: codehelion explain 0f5065d5 · list every group: --limit 0
```

Every field in that heading is explained in [Reading a report](reading-a-report.md).
The short hexadecimal string that closes it is the group's stable id, and it is
the shortest prefix `codehelion explain` accepts:

```sh
codehelion explain 0f5065d5
```

Anything qualifying the run — a ceiling that fired, a rule that matched nothing —
goes to the error stream, so the report on standard output stays pipeable.

## Where the results are kept

Each scan records into a local SQLite database under `.codehelion/` in the Git
repository holding the scan root, so scanning a subdirectory reuses the
repository's database rather than starting a new one. Add `.codehelion/` to the
repository's `.gitignore`.

Because the run is recorded, a report can be rendered again without reading the
tree:

```sh
codehelion report                    # the latest completed scan, again
codehelion report --run 1            # one particular recorded scan
codehelion report --format json --output report.json
```

See [Configuration](configuration.md) for the database's location and lifecycle,
and [The command line](cli.md) for every command and flag.

## Optional: compiler evidence

Semantic mode adds compiler-resolved type and name information. It needs a
separately installed helper for each language you want to analyse, which is what
keeps compiler APIs out of the CLI itself:

```sh
cargo install codehelion-backend-rust
cargo install codehelion-backend-clang # also needs a system libclang
codehelion doctor
```

`doctor` reports which components this machine has, what each helper answered
when asked, and which local database a run would use. A helper that is not
installed is reported as optional and absent; nothing fails because of it.

## Optional: artifact analysis

The `artifact` commands read a compiled artifact's bytes — WASM, ELF, Mach-O,
PE/COFF and static archives — without loading or executing it:

```sh
codehelion artifact analyze path/to/binary
```

Source scanning does not depend on any of it. See
[Artifact analysis](artifact-analysis.md).

## Next

- [Analysis modes](analysis-modes.md) — choosing between Fast, Structural and Semantic.
- [The refactoring loop](refactoring-workflow.md) — what to do with the first report.
- [Suppression](suppression.md) — quieting what a project has decided to keep.
