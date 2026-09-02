# Getting started

## Install

Every [release](https://github.com/libraz/codehelion/releases) attaches a
prebuilt binary, which is the shortest route: download, unpack, run. The archive
holds one self-contained executable named `codehelion`; SQLite is bundled.

| platform | archive |
|---|---|
| Linux x86-64 | `codehelion-<version>-linux-x86_64.tar.gz` |
| Linux ARM64 | `codehelion-<version>-linux-aarch64.tar.gz` |
| macOS Apple silicon | `codehelion-<version>-macos-aarch64.tar.gz` |
| Windows x86-64 | `codehelion-<version>-windows-x86_64.zip` |

`SHA256SUMS` is attached beside them, so an archive can be verified before it is
unpacked.

With a Rust toolchain, the same binary can be built from source:

```sh
cargo install codehelion
```

Or from a checkout:

```sh
cargo install --path crates/codehelion-cli
```

Building requires Rust 1.98 or newer, the optional Rust semantic helper
included. The analysis libraries that helper is built on set the floor, and it
is one floor rather than one per component. A downloaded binary needs no
toolchain at all.

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

 #1  0.56  type-1 ×2      109 tokens  b92c1297
     ├─ ◆ corpus/synthetic/rust/seed.rs:30-49                   values_equal
     └─   corpus/synthetic/rust/type1.rs:35-54                  values_equal

 #2  0.53  type-1 run ×2  101 tokens  5d7e5cd2
     ├─ ◆ crates/codehelion-cli/src/scan/structural.rs:177-183  run_with
     └─   crates/codehelion-cli/src/scan.rs:62-68               run

... and 1184 more groups (--limit 0 lists every one)

1,538 groups (type-1 78, type-2 198, type-3 1262) · 352 suppressed · sorted by priority
supplemental: 492 siblings (--show-siblings; 60 dropped by search ceilings), 1,000 near misses (--show-near-misses; 5,633 dropped by the retention cap)
553 files, 199,546 lines, 1,042,197 tokens · run 9 (0 file(s) changed; replay: codehelion report --run 9)
◆ the occurrence a group is measured against · "run" a repeated stretch of statements, not a whole unit · ×N the number of occurrences
open one: codehelion explain b92c1297 · list every group: --limit 0
```

Every field in that heading is explained in [Reading a report](reading-a-report.md).
The short hexadecimal string that closes it is the group's stable id, and it is
the shortest prefix `codehelion explain` accepts:

```sh
codehelion explain b92c1297
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
