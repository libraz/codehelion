# codehelion

[![CI](https://img.shields.io/github/actions/workflow/status/libraz/codehelion/ci.yml?branch=main&label=CI)](https://github.com/libraz/codehelion/actions)
[![crates.io](https://img.shields.io/crates/v/codehelion-cli.svg)](https://crates.io/crates/codehelion-cli)
[![codecov](https://codecov.io/gh/libraz/codehelion/branch/main/graph/badge.svg)](https://codecov.io/gh/libraz/codehelion)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/libraz/codehelion/blob/main/LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.85%2B-orange?logo=rust)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](https://github.com/libraz/codehelion)

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

There are two build-free analysis modes and an optional compiler-assisted one.
**Fast** is token-level Type-1 (identical) and Type-2 (renamed identifiers,
changed literals) detection; comments and whitespace are removed before
comparison, so a comment-only edit does not split one finding into two.
**Structural** adds Type-3 detection — copies that differ by added, removed or
changed statements — and reports the per-dimension similarity each finding was
judged on. **Semantic** runs separately installed Rust and Clang helpers to
bring in compiler-resolved type and name information, without linking compiler
APIs into the CLI.

codehelion is pre-1.0. The command-line surface, the report formats and the
on-disk database layout can change between releases.

## What a report looks like

Structural mode, run against codehelion's own tree:

```text
codehelion scan (structural mode)
  root: ~/src/codehelion
  configuration: defaults; minimum clone length: 20 tokens
  files: 356 analysed (rust 326, c 4, cpp 26)
  lines: 127217; tokens: 673647; lexer diagnostics: 0
  clone groups: 944 (type-1 67, type-2 118, type-3 759, restricted-semantic 0; suppressed: 0 noise, 118 by rule)
    642 of them are duplication inside test code, which repeats itself by design; a group spanning a test and what it exercises is not counted here
  note: candidate search was truncated by high frequency, high frequency postings; duplication the tree contains may be missing from this report

top groups by priority:
  eefc3057233358cde7b44e1c33a36844 type-1 priority 0.62 identifiers 0.95 [within one file]
    confidence 0.82, maintenance risk 0.36, refactoring difficulty 0.17 (2 instances, 188-188 tokens, 188 repeated, 1.00 similarity, 1 file(s))
    similarity: composite 1.00 (lexical 1.00, structural 1.00, control-flow 1.00, type n/a, api 1.00); cohesion 1.00; confidence high [structural-verify-v3]
    crates/codehelion-cli/src/scan/structural/reporting.rs:758-779 [no enclosing unit] [canonical] [finding 945224c9097e2c3baab35a706cdc59e7]
    crates/codehelion-cli/src/scan/structural/reporting.rs:657-678 [no enclosing unit] [finding 7d1268463bd34f9a08ef27fbcda724b0]
```

Three things in that output are the point of the tool. The `note:` line says a
ceiling fired, so the report is not claiming to be complete. The `similarity:`
line shows the dimensions the verdict was composed from, including the one this
mode cannot measure. And each `finding` identifier goes straight into
`codehelion explain <ID>`, a suppression rule or a baseline.

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
  timeout, candidate budget) is counted in the report. On a tree large enough
  for the candidate budget to stop the search, the report says how many pairs it
  left unexamined rather than presenting a partial answer as a complete one.
- **Local by construction** — the ban on network access and on executing the
  scanned tree is enforced by lints and dependency policy, not by convention:
  `clippy.toml` disallows process spawning and sockets in the scan path, and
  `cargo-deny` refuses the common HTTP stacks outright.

## Installation

```sh
cargo install --path crates/codehelion-cli
```

The result is a single self-contained binary; SQLite is bundled. Installing
from a checkout is currently the only supported route.

The CLI and every non-semantic component require Rust 1.85 or newer. The
optional Rust semantic helper has a separate Rust 1.95-or-newer build
requirement; its higher toolchain need does not change the CLI's MSRV.

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
codehelion report             # render the latest completed scan again
codehelion report --run 1     # render a particular recorded scan again
codehelion explain <ID>       # show a finding from the local database
codehelion explain <ID> --format json
codehelion baseline create    # freeze the latest findings as a baseline
codehelion cache status       # local-database location and size
codehelion cache clear --force # permanently delete the local audit database
codehelion config init        # write a commented codehelion.toml template
codehelion config show        # print the effective configuration
codehelion doctor             # report available analysis components
```

The main scan controls are:

- `--config <file>` and `--db <path>` choose the configuration and local database.
- `--jobs <n>` sets frontend read-and-lex workers (capped at four times host parallelism); clone grouping and report rendering remain serial. `--no-ignore` also reads ignored files.
- `--baseline <file>` compares with accepted findings; `--show-suppressed`, `--show-siblings`, and `--show-near-misses` expand text output. JSON and SARIF retain those data regardless.
- `--include-trivial` restores predicate families to their measured priority in Structural and Semantic mode.
- `--fail-on-findings` returns exit code 3 when visible findings remain.
- `--compare-build-variants` and `--compare-languages` request separate Semantic comparisons; they never merge ordinary scan partitions.
- `--allow-execution=build-script` is the explicit, opt-in permission for a Semantic helper to run a project build script. Nothing in the scanned tree executes without it; `--untrusted` permits no execution.
- `cache clear --force` permanently removes the local audit database; it always requires the explicit confirmation flag.

### Exit status

- `0`: command completed successfully.
- `1`: an operational error prevented completion.
- `2`: command-line usage was invalid.
- `3`: `scan --fail-on-findings` found one or more visible findings.

### Ordering a report

Reports come out ordered by the composed priority, which weighs several
measures against one another. When the job in front of you is one of those
measures, order on it instead:

```sh
codehelion scan --sort duplicated-tokens    # the most repeated code first
codehelion scan --sort instances            # the most widely copied first
codehelion scan --mode structural --sort identifier-jaccard # the most alike by name first
```

For maintainability work, `--sort identifier-jaccard` with a floor is usually
the shortest path to something worth unifying: copies that still agree on their
identifiers are copies nobody has diverged yet, and those are the ones a single
shared function can still replace.

```sh
codehelion scan --mode structural --sort identifier-jaccard --min-identifier-jaccard 0.7
```

The floor is a view over the same findings — it decides what the text listing
shows, and changes no count, no export and nothing recorded. Raw identifier
agreement is measured on whole units, so a run that reports fragments has no
value to compare and the report says how many entries that left out.

### Baselines

Findings are grouped into clone groups; each group and member carries a stable
ID you can suppress, baseline or look up later with `explain`. The default text
report prints each listed member as `[finding <ID>]`, so the identifier is ready
to paste into `codehelion explain <ID>`.

Once a finding is accepted, `codehelion baseline create` freezes it and later
scans hide it. A baseline is the explicit before-and-after comparison a team
can keep alongside the retained local scan history:

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

## Artifact inspection (optional)

The `artifact` commands read WASM, ELF, Mach-O, PE/COFF and static archives
locally to report observed size, duplicate code and data, retained size and
source-location evidence. They parse bytes; they never load or execute the
inspected artifact.

```sh
codehelion artifact analyze path/to/binary
codehelion artifact report              # render the latest saved analysis
codehelion artifact report --analysis 1 # render a particular saved analysis
codehelion artifact compare before/binary after/binary
codehelion artifact calibration                 # summarize the latest completed source scan
codehelion artifact calibration --source-run 1  # summarize a particular source scan
```

Debug companions are accepted only after the matching ELF build ID, Mach-O UUID
or PE CodeView/PDB identity has been verified. `artifact analyze --debug-file companion`
can inspect a native debug companion without a source scan; add
`--source-run` and `--build-variant` only when requesting source-artifact
correlation. When an artifact command receives `--build-variant manifest.json`, its identity uses the canonical JSON value, so whitespace and object-member ordering do not change the build variant.

Artifact operations reject inputs above 512 MiB by default and run parsing,
correlation, persistence, and rendering in a worker with one 30-second
deadline. Timeout diagnostics name the phase that was running; `--max-bytes`
and `--timeout-seconds` adjust the limits. On Linux,
`--max-memory-bytes <bytes>` also enforces a worker virtual-memory ceiling;
other platforms reject that option rather than silently ignoring it. The
versioned IR retained for `artifact report` is separately capped at 64 MiB, and
an analysis whose persisted details exceed that limit fails without writing a
partial database record.

## Configuration

`codehelion scan` reads an optional `codehelion.toml` from the scan root.
`codehelion config init` writes a fully commented template; the main knobs:

```toml
# min-clone-tokens = 20             # smallest clone reported, in tokens
# literal-normalization = "full"    # "preserve", "category" or "full"
# database = ".codehelion/audit.db" # local-database location
# jobs = 4                           # frontend read-and-lex workers (capped at 4× host parallelism); grouping/reporting stay serial

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
# clone-ids = []                    # stable clone ids (hex; prefixes need at least 8 characters)
# generated-markers = ["@generated", "do not edit", "automatically generated", "auto-generated", "autogenerated"]
                                    # banners flagging machine output, matched
                                    # without regard to case; replaces defaults
# split-pairs = "rank-down"        # verified pairs that no complete clone group
                                    # can hold; reported below complete groups
# width-family = "hide"            # one routine per integer width; set to
                                    # "report" where it can be unified

[limits]                            # resource ceilings, all reported when hit
# max-file-bytes = 2097152
# parse-timeout-ms = 10000          # deterministic parse-work budget, not wall-clock time
# helper-timeout-ms = 300000       # Semantic helper response deadline
# posting-cap = 64                  # unset: each mode keeps its own default
# pair-budget = 1000000             # per pairing pass, not shared between them
# near-miss-delta = 0.05            # Structural diagnostic band below the Type-3 gate
# near-miss-cap = 1000              # retained diagnostic near misses per report
# sibling-candidate-budget = 50000  # post-grouping Structural sibling comparisons
# sibling-per-group-cap = 8         # retained incomplete mirrors per primary group
# sibling-total-cap = 1000          # retained incomplete mirrors per report
# verification-budget = 1000000     # Structural pairs sent to precise verification
# max-alignment-cells = 4000000     # dynamic-programming cells per Structural alignment
# max-component = 1024
```

split-pairs controls verified pairs that cannot belong to the same complete
clone group; they remain visible by default, below complete groups. width-family
controls routines that differ only by integer width and is hidden by default.
Set it to "report" when a macro, generic, or template could express the family
once. Structural and Semantic scans apply these classifications; Fast scans say
explicitly when they are unavailable.

Completed scans are stored in local SQLite, and text, JSON and SARIF reports
are exports from those snapshots. An unchanged tree reuses its compatible
completed run; `--no-reuse` records a fresh run. When a group changes identity
but retains enough member content, its stored lineage links the two runs. A
baseline remains the explicit record of findings a project has accepted.

Each scan creates its persistent local audit database at
`.codehelion/audit.db` by default, placed under the Git repository holding the
scan root so that scanning a subdirectory reuses the repository's database
rather than starting a new one; a scan root outside any repository holds its
own. `--db <path>` overrides the location. Add `.codehelion/` to the
repository's `.gitignore`; this database is not an expendable build cache.

`codehelion.toml`, in contrast, is read only from the scan root itself and is
never inherited from a parent directory: a scan says which settings governed it
and where they came from, and a file nobody named that sits above the tree
being read is not that.

`.h` is the one extension C and C++ share, and the grammar it is read with
decides what the analysis can see inside it: a C++ header read as C recovers
into shapes that declare nothing, which both hides its real duplication and
invents duplication between class bodies. `detect` counts the files whose
extension is not in doubt and follows the majority; where a tree has none —
a header-only library — it reads the headers themselves for something only C++
spells, and one of them saying so settles the run. The choice is part of the
run's build variant, so results read one way are never compared with results
read the other.

## Limitations

**A finding measures maintainability, not size.** It names code a reader has to
keep in step, not bytes a compiler emits. Optimisers routinely fold identical
code that is still duplicated in the source, so removing a reported clone need
not make the built artifact any smaller.

**Fast mode reports more than you want to read.** The suppression policies for
boilerplate, test code and integer-width families need structural
classifications, so Fast mode cannot apply them and says so in the report. On a
tree of any size, `--mode structural` is what produces a list worth reading
top-down.

**Incomplete or edited copies are harder to detect.** codehelion is not a
mirror-consistency checker: the Structural detector can miss an otherwise
similar mirror when it diverges enough not to become a candidate.

**Large trees hit ceilings.** The candidate budget and the high-frequency
posting cap bound the search, and a run that hits either reports how much it
left unexamined. The index is held in memory, so a very large tree is bounded
by the ceilings rather than by disk.

**Artifact inspection depends on symbols.** A stripped binary yields almost
nothing; supply the unstripped build or a verified debug companion. Duplicate
detection that sees past register and immediate differences is implemented for
x86 only — on other architectures, only byte-identical duplicates are found.

**The audit database is not migrated.** A database written under a different
schema is rejected rather than converted; move it aside and rescan. This will
change before 1.0.

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
with warnings as errors and `unsafe` forbidden; `cargo-deny` checks dependency
advisories, bans and licences; `clippy.toml` disallows process spawning and
network sockets in the scan path. Tests are written alongside the code they
cover and a pre-commit hook runs the whole `make check` suite.

Detection accuracy is measured against the corpora in `corpus/`, which record
hand-written verdicts on real projects rather than the projects themselves; see
`corpus/README.md` for what each half can and cannot answer.

The protocol handshake cases live in `codehelion-helper-conformance/`; they
exercise the independently built helpers rather than treating their wire format
as an auto-generated or autogenerated implementation detail.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a security issue, follow
[SECURITY.md](SECURITY.md) rather than opening a public issue.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
