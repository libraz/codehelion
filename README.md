# codehelion

[![CI](https://img.shields.io/github/actions/workflow/status/libraz/codehelion/ci.yml?branch=main&label=CI)](https://github.com/libraz/codehelion/actions)
[![crates.io](https://img.shields.io/crates/v/codehelion.svg)](https://crates.io/crates/codehelion)
[![codecov](https://codecov.io/gh/libraz/codehelion/branch/main/graph/badge.svg)](https://codecov.io/gh/libraz/codehelion)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/libraz/codehelion/blob/main/LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.98%2B-orange?logo=rust)](https://www.rust-lang.org)
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

Structural mode, run against codehelion's own tree, showing the first three
groups:

```text
codehelion scan · structural mode · ~/src/codehelion

 #1  0.67  type-1 ×2  240 tokens  0f5065d5
     ├─ ◆ crates/codehelion-cli/src/scan/store.rs:177-205       tree_changes
     └─   crates/codehelion-cli/src/scan/structural/store.rs:145-173  tree_changes

 #2  0.62  type-1 ×2  188 tokens  f7f71e71
     ├─ ◆ crates/codehelion-cli/src/scan/structural/reporting.rs:749-770
     └─   crates/codehelion-cli/src/scan/structural/reporting.rs:853-874

 #3  0.59  type-1 ×2  128 tokens  814ddea4
     ├─ ◆ crates/codehelion-frontend-c/src/ir.rs:1822-1836      line_column
     └─   crates/codehelion-frontend-rust/src/ir.rs:887-901     line_column

... and 956 more groups (--limit 0 lists every one)

1,226 groups (type-1 76, type-2 190, type-3 960) · 267 suppressed · sorted by priority
supplemental: 515 siblings (--show-siblings; 80 dropped by search ceilings), 1,000 near misses (--show-near-misses; 3,800 dropped by the retention cap)
369 files, 154,952 lines, 826,558 tokens · run 1 (replay: codehelion report --run 1)
◆ the occurrence a group is measured against · ×N the number of occurrences
open one: codehelion explain 0f5065d5 · list every group: --limit 0
```

The ranking value leads each heading because it is what the listing is in
order on. `◆` marks the occurrence the group is measured against, which is
the one to read first. The identifier that closes the heading is the shortest
prefix `codehelion explain` accepts, so a group can be opened straight from
the listing.

`--decoration ascii` draws the same listing without a character outside
ASCII, and `--decoration none` drops the tree entirely. Anything qualifying
the run — a ceiling that fired, a rule that matched nothing — goes to the
error stream instead, which leaves the report on standard output pipeable:

```text
⚠ warning: candidate search was truncated by high frequency, high frequency postings; duplication the tree contains may be missing from this report
```

`-v` adds what each group was ranked on, including the similarity dimensions
this mode could not measure:

```text
 #1  0.67  type-1 ×2  240 tokens  0f5065d5
     across directories, identifiers 1.00
     confidence 0.86, maintenance risk 0.44, refactoring difficulty 0.19 (2 instances, 240-240 tokens, 240 repeated, 1.00 similarity, 2 file(s))
     similarity: composite 1.00 (lexical 1.00, structural 1.00, control-flow 1.00, type n/a, api 1.00); cohesion 1.00; confidence high [structural-verify-v1]
     content entropy: 4.91 bits
     body evidence: loop no, recognised allocation no, at least 26 call site(s)
     ├─ ◆ crates/codehelion-cli/src/scan/store.rs:177-205       tree_changes  [finding c8c5aae7]
     └─   crates/codehelion-cli/src/scan/structural/store.rs:145-173  tree_changes  [finding 63fd17f8]
```

`-vv` adds what the run itself did: the candidate pipeline stage by stage, the
ceilings that applied, and full identifiers.

## Why keep scanning

Duplication does not arrive once. It comes from a fix copied to a second place,
from two people solving the same problem in the same week, and now from
generated code that had no reason to go looking for an existing implementation.
What makes it expensive is not that it exists but that it gets lost: a copy
nobody remembers ruling on is re-reported every scan, and a copy somebody
decided to keep is argued about again.

That is what the stable identifiers and the baseline are for.

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

Semantic scanning additionally needs the helper for each language you want to
analyse. Install the helpers onto `PATH`, then use `doctor` to confirm their
protocol and compiler availability:

```sh
cargo install codehelion-backend-rust
cargo install codehelion-backend-clang # also needs a system libclang
codehelion doctor
```

## Usage

```sh
codehelion scan               # scan the current directory, text report
codehelion scan --mode structural           # also detect gapped (Type-3) clones
codehelion scan --mode semantic             # compare on what a compiler resolved (needs a helper)
codehelion scan --format json --output report.json path/to/repo
codehelion scan --format sarif --output report.sarif   # SARIF 2.1.0 log
codehelion scan -v            # add the numbers behind each group; -vv adds run diagnostics
codehelion scan --quiet       # the groups alone, without the heading or the summary
codehelion scan --limit 0     # list every clone group and every occurrence
codehelion scan --untrusted   # read a tree nobody vouches for under lowered ceilings
codehelion report             # render the latest completed scan again
codehelion report --run 1     # render a particular recorded scan again
codehelion explain <ID>       # show a finding from the local database
codehelion explain <ID> --format json
codehelion baseline create    # freeze the latest findings as a baseline
codehelion baseline update    # drop baseline entries the latest scan no longer reports
codehelion cache status       # local-database location and size
codehelion cache prune --force # apply the retention limits and compact the database
codehelion cache clear --force # permanently delete the local audit database
codehelion config init        # write a commented codehelion.toml template
codehelion config show        # print the effective configuration
codehelion doctor             # report available analysis components
```

The main scan controls are:

- `--config <file>` and `--db <path>` choose the configuration and local database.
- `--jobs <n>` sets frontend read-and-lex workers (capped at four times host parallelism); clone grouping and report rendering remain serial. Omitted, the worker count follows host parallelism.
- `--no-ignore` also reads ignored files, and `--follow-links` follows symbolic links, which are otherwise excluded and counted by type. `--compile-commands <path>` names the compilation database to read instead of the one discovery would pick.
- `--baseline <file>` compares with accepted findings; `--show-suppressed`, `--show-siblings`, and `--show-near-misses` expand text output. JSON and SARIF retain those data regardless. `--siblings-by-signature` enables signature-based sibling generation in Structural and Semantic modes; it is off by default, while `--show-siblings` only changes text visibility.
- `-v`/`-vv` choose how much is said about each group, `--limit <n>` how many groups are listed, and `--quiet` prints the groups alone. Left out, a text report lists 10 groups with 5 occurrences under each and says how many it left out; `--limit <n>` changes the group count alone, and `--limit 0` lifts both. `--color <auto|always|never>` overrides the terminal detection, and `NO_COLOR` is honoured.
- `--decoration <auto|unicode|ascii|none>` chooses the glyphs the listing is drawn with. Unlike colour it does not follow the destination: a report written to a file keeps the tree a terminal would have shown, because a box-drawing character in a file is still readable where an escape sequence is not. `auto` draws box-drawing characters everywhere except Windows, whose console depends on the active code page.
- `--include-trivial` restores predicate families to their measured priority in Structural and Semantic mode.
- `--fail-on-findings` returns exit code 3 when visible findings remain.
- `--compare-build-variants` and `--compare-languages` request separate Semantic comparisons; they never merge ordinary scan partitions.
- `--allow-execution=build-script` is the explicit, opt-in permission for a Semantic helper to run a project build script. Nothing in the scanned tree executes without it; `--untrusted` permits no execution.
- `--untrusted` lowers the scan's ceilings on any platform. Combined with `--mode semantic` it also requires an operating-system memory ceiling around the helper process, which only Linux can enforce; elsewhere that combination fails rather than run a helper unconfined.
- `cache prune --force` applies the retention limits to the local audit database and compacts it, keeping the newest 20 standalone artifact analyses and the newest 20 comparisons of each kind unless `--keep-artifacts` and `--keep-comparisons` say otherwise. It deletes retained history, so it requires the confirmation flag.
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

Findings are grouped into clone groups, and both a group and each of its
members carry a stable ID. The group's ID closes its heading in the default
report, and it is the one `[suppression] clone-ids` and a baseline take: both
name whole groups, so a member's ID written there matches nothing. Member IDs
are printed as `[finding <ID>]` under `-v`. Either kind can be opened with
`codehelion explain <ID>`.

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

A baseline is for freezing a threshold and defending it in CI. Following your
own progress through a refactor does not need one: rescan, and read the
summary line saying what became of the previous run's highest-ranked groups
together with `codehelion explain <id>`, which says whether a group is still
in the latest run. Both are derived from the runs already in the local
database, so nothing has to be created, kept in step, or committed.

### Rescanning after a refactor

A scan is also a check on the refactor you have just finished. Run it again on
the tree you changed, before moving on:

```sh
codehelion scan --mode structural
```

Then read the result against one rule: if a helper you have just written comes
back grouped with a call site you meant to have replaced, that call site is a
replacement you missed. Nothing else reports it — the code still compiles and
still behaves the same way, so a passing test suite is not evidence that every
copy went away. A scan of an ordinary tree finishes in seconds, which is what
makes running one per refactor practical.

Whether the artifact also got smaller is a separate question: a finding names
code a reader has to keep in step, not bytes a compiler emits.
`codehelion artifact analyze path/to/binary` measures that side.

The similarity breakdown a group prints under `-v` is worth reading before
opening the files. A group whose structure and control flow agree exactly
while its identifiers do not is usually the same routine written twice with
different names for the same things — the kind that collapses into one
function taking an argument for whatever differs. A group whose identifiers
agree as well is usually a copy, where one side can simply go. This is a way
of reading the numbers, not a rule the tool applies: codehelion reports what
the occurrences have in common and leaves the refactoring to you.

## Artifact inspection (optional)

The `artifact` commands read WASM, ELF, Mach-O, PE/COFF and static archives
locally. They parse bytes; they never load or execute the inspected artifact.

Observed size and duplicate code are reported for every format. The rest is
what the format itself can establish: retained and shared size need a call
graph, which is derived for WASM and ELF; duplicate data needs independently
sized data regions, which WASM has; a source location needs debug evidence —
DWARF for ELF, a matching dSYM for Mach-O, a matching PDB for PE/COFF, a
recorded source-map URL for WASM. A quantity the format cannot supply is
reported as unavailable beside an assumption naming what was missing, rather
than as a number.

These commands measure the artifact as it was built; they do not forecast what
consolidating duplication in the source would take out of it. The gap between
the two is wide. In one measured project, removing 238 lines of real code —
2,714 duplicated tokens — took 3,554 bytes (0.14%) off the uncompressed build
and 584 bytes (0.09%) off the Brotli-compressed one; two releases later,
consolidating 14 clone groups took off 15,323 bytes (0.56%) uncompressed and
928 bytes (0.13%) compressed, 6% of the uncompressed figure. The reason sits
upstream of the refactor: the linker and `wasm-opt` fold identical code before
it ships, and a 2.6 MiB shipped WASM module was measured to hold 20 bytes of
byte-identical duplicate in all. Consolidating duplication in the source is
worth doing where the size ceiling is an uncompressed number — a memory-mapped
image, a firmware image, a WASM module measured before transport encoding —
and buys close to nothing where the ceiling is measured after gzip or Brotli.

How many copies exist in the source and how many instantiations exist in the
binary are different axes, and only the first is in codehelion's search model.
In one measured tree, 1,730 of the 2,726 bytes recovered — 63% — came from a
single source-level template that the compiler had turned into 14 distinct
instantiations, because the predicate closure type differed at every call
site. There is one copy to find in the source, so no clone group describes the
multiplicity; the group codehelion did report on that tree accounted for the
other 996 bytes, the smaller half. Where a binary's size is dominated by how
many times something was instantiated rather than by how many times it was
copied, this is not the tool that measures it.

```sh
codehelion artifact analyze path/to/binary
codehelion artifact analyze path/to/binary --format csv  # also json, or text by default
codehelion artifact analyze path/to/binary --untrusted   # lowered size, time and memory ceilings
codehelion artifact report              # render the latest saved analysis
codehelion artifact report --analysis 1 # render a particular saved analysis
codehelion artifact compare before/binary after/binary
codehelion artifact calibration                 # summarize the recorded measurements
codehelion artifact calibration --source-run 1  # summarize a particular source scan
codehelion artifact calibration --baseline earlier.json  # set the summary beside an earlier one
```

`artifact calibration` reads measurements rather than taking them, so it
summarizes nothing until some exist. One is recorded by `artifact compare`
when it is given `--source-run` and `--clone-group` together with
`--before-build-variant` and `--after-build-variant`: the group's saved
estimate is then set beside the size difference the two artifacts actually
show. The estimate it needs comes from an earlier `artifact analyze` run with
`--source-run` and `--build-variant`.

`--baseline <file>` takes a calibration report written earlier by
`artifact calibration --format json` and prints the change in each error
statistic, overall and per stratum, beside the current value. It compares and
reports only: no threshold is enforced and nothing fails on a difference. A
report written under a different calibration report schema is refused rather
than compared against.

The `verified_savings_bytes` that comes out of a calibrated comparison is the
whole observed size difference between the two artifacts, assigned to the one
clone group named by `--clone-group`. What the comparison establishes is that
both artifacts are the same format and were built under the same declared
build variant, and nothing beyond that: a pair of builds that also picked up a
dependency update or a toolchain change reports that difference too, as the
measured saving of the refactoring. The number means what it says only for a
pair that differs in nothing else.

Debug companions are accepted only after the matching ELF build ID, Mach-O UUID
or PE CodeView/PDB identity has been verified. `artifact analyze --debug-file companion`
can inspect a native debug companion without a source scan; add
`--source-run` and `--build-variant` only when requesting source-artifact
correlation. When an artifact command receives `--build-variant manifest.json`, its identity uses the canonical JSON value, so whitespace and object-member ordering do not change the build variant.

`--build-variant` takes a file you write, not one to go looking for. Its
contents are yours to choose; what they buy is that only artifacts built the
same way are compared with one another:

```sh
echo '{"profile":"release","target":"wasm32","toolchain":"emcc-5.0.2"}' > build-variant.json
codehelion artifact analyze dist/app.wasm --build-variant build-variant.json --source-run 2
```

A source run also has a build variant, and reports print its digest. The two
are separate conditions — how the sources were read, and how the artifact was
built — recorded side by side rather than checked against each other. There is
no source digest to find and copy into the manifest.

`artifact analyze` and `artifact compare` reject inputs above 512 MiB by
default and run parsing, correlation, persistence, and rendering in a worker
with one 30-second deadline. Timeout diagnostics name the phase that was
running; `--max-bytes` and `--timeout-seconds` adjust the limits. On Linux,
`--max-memory-bytes <bytes>` also enforces a worker virtual-memory ceiling;
other platforms reject that option rather than silently ignoring it.
`--untrusted` clamps all three at once, so it is available on Linux only:
elsewhere it fails rather than accept an artifact nobody vouches for under a
memory ceiling that cannot be enforced. `artifact report` and
`artifact calibration` re-read what is already in the local database and run
in process, so none of these options apply to them. The
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
# jobs = 4                           # frontend read-and-lex workers (capped at 4× host parallelism);
                                    # grouping/reporting stay serial. Omit for automatic,
                                    # which is what the built-in default does; 4 is an example

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
# clone-ids = []                    # stable clone-group ids (hex; prefixes need at least 8 characters)
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
but retains enough member content, its stored lineage links the two runs, and
the report says of each group whether it kept the identity it had or inherited
one, and from which group. The totals say what became of the previous
comparable run's highest-ranked groups; `report.churn-top` sets how many of them
are followed, 100 by default. A baseline remains the explicit record of findings
a project has accepted.

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

Identical code folding can already remove same-signature functions with identical
bodies in C++ and Rust. Type-1 copies are therefore often folded by the linker
already. Type-2 and Type-3 copies that change identifiers or literals can leave
distinct machine code, so they can matter more when size is the reason to
inspect duplication. The two are not the same size of problem: in an optimised
build, what is still byte-for-byte identical in the artifact is a negligible
part of it, while the code that matches only after register and immediate
differences are normalized away is thousands of times larger.
`codehelion artifact analyze` reports the exact and the normalized figure side
by side, so the ratio for your own build is something you measure rather than
assume.

**Compressed size moves less than uncompressed size does.** What removing
duplication takes out of an artifact is a repeated byte sequence, and a
repeated byte sequence is the first thing a compressor folds away. The
uncompressed binary shrinks by roughly what was removed; the compressed one
shrinks by much less, because the compressor was already paying almost nothing
for the second copy. If your size budget is a compressed number, deduplication
is not the tool for it. If it is an uncompressed number — a memory-mapped
image, an embedded firmware image, a WASM module measured before transport
encoding — it is. Measure both before and after your own refactor rather than
taking a ratio from anywhere else; nothing here re-derives one for you.

**Fast mode reports more than you want to read.** The suppression policies for
boilerplate, test code and integer-width families need structural
classifications, so Fast mode cannot apply them and says so in the report. On a
tree of any size, `--mode structural` is what produces a list worth reading
top-down.

**Incomplete or edited copies are harder to detect.** Structural and Semantic
modes run two sibling channels. The similarity channel always runs: it retains
an ungrouped unit that measures close to a group's canonical member and sits in
a file that group already occupies. The signature channel is opt-in with
`--siblings-by-signature` and off by default; enabled, it can retain a
low-confidence sibling when its normalized signature matches the group's
canonical function and the otherwise ungrouped function is in the
same directory. A shared signature is evidence only while it is rare, so a
signature that more units share than
`limits.signature-sibling-max-units-per-signature` allows is left out of the
search entirely, and the summary names how many signatures were left out and
how far the widest one reached. Candidates removed by that limit are counted
apart from those a search ceiling dropped, so a reader can tell which of the
two to move; both are configurable, and the counts are deterministic for a
given tree and settings rather than a property of the machine.
`--show-siblings` only changes text visibility; JSON and SARIF retain
generated sibling data. A mirror in another directory, a changed signature, or
a candidate beyond the sibling-search ceiling can still keep a copy out;
codehelion is not a mirror-consistency checker. It does not prove that every
mirror has been found or that two same-signature bodies behave alike.

An intact copy is maintenance debt; a copy that has drifted is a bug today —
and the drifted one is the harder of the two to detect, which is the reverse
of the order a mirror audit wants. In one measured case an enum-to-string
mapping had been hand-mirrored across three surfaces: the three intact copies
were all grouped, and the one copy actually missing three names — the copy
causing a live bug — landed in no group at all. In another, three functions
built the same path; the two exact ones were grouped, and the third,
differing only in taking an early return where the others used an else
branch, appeared neither under `--show-siblings` nor under
`--show-near-misses`. Both were found by hand, with `grep`. So when a group is
reported, read what sits beside it: the same-shaped neighbours the group does
not include are where a drifted copy is most likely to be.

**A layer built on one signature gets nothing from that channel.** Where a
dispatch or callback table gives a hundred functions the same callable shape,
the signature separates nothing, and the channel has no evidence to offer
about that layer at all. Saying so is the point of the sharing limit: the
alternative is thousands of siblings that each pair one arbitrary function
with another, which reads like a result until it is examined.

**Large trees hit ceilings.** The candidate budget and the high-frequency
posting cap bound the search, and a run that hits either reports how much it
left unexamined. The index is held in memory, so a very large tree is bounded
by the ceilings rather than by disk.

**Artifact inspection depends on symbols.** A stripped binary yields almost
nothing; supply the unstripped build or a verified debug companion. Duplicate
detection that sees past register and immediate differences covers native
machine code built for x86 and, separately, WebAssembly, which is normalized
over its own opcode stream; on a native artifact built for another
architecture, only byte-identical duplicates are found. Correlating an artifact
back to the sources reads a name out of each symbol, which is done for Rust and
for the Itanium C++ ABI; a C++ artifact decorated for the Microsoft ABI is
still read for size and duplication, but reports no source correspondence
rather than a guessed one.

**A WebAssembly module correlates to source one symbol at a time.** ELF, Mach-O
and PE/COFF reach a source line through DWARF, a matching dSYM or a matching
PDB, and a source line is what lets a clone group's line range be attributed
bytes. A core module carries function names in its name section and no line
information, so correlation names whole functions and leaves clone-group byte
attribution unavailable. Building the module with DWARF would change the size
being measured, which is usually the reason to inspect it, so the reports say
what the name section can and cannot support instead of asking for a build that
answers a different question.

**The audit database is not migrated.** A database written under a different
schema is never converted, so no history carries across one. At the default
path a run leaves that database exactly where it is, records into
`audit-v<schema>.db` beside it, and says which file it used; a database named
with `--db` is refused instead, since writing somewhere else would ignore the
path that was asked for. `doctor` lists every audit database in the directory,
which of them this build can open, and which one a run would take. This will
change before 1.0.

## Accuracy

Measured with `make eval` at 0.4.0. The generated corpora are committed, so the
recall numbers are reproducible from a checkout on their own. The labelled
cases commit their verdicts and not their sources, so the precision numbers
need `corpus/scripts/materialize-labeled.sh` run first. `corpus/README.md`
explains why each half can answer only one of the two questions.

**Recall — ten generated mutation corpora, 43 clone pairs and 11 deliberate
non-clones.** A generated corpus knows every clone it contains, so it can be
scored for recall. It cannot be scored for precision: it labels the clones it
was built around and nothing else, so an unlabelled true copy would count
against the detector.

| corpus | Fast | Structural |
|---|---|---|
| rust | 0.7143 | 1.0000 |
| c | 0.8333 | 1.0000 |
| cpp | 0.8571 | 1.0000 |
| cpp-common-signature | 1.0000 | 1.0000 |
| rust-graded | 1.0000 | 1.0000 |
| rust-literals | 1.0000 | 1.0000 |
| rust-replaced | 1.0000 | 1.0000 |
| rust-negative | 1.0000 | 1.0000 |
| rust-partial | 1.0000 | 0.5000 |
| rust-divergent | 0.4000 | 0.8000 |

Fast mode reaches no type-3 clone at all in `rust`, `c` and `cpp`, which is the
cost of skipping the structural pass rather than a tuning question.
`rust-partial` is the one corpus where Structural mode scores below Fast.
`cpp-common-signature` is there for the signature sibling channel: nine
functions share one callable shape, and what it fixes is that withholding a
shape that common as evidence costs the primary result nothing.

The six restricted-semantic corpora are not scored here. Each registered rule
is asserted by its own tests, which state why a pair matched or was dropped —
a stronger claim than a corpus average over rules that answer different
questions.

**Precision — eight labelled snapshots of real projects, 141 clone-pair and 177
non-clone verdicts.** Every group the detector reported on these trees carries
a hand-written verdict, so precision is measurable. Recall is not: nobody
enumerated the clones in those projects first.

| case | Structural precision | confirmed | refuted |
|---|---|---|---|
| fast-yaml | 1.0000 | 1 | 0 |
| codehelion-store | 1.0000 | 2 | 0 |
| cjson | 0.8235 | 14 | 3 |
| bitflags | 0.7857 | 11 | 3 |
| spdlog | 0.5833 | 21 | 15 |
| serde-json | 0.5357 | 45 | 39 |
| lz4 | 0.5357 | 15 | 13 |
| tinyxml2 | 0.5263 | 10 | 9 |
| **all cases** | **0.5920** | **119** | **82** |

Two of the eight are this author's own projects, and both score 1.0000.
Dropping them moves the aggregate to 0.5859 — they carry 3 of the 201
verdicts, so the figure is the other six projects' either way.

0.5920 is the figure for the whole report read end to end, which is not how a
duplication report is read. Over the 200 of those verdicts a finding of its own
carries — the report shows a duplication that is a shorter cut of another
inside the longer one, so it takes no place of its own in the order:

| ordered by | p@10 | p@50 | MAP |
|---|---|---|---|
| priority | 1.0000 | 0.9600 | 0.9290 |
| size | 1.0000 | 0.9400 | 0.8772 |

Nothing false reaches the first ten either way. What the aggregate says is that
the tail is close to half noise, which is why the priority ordering and
`--mode structural` are defaults rather than options.

The snapshots these verdicts are anchored to are fetched by
`corpus/scripts/materialize-labeled.sh` and never redistributed. A case that
has not been materialized is reported as unscored rather than scored as
perfect.

## Development

Common tasks are wrapped in the `Makefile` (`make help` for the full list):

```sh
make format        # auto-fix: clippy --fix + cargo fmt
make format-check  # verify formatting
make lint          # clippy with warnings as errors
make test          # run the test suite
make check         # format-check + lint + boundary checks + test + doc
make audit         # cargo-deny (advisories, bans, licenses)
make coverage      # HTML coverage report (needs cargo-llvm-cov)
make hooks         # install the pre-commit git hook
```

Guardrails: `rustfmt` with a pinned config; `clippy` `pedantic` + `nursery`
with warnings as errors and `unsafe` forbidden; `cargo-deny` checks dependency
advisories, bans and licences; `clippy.toml` disallows process spawning and
network sockets in the scan path. Tests are written alongside the code they
cover. The pre-commit hook runs `cargo fmt --check` and `cargo clippy` with
warnings denied — the mechanical part, which costs seconds. The tests, the
boundary checks and the packaging check are in `make check`, to run before
pushing.

Detection accuracy is measured against the corpora in `corpus/`, which record
hand-written verdicts on real projects rather than the projects themselves.
`make eval` prints the tables; the current figures are under
[Accuracy](#accuracy), and `corpus/README.md` covers what each half can and
cannot answer.

The protocol handshake cases live in `crates/codehelion-helper-conformance/`.
They run the independently built helper binaries, rather than checking the
protocol against a description of it that the CLI also generated.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a security issue, follow
[SECURITY.md](SECURITY.md) rather than opening a public issue.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
