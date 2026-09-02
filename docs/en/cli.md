# The command line

Every command's own `--help` is authoritative and more detailed than this page;
what follows is the shape of the surface.

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
codehelion history            # classify the commits in the range and say what it read
codehelion seam               # measure the seams the ledger names
codehelion seam --suggest     # propose candidate seams from co-change alone
codehelion seam --no-record   # measure the seams without recording the evaluation
codehelion guard              # compare a change against the ledger
codehelion guard --deny-asymmetric  # exit 3 when a change touched part of a seam
codehelion guard --paths src/a.rs   # name the seam a path belongs to, before editing
```

## `scan`

Reads a tree and records the run. The main controls:

- `--config <file>` and `--db <path>` choose the configuration and local database.
- `--jobs <n>` sets frontend read-and-lex workers (capped at four times host
  parallelism); clone grouping and report rendering remain serial. Omitted, the
  worker count follows host parallelism.
- `--no-ignore` also reads ignored files, and `--follow-links` follows symbolic
  links, which are otherwise excluded and counted by type.
  `--compile-commands <path>` names the compilation database to read instead of
  the one discovery would pick.
- `--baseline <file>` compares with accepted findings, and `--baseline-mode`
  chooses whether the frozen groups are hidden or marked. `--show-suppressed`,
  `--show-siblings` and `--show-near-misses` expand text output; JSON and SARIF
  retain those data regardless. `--siblings-by-signature` enables signature-based
  sibling generation in Structural and Semantic modes; it is off by default,
  while `--show-siblings` only changes text visibility.
- `-v`/`-vv` choose how much is said about each group, `--limit <n>` how many
  groups are listed, and `--quiet` prints the groups alone. Left out, a text
  report lists 10 groups with 5 occurrences under each and says how many it left
  out; `--limit <n>` changes the group count alone, and `--limit 0` lifts both.
  `--color <auto|always|never>` overrides the terminal detection, and `NO_COLOR`
  is honoured.
- `--decoration <auto|unicode|ascii|none>` chooses the glyphs the listing is
  drawn with. Unlike colour it does not follow the destination: a report written
  to a file keeps the tree a terminal would have shown, because a box-drawing
  character in a file is still readable where an escape sequence is not. `auto`
  draws box-drawing characters everywhere except Windows, whose console depends
  on the active code page.
- `--sort <axis>` and `--min-identifier-jaccard <value>` order and filter the
  text listing. See [Reading a report](reading-a-report.md#ordering).
- `--include-vendored` reports duplication inside vendored trees, and
  `--include-trivial` restores predicate families to their measured priority in
  Structural and Semantic mode.
- `--no-reuse` analyses even when an identical completed run is available locally.
- `--fail-on-findings` returns exit code 3 when visible findings remain.
- `--compare-build-variants` and `--compare-languages` request separate Semantic
  comparisons; they never merge ordinary scan partitions.
- `--helper <NAME=PATH>` overrides one compiler-helper location as `rust=PATH` or
  `clang=PATH`.
- `--allow-execution=build-script` is the explicit, opt-in permission for a
  Semantic helper to run a project build script. Nothing in the scanned tree
  executes without it; `--untrusted` permits no execution.
- `--untrusted` lowers the scan's ceilings on any platform. Combined with
  `--mode semantic` it also requires an operating-system memory ceiling around
  the helper process, which only Linux can enforce; elsewhere that combination
  fails rather than run a helper unconfined.

## `report`

Re-renders one recorded scan without reading the tree again. It takes the display
options `scan` takes — format, verbosity, limit, sort, colour, decoration — so a
run recorded as text can be exported as JSON later. `--run <id>` selects a
recorded scan; every scan format prints the id that replays it.

## `explain`

Shows one group or one occurrence from the local database, by stable id or an
unambiguous prefix. `--format json` prints it as data.

## `baseline`

`create` freezes the last recorded scan's findings into a file; `update` drops the
entries the latest scan no longer reports. Both take the scanned path and
`--file`. See [Baselines](baselines.md).

## `cache`

`status` shows the local database's location, size and contents. `prune` applies
the retention limits and compacts it, keeping the newest 20 standalone artifact
analyses and the newest 20 comparisons of each kind unless `--keep-artifacts` and
`--keep-comparisons` say otherwise. `clear` permanently removes the database.
Both `prune` and `clear` delete retained history, so both require `--force`.

## `config`

`init` writes a commented `codehelion.toml` template; `show` prints the effective
configuration. See [Configuration](configuration.md).

## `doctor`

Reports what this machine has: the helpers and their protocol versions, what each
helper answered when asked, the sandboxing the platform can enforce, how many
restricted semantic rules this build carries, every audit database in the
configured directory with which of them this build can open, and the artifact
formats this build reads.

## `artifact`

```sh
codehelion artifact analyze path/to/binary
codehelion artifact analyze path/to/binary --format csv  # also json, or text by default
codehelion artifact analyze path/to/binary --untrusted   # lowered size, time and memory ceilings
codehelion artifact analyze path/to/binary --debug-file companion
codehelion artifact report              # render the latest saved analysis
codehelion artifact report --analysis 1 # render a particular saved analysis
codehelion artifact compare before/binary after/binary
codehelion artifact calibration                 # summarize the recorded measurements
codehelion artifact calibration --source-run 1  # summarize a particular source scan
codehelion artifact calibration --baseline earlier.json  # set the summary beside an earlier one
```

`--input-format` asserts the format magic-byte detection must find, and `--arch`
selects the slice of a universal Mach-O binary. `--build-variant`, `--source-run`
and `--linker-map` are the source-correlation inputs. See
[Artifact analysis](artifact-analysis.md) and [Calibration](calibration.md).

## `history`

Reads the local commit records and nothing else: how many commits the range
holds, how they classify as fix, feature or other, and which commits it starts
and ends at. It opens no source file and reads no ledger. `--path <dir>` selects
the repository, `--until <rev>` fixes the end of the range, and `--config <file>`
names the configuration the range settings come from. `--format text|json`,
`--output <file>` and `--force` behave as they do elsewhere.

## `seam`

Reports, for each `[[seam]]` entry in the ledger, how many asymmetric changes it
has seen, how many of those became breaches, and when the most recent breach was.
`--suggest` instead proposes candidate seams from co-change alone, with the
coupling value and the support behind each; it never writes to the ledger. Takes
the same `--path`, `--config`, `--until`, `--format`, `--output` and `--force`.
See [Seam tracking](seam-tracking.md).

An evaluation is also recorded in the local audit database, so a later report can
set it beside the generation before it. `--db <file>` names the database to record
into; left off, it is the one every other command resolves for itself.
`--no-record` reports the evaluation without recording it. Neither `--suggest` nor
`--until <rev>` records: a proposal is not a measurement, and a range deliberately
cut short would be read by the next comparison as a change in the code. A
recording that fails leaves the report standing and says so on the error stream.

## `guard`

Compares one change against the ledger. By default it reads the working tree
against `HEAD`; `--since <rev>` reads that revision to `HEAD` instead.
`--paths <p>...` is the lookup to run before editing: it names the seam each path
belongs to and the members that would have to move with it, reading the ledger
alone and never opening git.

`--deny-asymmetric` returns exit code 3 when a change touched some of a seam's
members and not the others. Without it, `guard` reports and returns 0. There is
no per-invocation exception; a seam that reports too much is cut more finely in
its `members`. An absent or empty ledger reports nothing and returns 0.

## Exit status

- `0`: command completed successfully.
- `1`: an operational error prevented completion.
- `2`: command-line usage was invalid.
- `3`: `scan --fail-on-findings` found one or more visible findings, or
  `guard --deny-asymmetric` found one or more asymmetric changes.
