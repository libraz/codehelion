# Continuous integration

> **Pre-1.0 surface.** This is documented and tested, but has not had the real
> use that would make it worth a promise, so it can change between releases.

Three things codehelion offers an automated check, all of them exit codes from a
local run. None needs a service, an account or a network call.

## A gate on duplication that arrived

```sh
codehelion scan --mode structural \
  --baseline codehelion-baseline.json \
  --fail-on-findings
```

Exit `3` when findings remain that the baseline does not already carry. The
baseline is created once, from a scan of the tree as it is, so the check answers
one question: did this change add duplication that was not already there.

It is deliberately not a ratio. A gate on "duplication stays under N%" is
answered by raising N, and it moves on its own as a codebase grows — a tree that
doubles in size while duplicating at the same rate reports a falling percentage.
A baseline names the groups instead of counting them, so what fails is an
addition, and what clears it is either removing the duplication or recording the
decision to keep it.

Creating and updating the file is in [Baselines](baselines.md); recording a
decision to keep a group instead of a passing exception is in
[Suppression](suppression.md).

## A gate on seams

A seam is a set of files a project has written down as changing together — two
frontends that have to implement one rule, a pair of documents kept in two
languages.

```sh
codehelion guard --since "$MERGE_BASE" --deny-asymmetric
```

Exit `3` when a change touched some of a seam's members and not the others.
Without `--deny-asymmetric` it reports and returns `0`, which is the form to
start with. An absent or empty ledger reports nothing and returns `0`, so the
step can be added before any seam has been written down.

What this catches is the change that is complete in every way a compiler or a
test can see and incomplete in the way only the ledger records. It is also the
check most likely to fire on a change that was right: a member deliberately left
alone is an asymmetric change, and there is no per-invocation exception — a seam
that reports too much is cut more finely in its `members`.
[Seam tracking](seam-tracking.md) describes the ledger and what it cannot tell
apart.

## Findings in a code-scanning view

```sh
codehelion scan --mode structural --format sarif --output codehelion.sarif
```

The output is a SARIF 2.1.0 log. On GitHub:

```yaml
- run: codehelion scan --mode structural --format sarif --output codehelion.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: codehelion.sarif
```

Each clone group is one result, its canonical instance the primary location and
every occurrence a related location. The group's stable id is published in
`partialFingerprints`, which is what lets a consumer recognise the same group
across scans instead of closing and reopening it whenever a line moves.
Suppressed groups are emitted with a SARIF suppression rather than dropped.

Every clone rule reports at the `note` level, because duplication is not a defect
class with an inherent severity and the scan's own ranking is a different
quantity from a consumer's severity axis. So the upload is a view, not a gate:
what fails a build is the exit code from one of the two checks above. The seam
summary is not in the log at all — SARIF is shaped for findings, and a seam
summary is not one.

## What a run leaves behind

A scan records into a local SQLite database under `.codehelion/`. On a runner
that database goes away with the runner, which costs nothing except the
run-to-run comparison the summary would otherwise print. A baseline is tied to
the conditions the scan was read under, so a job that reads the tree differently
from a developer — a different mode, a different `.h` grammar decision — will not
match the baseline that developer created.

Nothing leaves the machine. The ban on network access is enforced by dependency
policy and lints rather than by configuration, which is described in
[Local execution and trust](security.md).

## Exit statuses

`0` completed, `1` an operational error, `2` invalid usage, `3` a gate fired.
The full list is in [The command line](cli.md).
