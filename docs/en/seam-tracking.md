# Seam tracking

A seam is a set of paths that implement the same semantics in more than one place
and that have actually been changed together. Two frontends carrying the same
rule, a renderer and the exporter that has to agree with it — the copies are in
the code, but the evidence that they belong together is in the history.

codehelion does not go looking for seams. They are written down in
`codehelion.toml`, by a person, and that ledger is what every check on this page
reads. The reason is that a guard whose subject is recomputed from history on
every run passes today and fails tomorrow with nobody having changed the code.
A committed ledger makes the subject of a report something a reader can look up.

Everything here is computed from the local `.git` alone. Nothing is sent
anywhere, and no language model takes part in a run.

## Writing the ledger

```toml
[[seam]]
id = "frontend-c-cpp"
members = ["crates/codehelion-frontend-c/**", "crates/codehelion-frontend-cpp/**"]
note = "same semantics implemented twice across the two frontends"
```

`members` are globs over repository-relative paths, and a seam needs at least two
of them. `id` is what names the seam in every report. `note` is free text that
nothing reads — it is there for the next person.

The settings sit in a separate `[seam-tracking]` section, because TOML cannot
spell one name as both an array of tables and a table. See
[Configuration](configuration.md#seams).

## The three commands

```sh
codehelion history                    # what the commit range holds
codehelion seam                       # the ledger's seams, measured
codehelion seam --suggest             # candidates from co-change alone
codehelion seam --no-record           # measured, and not kept
codehelion guard                      # the working tree against the ledger
codehelion guard --since v0.4.0       # a revision range instead
codehelion guard --paths crates/codehelion-frontend-c/src/lex.rs
codehelion guard --deny-asymmetric    # exit 3 on an asymmetric change
```

`history` reads the commit records and nothing else: how many commits the range
holds, how they classify as fix, feature or other, and which commits it starts
and ends at. It opens no source file and needs no ledger, which makes it the
command to run first on a repository that has neither.

`seam` reports, for each ledger entry, how many asymmetric changes it has seen,
how many of those became breaches, and when the most recent breach was.
`--until <rev>` fixes the end of the range, which is what lets two generations'
numbers be set beside each other.

`guard` compares one change against the ledger. By default it reads the working
tree against `HEAD`; `--since <rev>` reads that revision to `HEAD` instead.
`--paths <p>...` asks a different question — the one worth asking before an edit
rather than after. It names the seam each path belongs to and the members that
would have to move with it, reading the ledger alone and never opening git.

An absent or empty ledger is not an error: `guard` reports nothing and exits `0`.

## What the numbers mean

An **asymmetric change** is a commit that touched some of a seam's members and
left the others alone.

A **breach** is an asymmetric change followed, within `breach-window` later
commits, by a `fix:` commit touching a member the asymmetric change did not. The
window is counted in commits rather than in days, so the figure does not move
with how fast the work happened.

An asymmetric change is a shape, not a verdict — plenty of them are correct, and
a member can have its own reasons to change. A breach is the stronger statement:
the repository already paid for that asymmetry once, which is evidence the seam
is both real and costly.

Neither number measures the code. They describe what happened to a set of paths,
not whether what is in those paths is duplicated; a [scan](analysis-modes.md) is
what answers that. A ledger entry whose members turn out to be independent
produces asymmetric changes indefinitely and never a breach, and that pattern is
the signal to take it out of the ledger.

`guard` reports and exits `0` by default. `--deny-asymmetric` makes an asymmetric
change exit `3`, the same status `scan --fail-on-findings` uses. There is no
per-invocation escape hatch, and that is deliberate: reporting is what happens
unless somebody deliberately asked for the failure, so an exception flag would
exist only to defeat the flag they turned on. A seam that reports more than a
project wants to read is cut more finely in its `members`.

## What a run records

`codehelion seam` writes what it printed into the local audit database, as one
generation of the measurement. That is what lets a report set the newest
evaluation beside the one before it and name what moved; the counts a report
carries are read back rather than taken again, since a report opens no commit.
The block a report prints is described in
[Reading a report](reading-a-report.md#seams). `--db <file>` names the database,
and left off it is the one every other command resolves for itself — see
[Configuration](configuration.md#the-local-database).

Three invocations record nothing, each for its own reason:

- `--suggest` proposes candidates instead of measuring the ledger. A proposal is
  not a measurement: those pairs were never evaluated against the ledger, and
  filing them as the newest generation of what the ledger costs would answer a
  question nobody asked.
- `--until <rev>` reads a range somebody deliberately cut short. Kept as the
  newest generation, it would make the next comparison read the shorter question
  as a change in the code.
- `--no-record` is the explicit opt-out.

Recording is not what the command was run for, so a recording that fails does not
fail the run. A read-only checkout, or a database this build cannot open, costs
the next run its comparison point and nothing else: the report still goes out, and
the failure is a warning on the error stream the way a shallow history is. The
counts are the answer the run was for.

`history` and `guard` open no database at all. `history` reports the extent of a
range rather than anything about the code in it, and `guard` judges the change in
front of it, which the ledger and the working tree answer between them. Requiring
a recorded run there would make the question unanswerable in exactly the checkouts
it exists to be asked in.

## Candidates, and why promotion is by hand

`codehelion seam --suggest` proposes seams from co-change alone, with the numbers
behind each candidate:

```
support(a, b)     = commits touching both
confidence(a→b)   = support(a, b) / commits touching a
coupling(a, b)    = min(confidence(a→b), confidence(b→a))
```

`coupling` takes the minimum rather than either confidence on its own, so a path
that everything drags along — a top-level manifest, a lockfile — does not read as
coupled to the whole tree. Candidates under `min-coupling` or `min-support` are
not shown, and co-change is counted over the leading `suggest-depth` components
of each path rather than over whole file names.

Commits touching more paths than `max-commit-size` are left out of the coupling
figures, because a sweeping rename or a formatting pass hands support to every
pair it happened to include. They are not left out of breach detection: a large
commit that broke a seam still broke it.

A pair naming a directory that is no longer in the tree is not proposed. Two
crates since folded into one moved together in every commit either of them
appeared in, which reads as a perfect coupling forever and is a proposal nobody
can act on. Checking that the directory is still there is the only thing
`--suggest` reads outside the history, and it opens nothing.

`--suggest` never writes to the ledger. Promoting a candidate is a statement
about what the code is supposed to mean, and keeping that statement a human one
is what holds the guard's subject still while the history keeps growing.

## What makes two runs comparable

- Commits are walked in ascending `(committer time, commit id)` order, fixed here
  rather than inherited from git's own default. Ties are settled by commit id.
- Rename detection is off. A rename reads as a delete and an add. Rename
  detection is a similarity heuristic, and a result that moves with a threshold
  is not one two runs can be compared on.
- A commit counts as a fix through its Conventional Commits prefix and nothing
  else. There is no natural-language search over the message.
- A merge commit is followed through its first parent only.
- Every output carries a digest of the settings it was computed under, and the
  first and last commit of the range it read. Without those, a number that moved
  cannot be told from a setting that moved.

## What the history has to be

The repository has to have its history. A shallow clone cannot be read, which in
CI means `actions/checkout` with `fetch-depth: 0` — the default depth of 1 leaves
one commit visible.

Breaches need Conventional Commits. A repository whose messages carry no `fix:`
prefix reports no breaches at all. Asymmetric changes are detected either way,
since they are about paths rather than messages.

`history-limit` bounds how many of the newest commits are read. It is a ceiling
and not a floor: a young repository's figures are thin because there is little
behind them, and a seam with a handful of commits under it says less than the
numbers suggest.

## What this cannot see

Duplication inside one file carries no time axis, a correct change to a single
member still reports as asymmetric, and a file's history stops where it was
moved. See [Limitations](limitations.md).
