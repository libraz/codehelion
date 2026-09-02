# The refactoring loop

![One pass of the refactoring loop](../images/workflow.svg)

## Ordering the report for the job in front of you

The default order is the composed priority. When the job is one particular
measure, order on it instead — `--sort duplicated-tokens` for the most repeated
code, `--sort instances` for the most widely copied, `--sort identifier-jaccard`
for the copies that still agree on their names. See
[Reading a report](reading-a-report.md#ordering).

## Reading the numbers before opening the files

The similarity breakdown a group prints under `-v` is worth reading before
opening the files. A group whose structure and control flow agree exactly while
its identifiers do not is usually the same routine written twice with different
names for the same things — the kind that collapses into one
function taking an argument for whatever differs. A group whose identifiers agree
as well is usually a copy, where one side can simply go.

This is a way of reading the numbers, not a rule the tool applies: codehelion
reports what the occurrences have in common and leaves the refactoring to you.

## Rescanning after a refactor

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

## Following your own progress

Nothing has to be set up for this. Each scan is recorded, so the totals of the
next one say what became of the previous run's highest-ranked groups, and

```sh
codehelion explain <id>
```

says whether one particular group is still in the latest run. A
[baseline](baselines.md) is for freezing a threshold in CI; tracking a refactor in
progress does not need one.

## A seam is a different kind of work item

A clone group names code that is repeated. A [seam](seam-tracking.md) names paths
that have to move together, and the report says what not moving them has cost:

```text
seams: frontend-c-cpp 12 asymmetric changes, 7 breaches (last 6e014d86), 1,553 findings
```

The breach count is the one to order on. An asymmetric change is a commit that
touched some of the members and left the rest alone, and plenty of those were the
right change; a breach is one that a `fix:` to a member left alone followed, so
the repository has already paid for the asymmetry once. The findings beside it
are what a scan found inside those same paths, which is where the two kinds of
work item meet: a seam that breaches and holds findings is one this loop can act
on directly.

Before the edit rather than after it,

```sh
codehelion guard --paths crates/codehelion-frontend-c/src/lex.rs
```

names the members that would have to move with the file in front of you.

## Whether the artifact got smaller

That is a separate question. A finding names code a reader has to keep in step,
not bytes a compiler emits.

```sh
codehelion artifact analyze path/to/binary
```

measures that side, and [Limitations](limitations.md) states how wide the gap
between the two usually is — wide enough that consolidating source duplication is
worth doing for maintainability first, and for size only where the size ceiling is
an uncompressed number.
