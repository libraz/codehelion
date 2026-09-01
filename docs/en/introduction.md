# Introduction

codehelion finds duplicated logic in Rust, C and C++ codebases, and keeps
finding the same duplication across scans.

It reads sources directly. There is no build to run first, no
`compile_commands.json` to produce, and no network access anywhere in the tool.
It detects identical, renamed and gapped copies, reports several measures side
by side rather than one score, and names every finding by a content-derived
identifier that survives unrelated edits — so duplication that has already been
ruled on stays ruled on, and a scan months later can be measured against the one
before it.

codehelion is pre-1.0. The command-line surface, the report formats and the
on-disk database layout can change between releases.

## What one scan does

![What one scan does](../images/pipeline.svg)

A scan reads every supported source file with an error-tolerant lexer, which
means a file that does not parse still contributes what it does parse. Comments
and whitespace are removed before anything is compared, and identifiers and
literals are normalized according to the configured strategy.

What comes out is indexed by content: whole bodies as units, and runs of
statements inside them as fragments. Candidate pairs come from that index — an
exact seed where two fingerprints agree, a near-match proposal where enough
shingles overlap — and each candidate is verified by alignment before it becomes
a finding. Verified pairs are then grouped around a canonical member, which is
the occurrence every other one in the group was measured against.

The run is recorded into a local SQLite database, and the text, JSON and SARIF
reports are exports of that record. Rendering a report again does not read the
tree again.

Every stage has a resource ceiling, and every ceiling that fires is counted in
the report. On a tree large enough for the candidate budget to stop the search,
the report states how many pairs it left unexamined instead of presenting a
partial answer as a complete one.

## Why the same tree is scanned again

Duplication does not arrive once. It comes from a fix copied to a second place,
from two people solving the same problem in the same week, and from generated
code that had no reason to look for an existing implementation. What makes it
expensive is not that it exists but that it gets lost: a copy nobody remembers
ruling on is re-reported every scan, and a copy somebody decided to keep is
argued about again.

Stable identifiers and baselines are what stop that. A finding is named by what
it contains, so the decision recorded against it survives the edits around it.
See [Stable identifiers](stable-ids.md) and [Baselines](baselines.md).

## What a finding claims

A finding names code a reader has to keep in step. It is a maintainability
measure, not a size measure: optimisers routinely fold identical code that is
still duplicated in the source, so removing a reported clone need not make the
built artifact any smaller. [Artifact analysis](artifact-analysis.md) measures
that side separately, and [Limitations](limitations.md) states how wide the gap
between the two is.

Each group reports what its occurrences have in common — lexical, structural,
control-flow, type and API similarity, and the clone confidence, maintenance
risk and refactoring difficulty derived from them. A dimension the running mode
cannot measure is reported as absent rather than guessed. Deciding what to do
about a group is left to the reader.

## What codehelion is not

It is not a general code-quality platform, a vulnerability scanner, a style
checker, or a refactoring tool. It proves no semantic equivalence, guarantees no
size reduction, and refactors nothing on its own. It is also not a
mirror-consistency checker: it reports the duplication it finds and does not
claim to have found every copy.

## Where to go next

- [Getting started](getting-started.md) — install it and read a first report.
- [Analysis modes](analysis-modes.md) — what Fast, Structural and Semantic each measure.
- [Reading a report](reading-a-report.md) — what every field in the listing means.
- [The refactoring loop](refactoring-workflow.md) — using a scan as a check on the refactor you just finished.
