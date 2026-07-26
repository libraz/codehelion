# Provenance

- Project: lz4, a compression library written in C
- Origin: <https://github.com/lz4/lz4>
- Commit: `ebb370ca83af193212df4dcbadcc5d87bc0de2f0` (release v1.10.0)
- Contents: `lib/` — 11 files, about 11k lines, including the hash
  implementation the tree bundles and builds as part of the library.
- License: BSD 2-Clause for the library sources; the repository as a whole is
  dual-licensed BSD 2-Clause / GPL-2.0.

The sources are not committed under `corpus/labeled/`. `snapshot.toml` records
the origin and the commit they are cut from, and
`corpus/scripts/materialize-labeled.sh` fetches and reconstructs them locally.
The commit is fixed so the line ranges in `labels.json` stay meaningful, and is
never bumped in place: moving it invalidates every verdict recorded against it.

## Why this project

C written by someone else. The other cases in this corpus were written by one
author, which makes any false-positive class they show ambiguous: a class of
defect and a personal habit look identical when the sample has one author. This
case is idiomatic performance C from an unrelated project, so a class that
appears in both is a class.

It is also the densest source of lookalikes in the corpus. Performance C
instantiates one routine per integer width, wraps a single generic
implementation in a family of public entry points, and unrolls fixed-length
runs by hand — three shapes that are duplication by every similarity measure
and that no reader would act on.

## What the verdicts show

Two thirds of the reported groups are lookalikes, which is far worse than any
self-authored case in this corpus reaches. The three classes that account for
most of them:

- `type-specialised-variant` — the same routine written once per integer width
  (`LZ4_read16/32/64`, `XXH32_*` beside `XXH64_*`).
- `forwarding-wrapper` — public entry points that pass different constants to
  one generic implementation. Two of these groups hold ten and eleven members.
- `unrolled-repetition` — two stretches of one hand-unrolled run, alike because
  the run does the same thing eight times over.

A ninth group was a defect rather than a judgement call: a hand-unrolled store
reported as a clone of itself, the same run at four overlapping offsets inside
one function. It is gone, and what remains of that shape is the four
`unrolled-repetition` groups above, which are at least two distinct stretches
of code.
