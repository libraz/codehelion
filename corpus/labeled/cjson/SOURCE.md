# Provenance

- Project: cJSON, a JSON parser written in C
- Origin: <https://github.com/DaveGamble/cJSON>
- Commit: `acc76239bee01d8e9c858ae2cab296704e52d916` (release v1.7.18)
- Contents: `cJSON.c`, `cJSON.h`, `cJSON_Utils.c`, `cJSON_Utils.h` — about 5k
  lines. Tests, fuzzers and the build system are left out.
- License: MIT.

The sources are not committed under `corpus/labeled/`. `snapshot.toml` records
the origin and the commit they are cut from, and
`corpus/scripts/materialize-labeled.sh` fetches and reconstructs them locally.
The commit is fixed so the line ranges in `labels.json` stay meaningful, and is
never bumped in place: moving it invalidates every verdict recorded against it.

## Why this project

C written by someone else, in a different style from the other C case: a small
library shaped by its public API rather than by performance. Where that case
repeats a routine per integer width, this one repeats it per JSON type, so the
two disagree about which lookalike classes dominate and agree about which ones
exist at all.

It is also one of the few real trees small enough to rule on exhaustively while
still being written without any thought of this tool.

## What the verdicts show

The lookalikes here are the API surface: one predicate, one constructor and one
`Add…ToObject` per JSON type, plus the case-sensitive twin of every lookup.
None of them can be collapsed without changing the public interface.

The clones are the opposite — parsing and printing an array and an object share
their whole skeleton, and two files carry independent copies of the same
doubly-linked-list surgery and the same float comparison.

Two groups are refuted for a reason that is not about the code at all: the
detector reported a run of statements as a fragment group when it had already
reported the enclosing functions as a unit group, so the same duplication
arrives twice. Those carry `subsumed-by-unit-clone`.
