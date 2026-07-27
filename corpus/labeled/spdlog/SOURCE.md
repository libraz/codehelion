# Provenance

- Project: spdlog, a logging library written in C++
- Origin: <https://github.com/gabime/spdlog>
- Commit: `79524ddd08a4ec981b7fea76afd08ee05f83755d` (release v1.17.0)
- Contents: the library's own headers — 82 files, about 10k lines.
  `include/spdlog/fmt/bundled` is a second project vendored in whole; it says
  nothing about this one and carries more lines than everything else here put
  together, so it and the thin wrappers over it are left out.
- License: MIT.

The sources are not committed under `corpus/labeled/`. `snapshot.toml` records
the origin and the commit they are cut from, and
`corpus/scripts/materialize-labeled.sh` fetches and reconstructs them locally.
The commit is fixed so the line ranges in `labels.json` stay meaningful, and is
never bumped in place: moving it invalidates every verdict recorded against it.

## Why this project

C++ written by someone else, and the first case of that kind here — the other
C++ case is one of this repository's author's libraries, which makes any
false-positive class it shows ambiguous between a defect and a personal habit.

It is also the first header-only library, and that turned out to matter before
any verdict was written. A tree with no `.cpp` file has nothing to settle its
bare `.h` headers from, and settling them by default read the whole project
with the C grammar: 28.2 per cent of its tokens landed inside error regions
against 2.8 per cent under the C++ grammar. The verdicts here are recorded
against the C++ reading; a case labelled before that was noticed would have
been ruling on a project the parser had mostly not seen.

What the library brings that the C cases cannot: template classes instantiated
per mutex type, SFINAE overload pairs, `_mt`/`_st` factory families, and a
hand-written formatter dispatch table of about thirty small classes.

## What the verdicts show

Twenty-one of the thirty-nine reported groups are clones worth reporting and
eighteen are lookalikes. One of the eighteen is no longer reported — a shape
the tool now recognises and withholds — so what a scan puts up for scoring
today is twenty-one against seventeen. The classes that account for the
lookalikes:

- `getter-boilerplate` (4) — a lock and one assignment, or a lock and one
  return. One group holds five of them, drawn from three unrelated classes.
- `type-specialised-variant` (4) — the `_mt`/`_st` factory pair, the narrow and
  wide `to_string_view`, the SFINAE pair selected on a log-id constant, and
  `clone` written once in the base class and once in the derived one.
- `forwarding-wrapper` (3) — `localtime` beside `gmtime`, and the pair of
  one-line platform conditionals that stand for `isatty` and `getpid`. That
  pair is now withheld: each body is two `return`s under `#ifdef _WIN32` with
  nothing choosing between them, so what the two share is the platform split
  and not a duplicate. Its label stays as the guard that notices if it comes
  back.
- `guarded-forwarding` (2), `mirrored-operation` (2), and one each of
  `dispatch-table-entry`, `validated-setter` and `member-call-run`.

Four classes are new here. `mirrored-operation` is the one worth naming: a
bounded queue's `enqueue` and `dequeue` agree on every measure — same lock,
same condition variable wait, same single container call — because each is the
other read backwards, and no refactoring turns two dual operations into one.

## The formatter dispatch table

Five groups relate handlers in `pattern_formatter-inl.h`, which spells one
small class per format flag. Four are confirmed and one is refuted, on one
question: does removing the duplication remove a decision or only a spelling?

The six handlers that render a weekday or month name differ in which table they
index and which `tm` field they index it by — two parameters, six bodies, and a
template that takes both. The three that render fractional seconds differ in a
chrono duration and two constants. Those are worth acting on. The pair that
renders the logger name and the payload differ in which member of `log_msg`
they read, and each body is two statements: the template that removed them
would be as long as what it saved. That one is `dispatch-table-entry`.

## Duplication the platform split produced

`tcp_client.h` and `tcp_client-windows.h` are two implementations of one
client, and `udp_client-windows.h` is a third copy of the Windows one with the
protocol name changed. Three groups come from that, and all three are
confirmed: a fork maintained by copying is duplication whoever has to change
both ends of it. The same holds for the daily and hourly file sinks, which
share five groups and differ in an interval.

## A pairing that is absent for the right reason

Two findings relate the blocking queue's `enqueue` to its `dequeue`, once for
each of the two queue implementations `mpmc_blocking_q.h` holds. Both are
`mirrored-operation`. The pairing a reader might expect instead — the two
`enqueue` bodies against each other, which differ only in a block scope — is
reported nowhere, and that is correct rather than missing: the two
implementations sit under the two arms of one `#ifndef __MINGW32__`, so no
build holds both and neither is a copy the other's compilation could have
removed. The case therefore also stands as evidence for the conditional-arms
rule, which nothing else in the labelled corpora exercises.
