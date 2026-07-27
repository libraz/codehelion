# Provenance

- Project: bitflags, a Rust library for typed sets of bit flags
- Origin: <https://github.com/bitflags/bitflags>
- Commit: `f92a2921b41644b02ca5d50a6ace542e309e6a6f` (release 2.13.1)
- Contents: the crate — 45 files, about 6k lines, its test modules included.
- License: MIT OR Apache-2.0.

The sources are not committed under `corpus/labeled/`. `snapshot.toml` records
the origin and the commit they are cut from, and
`corpus/scripts/materialize-labeled.sh` fetches and reconstructs them locally.
The commit is fixed so the line ranges in `labels.json` stay meaningful, and is
never bumped in place: moving it invalidates every verdict recorded against it.

## Why this project

One boilerplate class — a body that is nothing but a run of macro invocations —
was ranked down in every report with no case here holding a single instance of
it. A default that decides where findings land, measured by nothing, is a guess
however reasonable it sounds.

Finding an instance took a search rather than a guess. Over a sample of 142
Rust crates and the 8140 groups they produce, the class accounts for 86 groups,
one in a hundred, and 81 of those 86 are test code — already ranked down for a
different reason. It is not written in production logic, because a function
whose body is only macro calls and no ordinary statements is a shape almost
nothing but a test has. bitflags is where the class is densest per group
reported and the crate is still small enough to rule on in full.

That is also why this case keeps its test modules when every other case here
leaves the suite out. A suite repeats itself for reasons that say nothing about
the library it covers, which is the usual argument for cutting it; here it is
the only place the shape under judgement is written.

## What the verdicts show

Sixteen of the twenty-five reported groups are clones worth reporting and nine
are lookalikes.

Four groups are in the library itself, and three of them are confirmed: the two
`ParseError` constructors that spell the same conditional stringification, the
strict parser written as a copy of the ordinary one — the source says so in a
comment — and the three `Flags` mutators that each reinterpret their own bits
through the same incantation before applying one set operation. The fourth,
`known_bits` against `unknown_bits`, is refuted: they are one mask and its
complement, and no consolidation of them leaves less code than it took.

The rest are in the suite, thirteen confirmed and eight refuted, and the line
between them is what the bodies hold. The suite is built around a per-module
`case` helper that checks one operation four ways — inherent method, trait
method, operator, compound assignment — and those helpers are copies of one
another across eight modules. Each copy carries the decision about what four
spellings are worth checking, so changing that decision means editing all
eight: duplication a reader can act on, and five of the confirmed groups relate
them. Five more relate the parser's own tests, which are one test body written
once per parsing entry point, and the last three are a test written twice for
two flag types.

Refuted against that: the `cases` functions that call the helpers, because all
each holds is the list of inputs that module happens to test, and the
three-line `write` shims that exist so a module's cases can name their writer
in one word.

## What the run of macros is worth ranking down

All four groups carrying the class are refuted, against sixteen of the other
twenty-one confirmed. They relate an error-message test to a `collect` test to
a formatting helper, or three operator tests to a pair of unrelated `case`
helpers — bodies alike in being a run of assertions and in nothing else. Where
a body is only assertion macros there is nothing left for a similarity measure
to read but their number and their shape, and enough test bodies of a similar
length will match on that alone.

All four are also test code, so on this project the class ranks down nothing
the suite rule would not have reached anyway. That is the usual case rather
than an accident of this one: across the sample of 142 crates, 83 of the 86
groups the class marks are test code as well. The three that are not are a
`fmt` written as two `#[cfg]`-alternative bodies and a pair of macro
definitions, all of them lookalikes too, and all of them the kind of finding
nothing else here would have filed below the rest.

## The suite is recognised from one line in the crate root

bitflags declares `#[cfg(test)] mod tests;` in `lib.rs` and writes the module
in `tests.rs` and a directory of files beside it, which no other case here
does. Every group in that tree is test code on the strength of that one line:
the functions carrying `#[test]` would be recognised without it, but the
`#[track_caller] fn case` helpers they call carry no marker of their own, and a
group holding one of those is recognised only by following the declaration to
the files it names.
