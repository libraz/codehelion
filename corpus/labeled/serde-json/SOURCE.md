# Provenance

- Project: serde_json, a JSON library written in Rust
- Origin: <https://github.com/serde-rs/json>
- Commit: `de8500740cdcabffb9734f503e4889def823cf10` (release v1.0.151)
- Contents: `src/` — 37 files, about 18k lines. The library only; the test
  suite is left out, being assertions over a handful of documents that
  duplicate themselves for reasons that say nothing about the library.
- License: dual MIT / Apache-2.0.

The sources are not committed under `corpus/labeled/`. `snapshot.toml` records
the origin and the commit they are cut from, and
`corpus/scripts/materialize-labeled.sh` fetches and reconstructs them locally.
The commit is fixed so the line ranges in `labels.json` stay meaningful, and is
never bumped in place: moving it invalidates every verdict recorded against it.

## Why this project

Rust written by someone else, and the first case of that kind here. The other
Rust cases are this repository's own code and one of its author's libraries,
which makes any false-positive class they show ambiguous — a class of defect
and a personal habit look identical when the sample has one author. This is
also the corpus's largest case and the one with the most reported groups, so it
carries more of the precision figure than any other.

It exercises a shape the C cases cannot. Rust libraries that implement a trait
family end up with one method per type and per direction, and a data type with
an owned and a borrowed form ends up with two of everything. Both produce
duplication that is real by every similarity measure, and the two are not worth
the same to a reader.

## What the verdicts show

Forty-four of the seventy-four reported groups are clones worth reporting and
thirty are lookalikes. The classes that account for the lookalikes:

- `type-specialised-variant` (11) — one routine per integer or float width.
  Two of these groups hold eleven and twelve members: every `serialize_i8`
  through `serialize_u128`, and every `write_i8` through `write_f64`.
- `forwarding-wrapper` (8) — an entry point whose body is a buffer and one
  delegating call, or a non-mutating wrapper over the in-place operation.
- `type-dispatch-accessor` (5) — a match that extracts one variant and falls
  back. One group holds nineteen of them.
- `exhaustive-match-table` (3) — two matches that enumerate a type's cases,
  alike in having one arm per case rather than in what the arms do. This class
  is new here: the C cases have no enum big enough to produce it.
- `nested-inside-copy` (6) — new here, and the one class that was a defect
  rather than a judgement call. No longer reported; the labels stay as the
  guard. See below.

What separates a confirmed clone from `type-specialised-variant` is not size
but whether the likeness is the type system's doing. `do_deserialize_i128`
beside `do_deserialize_u128` is confirmed — three hundred tokens of shared
scanning logic that differ in one match arm — while `as_u64` beside `as_u128`
is refuted, because nothing but the return type differs and Rust demands the
two be separate functions.

## `nested-inside-copy`

Six split pairs related a nested visitor method to a whole function that
contains a copy of it. `raw.rs` has two `Deserialize` impls whose bodies are
identical but for a type name, each holding its own `visit_map`. The report
already stated both facts: one group for the two outer functions, one for the
two inner ones. The six split pairs then related one file's inner function to
the other's outer function, at a two-to-one token ratio, and claimed
eighty-four per cent similarity — which was true only because the smaller side
is contained in the larger side's twin.

They were labelled before being fixed, as the corpus's working rule requires,
and the labels are what the fix was measured against: the six are gone, both
groups they derived from are still reported, and the only other finding the
change removed is the one described next. The verdicts remain as the guard —
if a crossing of this shape comes back, it comes back as a refuted finding
rather than as an unexplained rise in the count.

## Verdicts that could not be separated

Three findings once described one duplication in `de.rs`: the pair of outer
`next_element_seed` / `next_key_seed`, the pair of nested `has_next_element` /
`has_next_key`, and a split pair crossing the two. Every one of them overlapped
the others by more than the match threshold, so no set of verdicts could rule
on them separately, and all three were recorded as what the underlying
duplication is, which is a real clone. The crossing is the same shape as
`nested-inside-copy` and left with them, which is why the confirmed count is
one lower than the verdicts: the duplication it described is still reported, by
the two groups that remain.

One group holds two identical `deserialize_enum` bodies and a third member,
`visit_str`, that shares only their shape. It is confirmed, because the
duplication the group is about is real; the third member is the grouping
placing a lookalike beside it, which no verdict on this group can say.
