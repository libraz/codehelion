# Provenance

- Project: TinyXML-2, an XML parser written in C++
- Origin: <https://github.com/leethomason/tinyxml2>
- Commit: `8224e427b655b83dae5e2298f1e6919523a78737`
- Contents: the whole library — two files, about 5.4k lines. `xmltest.cpp` is
  the suite and is left out: it is one function holding thousands of
  assertions, and what it would add is a lookalike class the corpora already
  carry.
- License: zlib.

The sources are not committed under `corpus/labeled/`. `snapshot.toml` records
the origin and the commit they are cut from, and
`corpus/scripts/materialize-labeled.sh` fetches and reconstructs them locally.
The commit is fixed so the line ranges in `labels.json` stay meaningful, and is
never bumped in place: moving it invalidates every verdict recorded against it.

## Why this project

The second C++ case written by someone else, and the reason for it is the
first. Every lookalike class the other one contributed came from one library by
one author, which leaves each of them ambiguous between something about C++ and
something about that author. This library is C++ of an entirely different kind:
no templates in the API surface, no standard containers, manual memory out of
per-type pools, and control flow a C programmer would recognise. A class that
shows up in both is about the language.

It also brings a shape none of the other cases has in quantity: a public API
that is an overload set. Eight `SetAttribute`, seven `QueryIntAttribute`
siblings, seven `SetText`, seven `PushText`, seven `Query…Text` — the library
spells one entry point per scalar type, four times over. That makes it the
hardest case here by precision, and the most useful one for the largest
lookalike class.

## What the verdicts show

Twenty-nine reported groups: eleven are clones worth reporting and eighteen are
lookalikes. Six of the eighteen are already withheld — shapes the tool
recognises — so what a scan puts up for scoring is eleven against twelve, the
lowest precision of any case here. The classes that account for the lookalikes:

- `type-specialised-variant` (6) — the overload sets, at every layer: the
  attribute setters that format a scalar into a buffer, the accessors that read
  one back, the per-width float and double conversions.
- `forwarding-wrapper` (3) and `trivial-factory` (3) — the visitor's per-node
  overrides, the handle accessors, and the five `InsertNew…` and five `New…`
  constructors that differ in the node type they allocate.
- one each of `const-overload-pair`, `declaration-run`, `guarded-forwarding`,
  `member-call-run`, `mirrored-operation` and `single-expression-return`.

## Where one family splits

Three layers of one API are reported separately, and they do not get the same
verdict. `QueryIntAttribute` and its six siblings find the attribute, return
early when it is absent, and delegate — refuted. `QueryIntValue` and its six
siblings call one converter and map success onto one of two error codes —
refuted. `QueryIntText` and its six siblings ask whether the first child is
text, read it, convert it, and choose between two different failures — and
those are confirmed.

Same author, same file, same seven types, and the bodies differ only in which
converter they name. What separates them is whether the replacement costs as
much as what it saves: seven two-statement bodies still need seven
declarations, so the template that removed them would be the same size, while
seven eleven-line bodies each repeat a three-way decision about where the text
was and whether it converted. The corpora have twice found that no threshold on
length, similarity or body shape draws this line, and this family is why —
these are the same shape at three sizes, and the verdict changes in the middle.

The same question decides the two pairs of integer parsers. `ToInt` against
`ToInt64` and `ToUnsigned` against `ToUnsigned64` are confirmed, because what
each pair repeats is the policy that a leading `0x` selects a hexadecimal
format — a decision that has to stay in step across four functions and did not
arrive in them at the same time. `ToFloat` against `ToDouble` is refuted: the
two share a call and a format letter and no policy at all.

## A lookalike class this case needed

`single-expression-return` is new here. `IsNameChar` — a character class test
written as four disjuncts — is reported against `ErrorStr`, which is one
ternary over an empty check. Neither body is anything but a `return`, and that
is the entire resemblance: two compound expressions of about the same size,
computing things with nothing in common. It is the lowest-scoring group in the
case, and the only one whose two sides come from different files.

## What the overload sets are worth as evidence

`type-specialised-variant` was already the largest lookalike class in the
corpora, and it had been drawn from a C library, a Rust one and one C++
library. This case adds a second C++ author and, more usefully, a second kind
of C++: the other one specialises by instantiating templates, this one by
writing the overloads out. Both produce the class, which is what says the class
is about what an API has to spell rather than about how either author writes.
