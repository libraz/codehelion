# Analysis modes

There are two build-free modes and one compiler-assisted mode. The mode is part
of the run's identity, so results read one way are never compared with results
read another way.

![What each analysis mode measures](../images/modes.svg)

## Fast

Token-level detection of Type-1 (identical) and Type-2 (renamed identifiers,
changed literals) copies. Comments and whitespace are removed before comparison,
so a comment-only edit does not split one finding into two.

Fast is the default because it is the cheapest thing that answers a real
question. What it does not measure is everything that needs a parsed shape:
gapped copies, identifier agreement, the similarity breakdown, siblings and near
misses. The suppression policies for boilerplate, test code and integer-width
families need those classifications too, so Fast cannot apply them and says so
in the report.

On a tree of any size, that makes a Fast report longer than it is useful. Use it
where the question is "is this file a copy of that one", and use Structural where
the question is "what should I look at first".

## Structural

Structural adds Type-3 detection — copies that differ by added, removed or
changed statements — and reports the per-dimension similarity each finding was
judged on. It parses; it still never runs anything in the tree.

```sh
codehelion scan --mode structural
```

Structural is what makes the report orderable. It measures identifier agreement
against the canonical member, it produces the similarity breakdown that says
*how* two occurrences are alike, and it runs the two sibling channels and the
near-miss band described in [Grouping](grouping.md). It also applies the
suppression policies, which is what keeps generated code, test fixtures and
one-routine-per-integer-width families from crowding out the findings worth
reading.

The cost is time and memory rather than setup: no build, no toolchain, nothing
installed beyond the binary.

## Semantic

> **Pre-1.0 surface.** This is documented and tested, but has not had the real
> use that would make it worth a promise, so it can change between releases.

Semantic adds compiler-resolved type and name information and the registered
semantic rules on top of everything Structural measures.

```sh
codehelion scan --mode semantic
```

It needs a helper for each language it should analyse — `codehelion-backend-rust`
for Rust, `codehelion-backend-clang` for C and C++ — installed on `PATH` or named
with `--helper`. `codehelion doctor` reports which are present, the protocol
version each speaks, the compiler each found, and what each says it can supply.
A language whose helper is missing is analysed as Structural rather than failing
the run.

The helpers are separate processes reached over a versioned protocol, so no
compiler API is linked into the CLI. A compiler crash ends a helper process; the
scan records that unit as unavailable and continues. See
[Architecture](architecture.md).

Semantic runs none of the project's own code unless an execution class is
explicitly permitted:

```sh
codehelion scan --mode semantic --allow-execution=build-script
```

Nothing in the tree executes without that flag, and `--untrusted` permits no
execution at all. See [Local execution and trust](security.md).

Two comparisons are Semantic-only and opt-in. `--compare-build-variants`
compares exact duplicate units between distinct C/C++ build variants, and
`--compare-languages` compares registered Rust and C++ pipelines across
explicitly selected compilation partitions. Both emit a separate comparison;
neither changes an ordinary scan's partitions.

## Choosing

| The question | The mode |
|---|---|
| Is this file a copy of that one? | Fast |
| What should I look at first, in a tree of any size? | Structural |
| Did I miss a call site in the refactor I just finished? | Structural |
| Are these two the same routine after the compiler resolves the names? | Semantic |

A dimension a mode cannot measure is reported as absent, never guessed, so a
report always says which of these it was able to answer.
