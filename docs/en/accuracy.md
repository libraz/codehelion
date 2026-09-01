# Accuracy

The figures below are what `make eval` prints from a checkout, and the values are
pinned by the tests that produce them: a detector change that moves one fails the
suite until somebody records the new value, and fails again until this page says
the same thing.

The generated corpora are committed, so the recall numbers are reproducible from
a checkout on their own. The labelled cases commit their verdicts and not their
sources, so the precision numbers need `corpus/scripts/materialize-labeled.sh`
run first. `corpus/README.md` explains why each half can answer only one of the
two questions.

## Recall

Ten generated mutation corpora, 43 clone pairs and 11 deliberate non-clones. A
generated corpus knows every clone it contains, so it can be scored for recall.
It cannot be scored for precision: it labels the clones it was built around and
nothing else, so an unlabelled true copy would count against the detector.

| corpus | Fast | Structural |
|---|---|---|
| rust | 0.7143 | 1.0000 |
| c | 0.8333 | 1.0000 |
| cpp | 0.8571 | 1.0000 |
| cpp-common-signature | 1.0000 | 1.0000 |
| rust-graded | 1.0000 | 1.0000 |
| rust-literals | 1.0000 | 1.0000 |
| rust-replaced | 1.0000 | 1.0000 |
| rust-negative | 1.0000 | 1.0000 |
| rust-partial | 1.0000 | 0.5000 |
| rust-divergent | 0.4000 | 0.8000 |

Fast mode reaches no type-3 clone at all in `rust`, `c` and `cpp`, which is the
cost of skipping the structural pass rather than a tuning question.
`rust-partial` is the one corpus where Structural mode scores below Fast.
`cpp-common-signature` is there for the signature sibling channel: nine functions
share one callable shape, and what it fixes is that withholding a shape that
common as evidence costs the primary result nothing.

The six restricted-semantic corpora are not scored here. Each registered rule is
asserted by its own tests, which state why a pair matched or was dropped — a
stronger claim than a corpus average over rules that answer different questions.

## Precision

Eight labelled snapshots of real projects, 141 clone-pair and 177 non-clone
verdicts. Every group the detector reported on these trees carries a hand-written
verdict, so precision is measurable. Recall is not: nobody enumerated the clones
in those projects first.

| case | Structural precision | confirmed | refuted |
|---|---|---|---|
| codehelion-store | 1.0000 | 2 | 0 |
| fast-yaml | 1.0000 | 1 | 0 |
| cjson | 0.8235 | 14 | 3 |
| bitflags | 0.7857 | 11 | 3 |
| spdlog | 0.5833 | 21 | 15 |
| serde-json | 0.5357 | 45 | 39 |
| lz4 | 0.5357 | 15 | 13 |
| tinyxml2 | 0.5263 | 10 | 9 |
| **all cases** | **0.5920** | **119** | **82** |

Two of the eight are this author's own projects, and both score 1.0000. Dropping
them moves the aggregate to 0.5859 — they carry 3 of the 201 verdicts, so the
figure is the other six projects' either way.

## What the ordering is worth

0.5920 is the figure for the whole report read end to end, which is not how a
duplication report is read. Over the 200 of those verdicts a finding of its own
carries — the report shows a duplication that is a shorter cut of another inside
the longer one, so it takes no place of its own in the order:

| ordered by | p@10 | p@50 | MAP |
|---|---|---|---|
| priority | 1.0000 | 0.9600 | 0.9290 |
| size | 1.0000 | 0.9400 | 0.8772 |

Nothing false reaches the first ten either way. What the aggregate says is that
the tail is close to half noise, which is why the priority ordering and
`--mode structural` are defaults rather than options.

## Reproducing this

```sh
make eval
```

The snapshots the verdicts are anchored to are fetched by
`corpus/scripts/materialize-labeled.sh` and never redistributed. A case that has
not been materialized is reported as unscored rather than scored as perfect.
