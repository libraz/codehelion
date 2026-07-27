# Evaluation corpus

Ground-truth data for measuring detector accuracy (precision/recall, findings
per KLOC, false positives per KLOC, result stability). Unlike throwaway
prototypes, this corpus is a lasting asset: later work keeps measuring against
it, so treat changes here as changes to the ground truth.

## Layout

```text
corpus/
  synthetic/   generated mutation cases (seed code + mutation scripts). Committed.
  labeled/     verdicts on real code: labels.json + the commit they are anchored
               to. The sources themselves are NOT committed (git-ignored).
  external/    checkouts of real OSS repositories. NOT committed (git-ignored).
  scripts/     fetch/generate helpers run manually by developers.
```

Only `synthetic/` carries source in the repository, because the generator wrote
it. A labelled case carries its **verdicts** — which is the part that took
judgement and the part worth keeping — plus the commit those verdicts are
anchored to. The code stays where it came from.

`external/` holds snapshots of third-party repositories used for
`precision@top-k` evaluation. These are **not redistributed**: they are cloned
locally by a script in `scripts/`, pinned to a recorded commit hash, and never
committed. codehelion itself performs no network access — fetching is an
explicit developer action, separate from the tool.

## What each half measures

The two committed halves answer different questions, and neither can answer the
other's.

`synthetic/` measures **recall**. A generated corpus knows every clone it
contains, because it made them. It cannot measure precision: it labels the
clones it was built around and nothing else, so an unlabelled true copy that the
detector finds counts against it.

`labeled/` measures **precision**. Each case is a snapshot of a real project,
and what is labelled is what the detector reported: every group carries a
hand-written verdict, either a clone worth reporting or a lookalike that must
not be. It does not measure recall — nobody enumerated the clones in the project
first — so its `clone_pairs` are verdicts on reported groups, not a census.

Cases should come from projects with different authors. A false-positive class
that only ever appears in one author's code cannot be told apart from that
author's habits, and a corpus drawn from a single hand reports a precision
figure about that hand rather than about the detector.

That split is deliberate. Labelling a real tree exhaustively is not work anyone
finishes, and a precision figure that charges the detector for finding something
true is worse than no figure at all.

### Adding a labelled case

1. Write `snapshot.toml`: where the sources come from, the commit, and the paths
   to take from it. Never a live working tree — uncommitted edits shift line
   numbers underneath the labels. Give `origin` (a clone URL) whenever the
   project has one, so the case can be rebuilt on any machine; a bare local
   `repo` path only works where that path exists. A commit reachable by `origin`
   must be written as a full hash — one commit cannot be fetched by an
   abbreviation.
2. Run `corpus/scripts/materialize-labeled.sh` to fetch the project into
   `corpus/external/` and cut `snapshot/` from that commit.
3. Scan it in Structural mode and read **every** group it reports.
4. Record a verdict for each in `labels.json`: a `clone_pair` when the
   duplication is real and worth reporting, a `non_clone` when the two are alike
   for a reason that makes reporting them wrong.
5. Commit `labels.json`, `snapshot.toml` and `SOURCE.md`. Not `snapshot/`.

The commit in `snapshot.toml` is never bumped in place: the verdicts are about
that revision, and moving it invalidates every one of them. A newer revision is
a new case.

A group left without a verdict fails the harness rather than defaulting either
way. When the detector starts reporting something new about labelled code, that
is a verdict waiting to be made.

A verdict whose group the detector no longer reports is kept, not deleted. It
is scored against nothing — a suppressed or absent group is not a finding
anyone was shown — but it is the record of why that group should stay away, and
it is what notices if the group comes back.

A case whose `snapshot/` has not been materialized is reported as unscored, not
scored as perfect — so a machine without the sources gets no precision figure
rather than a flattering one.

### Working rules

Two rules keep this corpus the arbiter rather than a rubber stamp.

**A false positive becomes a label before it becomes a fix.** Reading a bad
finding tells you what a plausible fix would be; it does not tell you whether
the fix costs a true one. Write the verdict first, then change the detector,
and the change arrives with the evidence for it already in place.

**A threshold or default that changes what the report shows carries the corpus
numbers either side of it.** Not the direction — the numbers, per case. A
change that improves one project and costs another is a different change from
one that improves all of them, and only the table says which it is.

Where a change is a threshold rather than a rule, the numbers alone are not
enough: pick the value on all but one case and check it against the one held
back. A value that either does nothing or costs the held-out case its clearest
finding is fitted to the sample, however good the overall figure looks.

Some lookalike classes cannot be labelled from real code at all, because the
detector already drops them and a dropped pair reaches no report. Those belong
in the tests that assert *why* the pair was dropped, which is a stronger claim
than a corpus negative can make: a corpus says the pair went missing, a stat
says it went missing for the stated reason.

### `non_clones` reasons

`reason` is a controlled vocabulary, not free text, so classes of lookalike can
be counted rather than merely described. The ones in use:

| reason | what it names |
|---|---|
| `getter-boilerplate` | accessors whose body is one field read or write |
| `type-dispatch-accessor` | one guard-and-extract skeleton repeated per member type |
| `trivial-factory` | construct-and-return, differing only in the kind constructed |
| `forwarding-wrapper` | a body that is one delegating call |
| `guarded-forwarding` | a validity guard and then one delegating call, differing in what is delegated to |
| `parameterised-dispatch` | one call into a shared generic implementation, differing only in the constants passed |
| `const-overload-pair` | the const and non-const overloads of one operation |
| `trivial-accessor-pair` | two-statement accessors differing in a single operation |
| `type-specialised-variant` | the same routine written once per concrete type or integer width |
| `lifecycle-teardown` | a release routine: an optional null guard, one or more frees, a fixed return |
| `field-mapping-boilerplate` | building a struct out of positional accessors, once per query or row |
| `declaration-run` | a run of declarations or field assignments carrying no logic |
| `list-walk-idiom` | a null guard and a linked-list traversal, the idiom rather than shared logic |
| `unrolled-repetition` | adjacent stretches of one hand-unrolled run, alike because the run repeats one operation |
| `exhaustive-match-table` | two matches that enumerate a type's cases, alike in having one arm per case rather than in what the arms do |
| `nested-inside-copy` | a unit nested inside one member of a real group, related to the other member because that member contains a copy of it |

Extend the table when a case needs a class it does not have; do not reach for
the nearest existing word.

A run inside units the same report already groups is not automatically a
lookalike. It is one when the group is exact, because "these functions are
copies" accounts for every stretch inside them. It is a finding of its own when
the group is gapped: a group at 0.79 says its members are alike overall and
nothing about where they agree exactly, so a stretch they share verbatim is
something only the run can state.

A group can only be refuted when it is distinguishable from the groups around
it. Where a redundant report overlaps a real one by more than the match
threshold, no pair of verdicts can separate them, and both are recorded as what
the underlying duplication is. Such a redundancy is noted in the case's
`SOURCE.md` instead.

## Label format

Labels are machine-readable JSON so they can be checked by a script rather than
maintained as prose tables. The evaluation harness reads them with `serde_json`
(JSON, not YAML: `serde_yaml` is unmaintained and disallowed under
cargo-deny). One label file describes the expected clones (and the deliberate
non-clones) among a set of source files.

Line ranges are used **only** as evaluation input. Stable identity in
codehelion is fingerprint-based, never line- or position-based, so ranges never
feed into any stable ID.

Fields: `type` is one of `type-1 | type-2 | type-3 | restricted-semantic`;
`clone_pairs` are positive examples that should be reported (drives recall);
`non_clones` are boilerplate such as getters/setters, trait impls and test
fixtures that must not be reported (drives precision). `language` is one of
`rust | c | cpp`. Paths are relative to the label file's directory.

```json
{
  "schema_version": 0,
  "language": "rust",
  "files": ["a.rs", "b.rs"],
  "clone_pairs": [
    {
      "id": "cp-001",
      "type": "type-2",
      "fragments": [
        { "file": "a.rs", "start_line": 10, "end_line": 24 },
        { "file": "b.rs", "start_line": 5, "end_line": 19 }
      ]
    }
  ],
  "non_clones": [
    {
      "id": "nc-001",
      "reason": "getter-boilerplate",
      "fragments": [
        { "file": "a.rs", "start_line": 30, "end_line": 33 },
        { "file": "b.rs", "start_line": 40, "end_line": 43 }
      ]
    }
  ]
}
```

The concrete detection-result format that the evaluation harness compares
against these labels is defined alongside the harness itself.

## License policy for corpus contents

- `external/` snapshots are never redistributed; only a fetch script and the
  pinned commit hash live in the repository.
- `labeled/` cases redistribute nothing either: the verdicts are this
  repository's, the code they are about is not. Record each case's origin and
  license in its `SOURCE.md`.
