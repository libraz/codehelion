# Contributing

Issues and pull requests are welcome. A typo, a confusing message, a missing
test or a plain bug fix can go straight to a pull request — no issue first. For
something that adds a feature or changes what the detector reports, an issue is
the cheaper path: a short conversation about whether the idea fits costs less
than writing it and finding out afterwards.

This is maintained in spare time, so review is not fast. It does arrive.

Nothing below is a bar you have to clear on your own. It describes what the
code ends up looking like, not a checklist a pull request is scored against.
Where a change is right but the shape around it is off — a missing test, a
recorded number that moved, a commit message in the wrong form — that is
straightened out before it merges, and doing that is the maintainer's job, not
a reason to send the branch back.

## Two boundaries

Most design questions come down to one of these, so they are worth knowing
going in rather than meeting in review:

- **Source analysis never depends on compiled artifacts.** The clone engine
  works on a tree with nothing built in it. Artifact inspection is an optional
  layer on top and no core crate depends on it.
- **Compiler APIs stay out of the CLI.** rustc and Clang are reached through
  separate helper executables over a versioned protocol, so a compiler crash or
  hang cannot take the scan down with it.

You do not have to hold them in your head. `make verify-artifact-boundaries`
and `make verify-helper-boundaries` run in CI and fail on the dependency edge
itself, so crossing one shows up as a red check naming the edge.

Deliberately out of scope: graphical or web interfaces, a hosted service,
general code-quality rules, vulnerability detection, style checking, automatic
refactoring, and languages beyond Rust, C and C++. Those are not bad ideas.
They are other tools.

## Working on a change

Pull requests go to `develop`. `main` only ever fast-forwards from it, so a
branch opened against `main` has to be retargeted before it can merge — GitHub
will suggest `main` by default, and switching an open pull request over is two
clicks. Not worth closing one over.

```sh
make check   # format-check + lint + test + doc, plus the boundary checks
make hooks   # install a pre-commit hook that runs the formatting and lint checks
```

The hook is the mechanical half only — `cargo fmt --check` and `cargo clippy`
with warnings denied — because a hook that takes minutes is a hook people pass
`--no-verify` to. The tests and the boundary checks stay in `make check`.

Run `make check` before pushing: it is the core of what CI runs, and the part
worth having locally. CI adds a dependency audit, a build that proves Fast and
Structural work with no compiler helper present, and the accuracy run over the
corpus. If something fails only on CI, say so in the pull request — that is a
gap in the local checks, and worth fixing at that end too.

What a merged change looks like:

- **Tests ship with the code they cover.** A new function, module or CLI
  behaviour lands with its tests in the same change. Integration tests use real
  SQLite, real parsers and real helper processes rather than mocks. If you are
  not sure how to test the part you touched, open the pull request without and
  say so — that is a normal thing to hand over.
- **`unsafe` is forbidden**, and `unwrap`, `expect`, `panic`, `todo`,
  `unimplemented` and `dbg!` warn outside tests. Clippy runs with `pedantic` and
  `nursery` enabled and warnings denied. It is a strict set, and a first run
  having plenty to say about a patch is normal rather than a bad sign.
- **Comments, identifiers, log messages and commit subjects are English.**
- **Document the reasoning, not just the behaviour.** Module-level docs in
  `codehelion-core` are where the design decisions live; a constant that was
  chosen by measurement should say what the measurement was.

## Changing detection

Detection changes carry more bookkeeping than the rest of the code — not a
higher standard of writing, just more to record, because they move numbers
people compare across runs. Most of this ends up being a conversation in
review rather than something to get right in advance.

- Leave the version constants alone. Every stage carries one — normalization,
  feature extraction, verification weights, grouping rules — and they all reach
  the report header so that two results can be compared honestly. Until the
  first release tag they are all at v1 and stay there: nothing has shipped, so a
  second number can only describe a database or baseline somebody still has on
  disk, and re-running the scan is the whole of the recovery. They start moving
  when there is a released version for them to be moving away from.
- Accuracy is measured against `corpus/`. `make eval` prints the current
  numbers, and putting them before and after the change in the pull request
  helps, though the accuracy job runs on CI either way. The synthetic corpora
  measure recall and are committed, so that part works on a fresh clone. The
  labelled corpora measure precision against hand-written verdicts and need
  their sources fetched with `corpus/scripts/materialize-labeled.sh`; until
  then those cases report as unscored rather than failing.
- Read `corpus/README.md` before changing anything under it, and treat the
  pinned expectations as ground truth: if a change moves them, the pull request
  should say why the new numbers are the correct ones.
- A change that adds or lowers a resource ceiling has to say what happens to the
  report when the ceiling fires. A ceiling that silently drops findings is a
  bug; a ceiling that reports what it dropped is a feature.

## Commits

Conventional Commits (`feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `ci:`,
`chore:`), a scope where it helps, and a body that describes the change itself.
A message in the wrong shape can be rewritten at merge time and is not
something to hold a pull request over.

## Licensing

Contributions are licensed under the [Apache License, Version 2.0](LICENSE),
the same terms as the rest of the project. Section 5 of that license already
says so for anything submitted for inclusion, so there is no separate agreement
to sign and no CLA.

## Reporting a bug

Useful to include: the codehelion version, the operating system, the mode you
ran, and the report header — it records the file counts, the detector versions
and every ceiling that fired, which is usually enough to reconstruct the
situation. If the input is a tree you cannot share, the header alone still
helps, and a report with only part of this is still worth filing.

Security issues go through [SECURITY.md](SECURITY.md), not the public tracker.
