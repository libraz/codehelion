# Contributing

Issues and pull requests are welcome, but review may take a while, and a change
that widens the project's scope is likely to be declined even if it is well
written. Opening an issue before a large change saves both of us the work.

## Before you start

Two boundaries decide most design questions, and a patch that crosses either
will be sent back:

- **Source analysis never depends on compiled artifacts.** The clone engine
  works on a tree with nothing built in it. Artifact inspection is an optional
  layer on top and no core crate depends on it.
- **Compiler APIs stay out of the CLI.** rustc and Clang are reached through
  separate helper executables over a versioned protocol, so a compiler crash or
  hang cannot take the scan down with it.

Both are checked mechanically: `make verify-artifact-boundaries` and
`make verify-helper-boundaries` run in CI and fail if a dependency edge appears.

Out of scope, deliberately: graphical or web interfaces, a hosted service,
general code-quality rules, vulnerability detection, style checking, automatic
refactoring, and support for languages beyond Rust, C and C++.

## Working on a change

```sh
make check   # format-check + lint + test + doc, plus the boundary checks
make hooks   # install a pre-commit hook that runs the above
```

`make check` is what CI runs. Run it before pushing.

- **Tests ship with the code they cover.** A new function, module or CLI
  behaviour lands with its tests in the same change. Integration tests use real
  SQLite, real parsers and real helper processes rather than mocks.
- **`unsafe` is forbidden**, and `unwrap`, `expect`, `panic`, `todo`,
  `unimplemented` and `dbg!` warn outside tests. Clippy runs with `pedantic` and
  `nursery` enabled and warnings denied.
- **Comments, identifiers, log messages and commit subjects are English.**
- **Document the reasoning, not just the behaviour.** Module-level docs in
  `codehelion-core` are where the design decisions live; a constant that was
  chosen by measurement should say what the measurement was.

## Changing detection

Detection changes are held to a higher bar than the rest of the code, because
they move numbers other people depend on.

- Anything that changes which findings are produced — normalization, feature
  extraction, verification weights, grouping rules — must bump the version
  constant that travels with the detector identity, so two results can be
  compared honestly.
- Accuracy is measured against `corpus/`. The synthetic corpora measure recall;
  the labelled corpora measure precision against hand-written verdicts. Read
  `corpus/README.md` before touching either, and treat the pinned expectations
  as ground truth: if a change moves them, the pull request should say why the
  new numbers are the correct ones.
- A change that adds or lowers a resource ceiling has to say what happens to the
  report when the ceiling fires. A ceiling that silently drops findings is a
  bug; a ceiling that reports what it dropped is a feature.

## Commits

Conventional Commits (`feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `ci:`,
`chore:`), a scope where it helps, and a body that describes the change itself.

## Reporting a bug

Include the codehelion version, the operating system, the mode you ran, and the
report header — it records the file counts, the detector versions and every
ceiling that fired, which is usually enough to reproduce the situation. If the
input is a tree you cannot share, the header alone is still useful.

Security issues go through [SECURITY.md](SECURITY.md), not the public tracker.
