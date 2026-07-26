# Provenance

- Project: this repository's own storage layer (`crates/codehelion-store/src`)
- Commit: `f9db8ef`
- Contents: one crate, scoped so every group the detector reports over it can be
  read and ruled on.
- License: Apache-2.0, the same as the rest of this repository.

The sources are not committed under `corpus/labeled/`. `snapshot.toml` records
the commit they are cut from and `corpus/scripts/materialize-labeled.sh`
reconstructs them locally. The commit is fixed so the line ranges in
`labels.json` stay meaningful, and is never bumped in place: moving it
invalidates every verdict recorded against it.

## Why this project

Dogfooding, and a second reading of one lookalike class. The delegating-wrapper
pair here (`open` / `open_in_memory`) is the same shape as the one in the C++
case, in a different language and a different author's idiom — which is what
separates a class of false positive from a quirk of one project.

It also carries a class the C++ case does not: closures that build a struct out
of positional row accessors, which repeat once per query and cannot be shared
without a derive macro.
