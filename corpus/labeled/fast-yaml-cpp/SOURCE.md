# Provenance

- Project: `fast-yaml-cpp` — a YAML parser exposed to Node.js through N-API
- Commit: `ea193f9`
- Contents: the project's own `src/` and `include/` C and C++ sources. Vendored
  third-party code under `third_party/` is excluded and was not scanned.
- Author: libraz, who is also this project's author.

The sources are not committed here. `snapshot.toml` records the commit they are
cut from and `corpus/scripts/materialize-labeled.sh` reconstructs them locally.
The commit is fixed so the line ranges in `labels.json` stay meaningful, and is
never bumped in place: moving it invalidates every verdict recorded against it.

## Why this project

Binding code is where duplication of the kind this tool looks for actually
lives: argument checking, option extraction and exception translation repeated
once per exported function. It also carries the lookalikes worth telling apart —
type-dispatch accessors, const/non-const overload pairs, delegating wrappers.
