# Provenance

- Project: `fast-yaml` — a YAML parser compiled to WebAssembly
- Commit: `5317da2`
- Contents: the project's own `src/` Rust sources. Vendored third-party code
  under `third_party/` is excluded and was not scanned.
- Author: libraz, who is also this project's author.

The sources are not committed here. `snapshot.toml` records the commit they are
cut from and `corpus/scripts/materialize-labeled.sh` reconstructs them locally.
The commit is fixed so the line ranges in `labels.json` stay meaningful, and is
never bumped in place: moving it invalidates every verdict recorded against it.

## Why this project

A small, ordinary Rust library: it reports one group over a thousand lines. That
is the point — a case where the detector says almost nothing is as much a fact
about its precision as a case where it says a great deal.
