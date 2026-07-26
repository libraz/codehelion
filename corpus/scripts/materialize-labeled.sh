#!/usr/bin/env bash
# Reconstruct the sources of every labelled corpus case from its pinned commit.
#
# The verdicts in a case's labels.json are anchored to line ranges, so they only
# mean anything against one exact revision. That revision is recorded in the
# case's snapshot.toml and extracted here into `snapshot/`, which is git-ignored:
# the sources belong to the projects they came from, not to this repository.
#
# Extraction is from the object database, never from a working tree — a tree
# with uncommitted edits shifts line numbers underneath the labels.
#
# Usage: corpus/scripts/materialize-labeled.sh [case ...]
set -euo pipefail

labeled_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../labeled" && pwd)"

read_key() {
  # Value of a top-level `key = "..."` in a snapshot.toml, ignoring comments.
  sed -n "s/^${2}[[:space:]]*=[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$1" | head -n 1
}

read_paths() {
  # Values of the `paths = ["a", "b"]` array in a snapshot.toml.
  sed -n 's/^paths[[:space:]]*=[[:space:]]*\[\(.*\)\].*/\1/p' "$1" |
    tr ',' '\n' | tr -d ' "' | grep -v '^$'
}

cases=("$@")
if [ ${#cases[@]} -eq 0 ]; then
  while IFS= read -r manifest; do
    cases+=("$(basename "$(dirname "$manifest")")")
  done < <(find "$labeled_dir" -mindepth 2 -maxdepth 2 -name snapshot.toml | sort)
fi

status=0
for name in "${cases[@]}"; do
  manifest="$labeled_dir/$name/snapshot.toml"
  if [ ! -f "$manifest" ]; then
    echo "$name: no snapshot.toml" >&2
    status=1
    continue
  fi

  repo="$(read_key "$manifest" repo)"
  commit="$(read_key "$manifest" commit)"
  mapfile -t paths < <(read_paths "$manifest")

  if [ ! -d "$repo/.git" ]; then
    echo "$name: $repo is not a git repository — clone it there first" >&2
    status=1
    continue
  fi
  if ! git -C "$repo" cat-file -e "$commit^{commit}" 2>/dev/null; then
    echo "$name: $repo has no commit $commit — fetch it first" >&2
    status=1
    continue
  fi

  target="$labeled_dir/$name/snapshot"
  rm -rf "$target"
  mkdir -p "$target"
  git -C "$repo" archive "$commit" -- "${paths[@]}" | tar -x -C "$target"
  echo "$name: $commit -> ${target#"$PWD"/}"
done

exit "$status"
