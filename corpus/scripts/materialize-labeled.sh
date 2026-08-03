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
# A case that records an `origin` URL is fetched into `corpus/external/<case>`
# on first use, so the case is reproducible on any machine. A case with only a
# local `repo` path is reproducible only where that path exists, and is skipped
# rather than failed elsewhere: the accuracy run reports an unmaterialized case
# as unscored, which is the honest answer on a machine that cannot reach it.
# A case that names an `origin` it cannot fetch is an error, because that one
# was meant to work anywhere.
#
# Usage: corpus/scripts/materialize-labeled.sh [case ...]
set -euo pipefail

corpus_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
labeled_dir="$corpus_dir/labeled"
external_dir="$corpus_dir/external"

read_key() {
  # Value of a top-level `key = "..."` in a snapshot.toml, ignoring comments.
  sed -n "s/^${2}[[:space:]]*=[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$1" | head -n 1
}

read_paths() {
  # Values of the `paths = ["a", "b"]` array in a snapshot.toml. The array may
  # span lines: a case that names its files one by one is more readable that
  # way, and a git pathspec wildcard is not a substitute because it crosses
  # directory boundaries.
  sed -n '/^paths[[:space:]]*=[[:space:]]*\[/,/\]/p' "$1" |
    tr ',' '\n' | sed -n 's/.*"\([^"]*\)".*/\1/p'
}

fetch_origin() {
  # Make $commit available in a local mirror of $origin, cloning on first use.
  # Kept under corpus/external, which is git-ignored: nothing fetched here is
  # redistributed by this repository.
  local name="$1" origin="$2" commit="$3" dir="$external_dir/$name"
  if [ ! -d "$dir/.git" ]; then
    echo "$name: cloning $origin" >&2
    mkdir -p "$dir"
    git init --quiet "$dir"
    git -C "$dir" remote add origin "$origin"
  fi
  if ! git -C "$dir" cat-file -e "$commit^{commit}" 2>/dev/null; then
    # Fetching one commit needs its full hash; fall back to everything when
    # the server declines to serve a bare object.
    git -C "$dir" fetch --quiet --depth 1 origin "$commit" ||
      git -C "$dir" fetch --quiet --tags origin
  fi
  echo "$dir"
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

  origin="$(read_key "$manifest" origin)"
  repo="$(read_key "$manifest" repo)"
  commit="$(read_key "$manifest" commit)"
  # Read into the array a line at a time rather than with `mapfile`, which
  # macOS does not have: the bash it ships predates it.
  paths=()
  while IFS= read -r path; do
    paths+=("$path")
  done < <(read_paths "$manifest")

  if [ -n "$origin" ]; then
    repo="$(fetch_origin "$name" "$origin" "$commit")" || {
      echo "$name: could not fetch $commit from $origin" >&2
      status=1
      continue
    }
  fi

  # A case that names no origin can only come from a path on this machine, and
  # that path is not one every machine has. Leaving it unmaterialized is the
  # answer, not an error: it costs the run that case's scores and nothing else.
  if [ -z "$origin" ] && [ ! -d "$repo/.git" ]; then
    echo "$name: skipped — $repo is not a git repository on this machine" >&2
    continue
  fi

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
