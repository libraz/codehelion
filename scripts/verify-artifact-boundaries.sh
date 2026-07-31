#!/bin/sh
# The source clone engine remains useful when no artifact exists. Keep its
# normal dependency closure independent of every artifact parser and metric
# crate, even though the command-line package may opt into those facilities.
set -eu

cargo_cmd=${CARGO:-cargo}
dependency_file=$(mktemp "${TMPDIR:-/tmp}/codehelion-core-artifact-deps.XXXXXX")

cleanup() {
    rm -f "$dependency_file"
}
trap cleanup EXIT HUP INT TERM

"$cargo_cmd" tree --locked --package codehelion-core --edges normal --target all \
    --no-dedupe --prefix none --format '{p}' >"$dependency_file"

while IFS= read -r dependency; do
    crate=${dependency%% *}
    case "$crate" in
        codehelion-artifact|codehelion-artifact-*)
            printf '%s\n' "error: codehelion-core normally depends on artifact crate $crate" >&2
            printf '%s\n' '       the source clone engine must remain artifact-backend independent.' >&2
            exit 1
            ;;
    esac
done <"$dependency_file"

printf '%s\n' 'artifact dependency boundary verified'
