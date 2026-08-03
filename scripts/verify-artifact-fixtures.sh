#!/bin/sh
# Build the repository-owned artifact fixtures and exercise the CLI against
# real WASM and ELF bytes. The programs are only compiled; codehelion never
# loads or executes either artifact.
set -eu

case "$(uname -s)" in
    Linux) ;;
    *)
        printf '%s\n' 'artifact fixture verification requires a Linux ELF toolchain' >&2
        exit 2
        ;;
esac

if ! command -v objcopy >/dev/null 2>&1; then
    printf '%s\n' 'artifact fixture verification requires objcopy for the split-debug input' >&2
    exit 2
fi

temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/codehelion-artifact-fixtures.XXXXXX")

cleanup() {
    rm -rf "$temporary_root"
}
trap cleanup EXIT HUP INT TERM

fixture_root="$temporary_root/fixture"
cp -R fixtures/artifact "$fixture_root"

(
    cd "$fixture_root"
    sh build.sh debug --with-elf
    sh build.sh debug --deduplicated --with-elf
    sh build.sh release --lto --with-elf
    sh build.sh release --lto --deduplicated --with-elf
)

cargo run --quiet -p codehelion -- scan \
    "$fixture_root" \
    --mode structural \
    --format json \
    --db "$temporary_root/artifact.sqlite" \
    --output "$temporary_root/source-scan.json"
source_run=$(sed -n 's/^[[:space:]]*"run_id": \([0-9][0-9]*\),\{0,1\}$/\1/p' "$temporary_root/source-scan.json")
test -n "$source_run"

cargo run --quiet -p codehelion -- artifact analyze \
    "$fixture_root/build/debug/duplicates.wasm" \
    --format json \
    --build-variant "$fixture_root/build/debug/build-variant.json" \
    --source-run "$source_run" \
    --db "$temporary_root/artifact.sqlite" \
    --output "$temporary_root/wasm.json"
cargo run --quiet -p codehelion -- artifact analyze \
    "$fixture_root/build/debug/libduplicates.so" \
    --format json \
    --build-variant "$fixture_root/build/debug/build-variant.json" \
    --source-run "$source_run" \
    --linker-map "$fixture_root/build/debug/libduplicates.map" \
    --db "$temporary_root/artifact.sqlite" \
    --output "$temporary_root/elf.json"
# Calibration measures the savings model over one clone group, so it needs a
# group the analysis actually attributed artifact bytes to. Only a group whose
# every non-canonical member was attributed carries an estimate, and reading it
# out of the report says which one that was instead of assuming.
calibration_group=$(awk '
    /"clone_group_fingerprint":/ {
        fingerprint = $2
        gsub(/[",]/, "", fingerprint)
    }
    /"estimated_refactor_savings_bytes": -?[0-9]/ { print fingerprint; exit }
' "$temporary_root/elf.json")
test -n "$calibration_group"
objcopy --only-keep-debug \
    "$fixture_root/build/debug/libduplicates.so" \
    "$temporary_root/libduplicates.debug"
cp "$fixture_root/build/debug/libduplicates.so" "$temporary_root/libduplicates-split.so"
objcopy --strip-debug "$temporary_root/libduplicates-split.so"
cp "$fixture_root/build/debug-deduplicated/libduplicates.so" \
    "$temporary_root/libduplicates-split-deduplicated.so"
objcopy --strip-debug "$temporary_root/libduplicates-split-deduplicated.so"
cargo run --quiet -p codehelion -- artifact analyze \
    "$temporary_root/libduplicates-split.so" \
    --format json \
    --build-variant "$fixture_root/build/debug/build-variant.json" \
    --source-run "$source_run" \
    --debug-file "$temporary_root/libduplicates.debug" \
    --db "$temporary_root/artifact.sqlite" \
    --output "$temporary_root/elf-split-debug.json"
cargo run --quiet -p codehelion -- artifact analyze \
    "$fixture_root/build/release-lto/libduplicates.so" \
    --format json \
    --build-variant "$fixture_root/build/release-lto/build-variant.json" \
    --source-run "$source_run" \
    --db "$temporary_root/artifact.sqlite" \
    --output "$temporary_root/elf-release-lto.json"
cargo run --quiet -p codehelion -- artifact analyze \
    "$fixture_root/build/release-lto-deduplicated/duplicates.wasm" \
    --format json \
    --build-variant "$fixture_root/build/release-lto-deduplicated/build-variant.json" \
    --db "$temporary_root/artifact.sqlite" \
    --output "$temporary_root/wasm-deduplicated.json"
cp "$fixture_root/build/debug/libduplicates.so" "$temporary_root/libduplicates-stripped.so"
strip --strip-all "$temporary_root/libduplicates-stripped.so"
cargo run --quiet -p codehelion -- artifact analyze \
    "$temporary_root/libduplicates-stripped.so" \
    --format json \
    --db "$temporary_root/artifact.sqlite" \
    --output "$temporary_root/elf-stripped.json"
cargo run --quiet -p codehelion -- artifact compare \
    "$fixture_root/build/debug/duplicates.wasm" \
    "$fixture_root/build/release-lto/duplicates.wasm" \
    --before-build-variant "$fixture_root/build/debug/build-variant.json" \
    --after-build-variant "$fixture_root/build/release-lto/build-variant.json" \
    --format json \
    --output "$temporary_root/compare.json"
cargo run --quiet -p codehelion -- artifact compare \
    "$fixture_root/build/debug/libduplicates.so" \
    "$fixture_root/build/release-lto/libduplicates.so" \
    --before-build-variant "$fixture_root/build/debug/build-variant.json" \
    --after-build-variant "$fixture_root/build/release-lto/build-variant.json" \
    --format json \
    --output "$temporary_root/compare-elf.json"
cargo run --quiet -p codehelion -- artifact compare \
    "$fixture_root/build/release-lto/duplicates.wasm" \
    "$fixture_root/build/release-lto-deduplicated/duplicates.wasm" \
    --before-build-variant "$fixture_root/build/release-lto/build-variant.json" \
    --after-build-variant "$fixture_root/build/release-lto-deduplicated/build-variant.json" \
    --format json \
    --output "$temporary_root/compare-deduplicated.json"
cargo run --quiet -p codehelion -- artifact compare \
    "$fixture_root/build/debug/libduplicates.so" \
    "$fixture_root/build/debug-deduplicated/libduplicates.so" \
    --before-build-variant "$fixture_root/build/debug/build-variant.json" \
    --after-build-variant "$fixture_root/build/debug-deduplicated/build-variant.json" \
    --source-run "$source_run" \
    --clone-group "$calibration_group" \
    --db "$temporary_root/artifact.sqlite" \
    --format json \
    --output "$temporary_root/compare-calibration.json"
cargo run --quiet -p codehelion -- artifact calibration \
    --source-run "$source_run" \
    --db "$temporary_root/artifact.sqlite" \
    --format json \
    --output "$temporary_root/calibration-baseline.json"
# A second measurement, so the baseline comparison above has something to
# compare. It is the same code with its debug information in a separate file:
# a different artifact, separately analysed, whose estimate is its own. The
# optimized builds cannot stand here — an optimizer leaves no line evidence
# tying each member of a clone group to its own bytes, so nothing in them is
# attributed and there is no estimate to measure.
cargo run --quiet -p codehelion -- artifact compare \
    "$temporary_root/libduplicates-split.so" \
    "$temporary_root/libduplicates-split-deduplicated.so" \
    --before-build-variant "$fixture_root/build/debug/build-variant.json" \
    --after-build-variant "$fixture_root/build/debug-deduplicated/build-variant.json" \
    --source-run "$source_run" \
    --clone-group "$calibration_group" \
    --db "$temporary_root/artifact.sqlite" \
    --format json \
    --output "$temporary_root/compare-calibration-split-debug.json"
cargo run --quiet -p codehelion -- artifact calibration \
    --source-run "$source_run" \
    --baseline "$temporary_root/calibration-baseline.json" \
    --db "$temporary_root/artifact.sqlite" \
    --format json \
    --output "$temporary_root/calibration.json"

grep -qE '"format": "wasm"' "$temporary_root/wasm.json"
grep -qE '"analysis_id": [1-9]' "$temporary_root/wasm.json"
grep -qE '"name": "duplicate_left"' "$temporary_root/wasm.json"
grep -qE '"name": "duplicate_right"' "$temporary_root/wasm.json"
grep -qE '"exact_groups": [1-9]' "$temporary_root/wasm.json"
grep -qE '"normalized_groups": [1-9]' "$temporary_root/wasm.json"
grep -qE '"format": "elf"' "$temporary_root/elf.json"
grep -qE '"imports": [1-9]' "$temporary_root/elf.json"
grep -qE '"source_mappings": [1-9]' "$temporary_root/elf.json"
grep -qE '"correlation": \{' "$temporary_root/elf.json"
grep -qE '"mappings": [1-9]' "$temporary_root/elf.json"
grep -qE '"source_mappings": [1-9]' "$temporary_root/elf-split-debug.json"
grep -qE '"mappings": [1-9]' "$temporary_root/elf-split-debug.json"
grep -qE '"estimated_refactor_savings_bytes": -?[1-9][0-9]*' "$temporary_root/elf.json"
grep -qE '"exact_groups": [1-9]' "$temporary_root/elf.json"
# Normalized duplicate detection reads machine instructions, and the only
# normalizer here is for x86-64. Elsewhere the count is nothing rather than
# something missed, and saying which is expected keeps the run honest on a
# machine of either kind.
case "$(uname -m)" in
    x86_64 | amd64)
        grep -qE '"normalized_groups": [1-9]' "$temporary_root/elf.json"
        ;;
    *)
        grep -qE '"normalized_groups": 0' "$temporary_root/elf.json"
        ;;
esac
grep -qE '"format": "elf"' "$temporary_root/elf-release-lto.json"
# The optimized build is read and correlated like any other, and it estimates
# nothing: an optimizer leaves no line evidence tying each member of a clone
# group to its own bytes, so no group has every member attributed. Saying so
# is the point — an estimate here would be one nothing in the artifact
# supports.
grep -qE '"correlation": \{' "$temporary_root/elf-release-lto.json"
grep -qE '"estimated_refactor_savings": \[\]' "$temporary_root/elf-release-lto.json"
grep -qE '"format": "wasm"' "$temporary_root/wasm-deduplicated.json"
grep -qE '"size_inferred": true' "$temporary_root/elf-stripped.json"
for field in \
    observed_bytes duplicated_bytes retained_bytes shared_dependency_bytes \
    duplicated_data_bytes upper_bound_savings_bytes \
    estimated_refactor_savings_bytes verified_savings_bytes \
    clone_confidence savings_confidence duplicate_groups dead_code retained_sizes
do
    grep -qE "\"$field\"" "$temporary_root/wasm.json"
    grep -qE "\"$field\"" "$temporary_root/elf.json"
done
# A comparison measures the difference between two artifacts, which is an
# observation and not a verified saving: nothing here says the difference came
# from removing a duplicate. Only the calibrated comparisons below, which name
# a source run and a clone group, produce a verified figure.
grep -qE '"observed_size_reduction_bytes": -?[0-9]+' "$temporary_root/compare.json"
grep -qE '"build_variant_warning": "build variants differ' "$temporary_root/compare.json"
grep -qE '"observed_size_reduction_bytes": -?[0-9]+' "$temporary_root/compare-elf.json"
grep -qE '"build_variant_warning": "build variants differ' "$temporary_root/compare-elf.json"
# The deduplicated pair is the one case where the difference has a direction:
# the same build with the duplicate removed is smaller.
grep -qE '"observed_size_reduction_bytes": [1-9][0-9]*' "$temporary_root/compare-deduplicated.json"
grep -qE '"calibration": \{' "$temporary_root/compare-calibration.json"
grep -qE '"verified_savings_bytes": [1-9][0-9]*' "$temporary_root/compare-calibration.json"
grep -qE '"calibration": \{' "$temporary_root/compare-calibration-split-debug.json"
grep -qE '"verified_savings_bytes": [1-9][0-9]*' "$temporary_root/compare-calibration-split-debug.json"
grep -qE '"samples": 2' "$temporary_root/calibration.json"
grep -qE '"comparison": \{' "$temporary_root/calibration.json"
grep -qE '"baseline_schema_version": "artifact-calibration-report-v1"' "$temporary_root/calibration.json"
grep -qE '"dimension": "artifact_format"' "$temporary_root/calibration.json"
grep -qE '"dimension": "artifact_build_variant"' "$temporary_root/calibration.json"
grep -qE '"dimension": "clone_type"' "$temporary_root/calibration.json"

printf '%s\n' 'artifact fixture end-to-end verification passed'
