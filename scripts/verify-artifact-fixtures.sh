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

cargo run --quiet -p codehelion-cli -- scan \
    "$fixture_root" \
    --mode structural \
    --format json \
    --db "$temporary_root/artifact.sqlite" \
    --output "$temporary_root/source-scan.json"
source_run=$(sed -n 's/^[[:space:]]*"run_id": \([0-9][0-9]*\),\{0,1\}$/\1/p' "$temporary_root/source-scan.json")
test -n "$source_run"
calibration_group=$(awk '
    /"groups": \[/ { groups = 1; next }
    groups && /"fingerprint":/ {
        fingerprint = $2
        gsub(/[",]/, "", fingerprint)
    }
    groups && /"scope": "fragment"/ { print fingerprint; exit }
' "$temporary_root/source-scan.json")
test -n "$calibration_group"

cargo run --quiet -p codehelion-cli -- artifact analyze \
    "$fixture_root/build/debug/duplicates.wasm" \
    --format json \
    --build-variant "$fixture_root/build/debug/build-variant.json" \
    --source-run "$source_run" \
    --db "$temporary_root/artifact.sqlite" \
    --output "$temporary_root/wasm.json"
cargo run --quiet -p codehelion-cli -- artifact analyze \
    "$fixture_root/build/debug/libduplicates.so" \
    --format json \
    --build-variant "$fixture_root/build/debug/build-variant.json" \
    --source-run "$source_run" \
    --linker-map "$fixture_root/build/debug/libduplicates.map" \
    --db "$temporary_root/artifact.sqlite" \
    --output "$temporary_root/elf.json"
objcopy --only-keep-debug \
    "$fixture_root/build/debug/libduplicates.so" \
    "$temporary_root/libduplicates.debug"
cp "$fixture_root/build/debug/libduplicates.so" "$temporary_root/libduplicates-split.so"
objcopy --strip-debug "$temporary_root/libduplicates-split.so"
cargo run --quiet -p codehelion-cli -- artifact analyze \
    "$temporary_root/libduplicates-split.so" \
    --format json \
    --build-variant "$fixture_root/build/debug/build-variant.json" \
    --source-run "$source_run" \
    --debug-file "$temporary_root/libduplicates.debug" \
    --db "$temporary_root/artifact.sqlite" \
    --output "$temporary_root/elf-split-debug.json"
cargo run --quiet -p codehelion-cli -- artifact analyze \
    "$fixture_root/build/release-lto/libduplicates.so" \
    --format json \
    --build-variant "$fixture_root/build/release-lto/build-variant.json" \
    --source-run "$source_run" \
    --db "$temporary_root/artifact.sqlite" \
    --output "$temporary_root/elf-release-lto.json"
cargo run --quiet -p codehelion-cli -- artifact analyze \
    "$fixture_root/build/release-lto-deduplicated/duplicates.wasm" \
    --format json \
    --build-variant "$fixture_root/build/release-lto-deduplicated/build-variant.json" \
    --db "$temporary_root/artifact.sqlite" \
    --output "$temporary_root/wasm-deduplicated.json"
cp "$fixture_root/build/debug/libduplicates.so" "$temporary_root/libduplicates-stripped.so"
strip --strip-all "$temporary_root/libduplicates-stripped.so"
cargo run --quiet -p codehelion-cli -- artifact analyze \
    "$temporary_root/libduplicates-stripped.so" \
    --format json \
    --db "$temporary_root/artifact.sqlite" \
    --output "$temporary_root/elf-stripped.json"
cargo run --quiet -p codehelion-cli -- artifact compare \
    "$fixture_root/build/debug/duplicates.wasm" \
    "$fixture_root/build/release-lto/duplicates.wasm" \
    --before-build-variant "$fixture_root/build/debug/build-variant.json" \
    --after-build-variant "$fixture_root/build/release-lto/build-variant.json" \
    --format json \
    --output "$temporary_root/compare.json"
cargo run --quiet -p codehelion-cli -- artifact compare \
    "$fixture_root/build/debug/libduplicates.so" \
    "$fixture_root/build/release-lto/libduplicates.so" \
    --before-build-variant "$fixture_root/build/debug/build-variant.json" \
    --after-build-variant "$fixture_root/build/release-lto/build-variant.json" \
    --format json \
    --output "$temporary_root/compare-elf.json"
cargo run --quiet -p codehelion-cli -- artifact compare \
    "$fixture_root/build/release-lto/duplicates.wasm" \
    "$fixture_root/build/release-lto-deduplicated/duplicates.wasm" \
    --before-build-variant "$fixture_root/build/release-lto/build-variant.json" \
    --after-build-variant "$fixture_root/build/release-lto-deduplicated/build-variant.json" \
    --format json \
    --output "$temporary_root/compare-deduplicated.json"
cargo run --quiet -p codehelion-cli -- artifact compare \
    "$fixture_root/build/debug/libduplicates.so" \
    "$fixture_root/build/debug-deduplicated/libduplicates.so" \
    --before-build-variant "$fixture_root/build/debug/build-variant.json" \
    --after-build-variant "$fixture_root/build/debug-deduplicated/build-variant.json" \
    --source-run "$source_run" \
    --clone-group "$calibration_group" \
    --db "$temporary_root/artifact.sqlite" \
    --format json \
    --output "$temporary_root/compare-calibration.json"
cargo run --quiet -p codehelion-cli -- artifact calibration \
    --source-run "$source_run" \
    --db "$temporary_root/artifact.sqlite" \
    --format json \
    --output "$temporary_root/calibration-baseline.json"
cargo run --quiet -p codehelion-cli -- artifact compare \
    "$fixture_root/build/release-lto/libduplicates.so" \
    "$fixture_root/build/release-lto-deduplicated/libduplicates.so" \
    --before-build-variant "$fixture_root/build/release-lto/build-variant.json" \
    --after-build-variant "$fixture_root/build/release-lto-deduplicated/build-variant.json" \
    --source-run "$source_run" \
    --clone-group "$calibration_group" \
    --db "$temporary_root/artifact.sqlite" \
    --format json \
    --output "$temporary_root/compare-calibration-release-lto.json"
cargo run --quiet -p codehelion-cli -- artifact calibration \
    --source-run "$source_run" \
    --baseline "$temporary_root/calibration-baseline.json" \
    --db "$temporary_root/artifact.sqlite" \
    --format json \
    --output "$temporary_root/calibration.json"

rg -q '"format": "wasm"' "$temporary_root/wasm.json"
rg -q '"analysis_id": [1-9]' "$temporary_root/wasm.json"
rg -q '"name": "duplicate_left"' "$temporary_root/wasm.json"
rg -q '"name": "duplicate_right"' "$temporary_root/wasm.json"
rg -q '"exact_groups": [1-9]' "$temporary_root/wasm.json"
rg -q '"normalized_groups": [1-9]' "$temporary_root/wasm.json"
rg -q '"format": "elf"' "$temporary_root/elf.json"
rg -q '"imports": [1-9]' "$temporary_root/elf.json"
rg -q '"source_mappings": [1-9]' "$temporary_root/elf.json"
rg -q '"correlation": {' "$temporary_root/elf.json"
rg -q '"mappings": [1-9]' "$temporary_root/elf.json"
rg -q '"source_mappings": [1-9]' "$temporary_root/elf-split-debug.json"
rg -q '"mappings": [1-9]' "$temporary_root/elf-split-debug.json"
rg -q '"estimated_refactor_savings_bytes": -?[1-9][0-9]*' "$temporary_root/elf.json"
rg -q '"exact_groups": [1-9]' "$temporary_root/elf.json"
rg -q '"normalized_groups": [1-9]' "$temporary_root/elf.json"
rg -q '"format": "elf"' "$temporary_root/elf-release-lto.json"
rg -q '"estimated_refactor_savings_bytes": -?[1-9][0-9]*' "$temporary_root/elf-release-lto.json"
rg -q '"format": "wasm"' "$temporary_root/wasm-deduplicated.json"
rg -q '"size_inferred": true' "$temporary_root/elf-stripped.json"
for field in \
    observed_bytes duplicated_bytes retained_bytes shared_dependency_bytes \
    duplicated_data_bytes upper_bound_savings_bytes \
    estimated_refactor_savings_bytes verified_savings_bytes \
    clone_confidence savings_confidence duplicate_groups dead_code retained_sizes
do
    rg -q "\"$field\"" "$temporary_root/wasm.json"
    rg -q "\"$field\"" "$temporary_root/elf.json"
done
rg -q '"verified_savings_bytes": [0-9]+' "$temporary_root/compare.json"
rg -q '"build_variant_warning": "build variants differ' "$temporary_root/compare.json"
rg -q '"verified_savings_bytes": [0-9]+' "$temporary_root/compare-elf.json"
rg -q '"build_variant_warning": "build variants differ' "$temporary_root/compare-elf.json"
rg -q '"verified_savings_bytes": [1-9][0-9]*' "$temporary_root/compare-deduplicated.json"
rg -q '"calibration": {' "$temporary_root/compare-calibration.json"
rg -q '"verified_savings_bytes": [1-9][0-9]*' "$temporary_root/compare-calibration.json"
rg -q '"calibration": {' "$temporary_root/compare-calibration-release-lto.json"
rg -q '"verified_savings_bytes": [1-9][0-9]*' "$temporary_root/compare-calibration-release-lto.json"
rg -q '"samples": 2' "$temporary_root/calibration.json"
rg -q '"comparison": {' "$temporary_root/calibration.json"
rg -q '"baseline_schema_version": "artifact-calibration-report-v1"' "$temporary_root/calibration.json"
rg -q '"dimension": "artifact_format"' "$temporary_root/calibration.json"
rg -q '"dimension": "artifact_build_variant"' "$temporary_root/calibration.json"
rg -q '"dimension": "clone_type"' "$temporary_root/calibration.json"

printf '%s\n' 'artifact fixture end-to-end verification passed'
