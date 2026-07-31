#!/bin/sh
# Build a real Mach-O dynamic library and dSYM, then verify the parser's
# documented container-only capability boundary. Neither output is executed.
set -eu

case "$(uname -s)" in
    Darwin) ;;
    *)
        printf '%s\n' 'Mach-O fixture verification requires macOS' >&2
        exit 2
        ;;
esac

for tool in clang++ dsymutil dwarfdump; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf '%s\n' "Mach-O fixture verification requires $tool" >&2
        exit 2
    fi
done

temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/codehelion-macho-fixtures.XXXXXX")
# DWARF retains the compiler argument spelling while scan canonicalizes its
# root. Use the physical spelling for both so the fixture tests actual mapping,
# not the `/var` -> `/private/var` macOS symlink.
temporary_root=$(cd "$temporary_root" && pwd -P)
fixture_root="$temporary_root/fixture"
mkdir -p "$fixture_root"
cp fixtures/artifact/elf/templates.cpp "$fixture_root/templates.cpp"

clang++ \
    -std=c++20 -fPIC -fno-exceptions -fno-rtti -g -O0 \
    -c "$fixture_root/templates.cpp" \
    -o "$fixture_root/templates.o"
clang++ \
    -dynamiclib "$fixture_root/templates.o" \
    -Wl,-undefined,dynamic_lookup \
    -o "$fixture_root/libduplicates.dylib"
dsymutil "$fixture_root/libduplicates.dylib" -o "$fixture_root/libduplicates.dylib.dSYM"
printf '%s\n' '{"target":"arm64-apple-darwin","debug_info":true}' \
    > "$fixture_root/build-variant.json"

dwarfdump --uuid "$fixture_root/libduplicates.dylib" \
    "$fixture_root/libduplicates.dylib.dSYM" \
    | rg -q 'UUID:'
test -f "$fixture_root/libduplicates.dylib.dSYM/Contents/Resources/DWARF/libduplicates.dylib"

cargo run --quiet -p codehelion-cli -- scan \
    "$fixture_root" \
    --mode structural \
    --format json \
    --db "$temporary_root/artifact.sqlite" \
    --output "$temporary_root/source-scan.json"
source_run=$(sed -n 's/^[[:space:]]*"run_id": \([0-9][0-9]*\),\{0,1\}$/\1/p' "$temporary_root/source-scan.json")
test -n "$source_run"

cargo run --quiet -p codehelion-cli -- artifact analyze \
    "$fixture_root/libduplicates.dylib" \
    --input-format mach-o \
    --format json \
    --build-variant "$fixture_root/build-variant.json" \
    --source-run "$source_run" \
    --db "$temporary_root/artifact.sqlite" \
    --output "$temporary_root/report.json"

rg -q '"format": "mach-o"' "$temporary_root/report.json"
rg -q '"name": "_duplicate_left"' "$temporary_root/report.json"
rg -q '"name": "_duplicate_right"' "$temporary_root/report.json"
rg -q '"data_segments": [1-9]' "$temporary_root/report.json"
rg -q '"source_mappings": [1-9]' "$temporary_root/report.json"
rg -q '"source_mapping": true' "$temporary_root/report.json"

printf '%s\n' 'Mach-O artifact fixture end-to-end verification passed'
