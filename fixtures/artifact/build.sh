#!/bin/sh
# Build reproducible artifact-analysis inputs without running either program.
set -eu

usage() {
    printf '%s\n' 'usage: ./build.sh <debug|release> [--lto] [--deduplicated] [--with-elf]' >&2
    exit 2
}

profile=${1:-}
case "$profile" in
    debug|release) ;;
    *) usage ;;
esac
shift

lto=false
deduplicated=false
with_elf=false
for option in "$@"; do
    case "$option" in
        --lto) lto=true ;;
        --deduplicated) deduplicated=true ;;
        --with-elf) with_elf=true ;;
        *) usage ;;
    esac
done

case "$profile" in
    debug)
        opt_level=0
        debuginfo=2
        ;;
    release)
        opt_level=2
        # The optimized calibration pair still carries local DWARF line rows.
        # This preserves the source-fragment evidence needed to measure the
        # model under LTO without changing compiler or optimization settings.
        debuginfo=2
        ;;
esac

variant="$profile"
if [ "$lto" = true ]; then
    variant="$variant-lto"
fi
if [ "$deduplicated" = true ]; then
    variant="$variant-deduplicated"
fi
output="build/$variant"
mkdir -p "$output"

if [ "$deduplicated" = true ]; then
    source=wasm/lib-deduplicated.rs
    rustc \
        --edition=2024 \
        --crate-type=cdylib \
        --target=wasm32-unknown-unknown \
        -C "opt-level=$opt_level" \
        -C "debuginfo=$debuginfo" \
        -C "lto=$lto" \
        "$source" \
        -o "$output/duplicates.wasm"
else
    source=wasm/lib.rs
    rustc \
        --edition=2024 \
        --crate-type=cdylib \
        --target=wasm32-unknown-unknown \
        -C "opt-level=$opt_level" \
        -C "debuginfo=$debuginfo" \
        -C "lto=$lto" \
        "$source" \
        -o "$output/duplicates.wasm"
fi

if [ "$with_elf" = true ]; then
    if [ "$(uname -s)" != Linux ]; then
        printf '%s\n' '--with-elf requires a Linux host C++ toolchain that emits ELF' >&2
        exit 1
    fi
    if [ "$deduplicated" = true ]; then
        cxx_deduplicated=-DDEDUPLICATED
    else
        cxx_deduplicated=
    fi
    object_dir="$output/elf"
    object_file="$object_dir/templates.cpp.o"
    mkdir -p "$object_dir"
    if [ "$lto" = true ]; then
        c++ \
            -std=c++20 -fPIC -fno-exceptions -fno-rtti \
            "-O$opt_level" -g$debuginfo -flto $cxx_deduplicated -c elf/templates.cpp \
            -o "$object_file"
        c++ \
            -shared -flto "$object_file" \
            -Wl,--build-id=sha1 -Wl,-Map,"$output/libduplicates.map" \
            -o "$output/libduplicates.so"
    else
        c++ \
            -std=c++20 -fPIC -fno-exceptions -fno-rtti \
            "-O$opt_level" -g$debuginfo $cxx_deduplicated -c elf/templates.cpp \
            -o "$object_file"
        c++ \
            -shared "$object_file" \
            -Wl,--build-id=sha1 -Wl,-Map,"$output/libduplicates.map" \
            -o "$output/libduplicates.so"
    fi
fi

cat >"$output/build-variant.json" <<EOF
{
  "profile": "$profile",
  "optimization_level": "$opt_level",
  "lto": $lto,
  "debug_info": $debuginfo,
  "wasm_target": "wasm32-unknown-unknown",
  "elf_requested": $with_elf,
  "rustc": "$(rustc --version)",
  "cxx": "$(c++ --version | head -n 1)"
}
EOF

printf '%s\n' "built $output"
