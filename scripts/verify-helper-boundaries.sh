#!/bin/sh
# Verify the normal dependency closures of the shipped engine and CLI.  The
# compiler adapters are separate executables, so their crates may be workspace
# members but must never occur below either of these roots in `cargo tree`.
#
# `rustc-*` has legitimate ecosystem crates (for example rustc-hash), so this
# check intentionally rejects the compiler-private `rustc_*` crate namespace
# rather than applying an unsafe broad substring match.
set -eu

cargo_cmd=${CARGO:-cargo}
temporary_files=''

cleanup() {
    # The paths come solely from mktemp below; splitting is safe because mktemp
    # does not emit whitespace in a path.
    # shellcheck disable=SC2086
    rm -f $temporary_files
}
trap cleanup EXIT HUP INT TERM

is_forbidden_crate() {
    case "$1" in
        # Direct Rust compiler-private crates are exposed through rustc_private.
        rustc_*) return 0 ;;
        # libclang / LLVM binding crates. Keep this list explicit: a crate whose
        # name merely contains "clang" or "llvm" is not necessarily a binding.
        clang|clang-sys|libclang|libclang-sys|llvm-sys|llvm-ir|inkwell) return 0 ;;
        # A backend is valid as a workspace member and child process, never as a
        # linked normal dependency of the engine or command-line binary.
        codehelion-backend-rust|codehelion-backend-clang) return 0 ;;
        *) return 1 ;;
    esac
}

for package in codehelion-core codehelion-cli; do
    dependency_file=$(mktemp "${TMPDIR:-/tmp}/codehelion-${package}-deps.XXXXXX")
    temporary_files="$temporary_files $dependency_file"

    "$cargo_cmd" tree --locked --package "$package" --edges normal --target all \
        --no-dedupe --prefix none --format '{p}' >"$dependency_file"

    while IFS= read -r dependency; do
        crate=${dependency%% *}
        if is_forbidden_crate "$crate"; then
            printf '%s\n' "error: $package normally depends on forbidden compiler binding $crate" >&2
            printf '%s\n' "       compiler adapters must remain independent helper processes." >&2
            exit 1
        fi
    done <"$dependency_file"
done

# Storage consumes the versioned IR contract, not the crate that can launch
# and supervise external programs. This keeps persistence usable without
# acquiring any process-management or sandbox dependencies.
store_dependency_file=$(mktemp "${TMPDIR:-/tmp}/codehelion-store-deps.XXXXXX")
temporary_files="$temporary_files $store_dependency_file"
"$cargo_cmd" tree --locked --package codehelion-store --edges normal --target all \
    --no-dedupe --prefix none --format '{p}' >"$store_dependency_file"
while IFS= read -r dependency; do
    crate=${dependency%% *}
    if [ "$crate" = codehelion-helper ]; then
        printf '%s\n' 'error: codehelion-store depends on the process-managing codehelion-helper crate' >&2
        printf '%s\n' '       depend on codehelion-helper-protocol for compiler IR instead.' >&2
        exit 1
    fi
done <"$store_dependency_file"

# The shared contract itself must remain inert. Framing may read and write the
# caller-provided stream, but the crate must never start or supervise a process.
if grep -R -n -E 'std::process|tokio::process|Command::new|Child::(wait|kill)' \
    crates/codehelion-helper-protocol/src; then
    printf '%s\n' 'error: codehelion-helper-protocol contains process-management code' >&2
    exit 1
fi

printf '%s\n' 'compiler helper dependency boundaries verified'
