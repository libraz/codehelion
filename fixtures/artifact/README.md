# Artifact analysis fixtures

These small programs produce known, inspectable compiled inputs for artifact
parser and report tests. Their build outputs are deliberately untracked.

Run `sh build.sh <debug|release> [--lto] [--deduplicated] [--with-elf]`. Every output directory
contains a `build-variant.json` that records the requested optimisation, LTO,
debug-information setting, target and toolchain. Optimized fixture builds keep
local debug information so source-fragment calibration can be measured under
LTO. The script always builds the
WebAssembly module; `--with-elf` additionally builds the C++ shared object on
Linux, where the host C++ toolchain produces ELF. It reports a clear error if
that optional request is made on another host.

ELF builds also retain the linker-produced `libduplicates.map`. It is an
optional local input to `codehelion artifact analyze --linker-map`; no linker is
ever invoked by analysis.

The Linux verification script also creates a GNU build-ID-verified external
debug companion from the ELF fixture, strips a copy of the program's debug
sections, and analyzes that copy with `--debug-file`. The companion is a local
input only; analysis rejects a mismatched build ID rather than attaching its
source locations to a different artifact.

On macOS, `make verify-macho-artifact-fixtures` builds a dynamic library and
its matching dSYM, checks their UUID relationship, and verifies symbol, data,
and source-location extraction. Analysis accepts the dSYM's inner DWARF image
only when its `LC_UUID` matches the inspected dynamic library; a conventional
adjacent `.dSYM` bundle is discovered automatically.

On Windows, `make verify-pe-artifact-fixtures` builds matching PE/PDB pairs
with MSVC debug information. It verifies that a matching CodeView identity
produces source mappings, preserves an explicit source-scan correlation for
both exported functions, and rejects a PDB from a distinct build.

The programs expose two intentionally similar functions and repeated static
data. They are inputs to parser tests only and are never executed by
codehelion.

`--deduplicated` selects the reduced Rust source and defines the matching
C++ source-only switch. In both cases callers have converged on one entry
point, so the redundant function is absent. It does not change the
build-variant manifest: the before/after pair therefore isolates a source
refactoring under identical compiler conditions, and can be used for
calibration as well as for the measured artifact comparison.
