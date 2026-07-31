# Artifact format extension boundary

The common `ArtifactBackend` boundary recognises these container formats before
dispatching to a parser. Recognition never causes the inspected input to run.

| Format | Backend crate | Detection | Potential capabilities | Status |
| --- | --- | --- | --- | --- |
| WebAssembly | `codehelion-artifact-wasm` | `\0asm` | symbols, direct calls, data segments | implemented |
| ELF | `codehelion-artifact-elf` | `\x7fELF` | symbols, relocations, direct calls, data segments | implemented |
| Mach-O | `codehelion-artifact-macho` | Mach-O magic values | symbols, relocations, direct calls, data segments, source mappings | recognised, no parser backend |
| PE/COFF | `codehelion-artifact-pe` | validated DOS/PE header | symbols, relocations, direct calls, data segments, source mappings | recognised, no parser backend |
| Archive | `codehelion-artifact-object` | `!<arch>\n` | member enumeration, then the delegated member capabilities | recognised, no parser backend |

An archive is modelled as a collection of object members. An archive backend
will enumerate each member and delegate its bytes to the appropriate object
backend; it does not treat the archive byte stream as one executable. Plain
ELF relocatable objects already use the ELF backend.

For a recognised format without a parser, the CLI reports: “`<format>` input is
recognised but has no parser backend in this build.” It deliberately makes no
claim about a future delivery date.
