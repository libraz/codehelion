# Artifact format extension boundary

The common `ArtifactBackend` boundary recognises these container formats before
dispatching to a parser. Recognition never causes the inspected input to run.

Each backend is a module behind the feature of the same name, so a build that
reads one format links no parser for the others.

The table below is generated from the format support definitions in
`src/support.rs`, which are also what every backend returns from
`ArtifactBackend::capabilities()`. A test compares the two, so the table cannot
claim an ability no backend declares or omit one that is declared.

| Format | Module and feature | Detection | Potential capabilities | Status |
| --- | --- | --- | --- | --- |
| wasm | `wasm` | `\0asm` | symbols, direct calls, data segments, normalized duplicates, independent data segments; source mappings from a recorded sourceMappingURL | implemented; the component encoding is recognised but not parsed |
| elf | `elf` | `\x7fELF` | symbols, direct calls, relocations, data segments, normalized duplicates; source mappings from embedded DWARF or a build-ID-matched debug companion | implemented; normalized duplicates need an x86 instruction architecture |
| macho | `macho` | Mach-O magic values | symbols, relocations, data segments, normalized duplicates; source mappings from a matching dSYM DWARF image | implemented; the call graph is unavailable; normalized duplicates need an x86 instruction architecture |
| pe-coff | `pe` | DOS `MZ` header or recognised COFF machine | symbols, relocations, data segments, normalized duplicates; source mappings from a matching PDB | implemented; the call graph is unavailable; normalized duplicates need an x86 instruction architecture |
| archive | `archive` | `!<arch>\n` or `!<thin>\n` | symbols, direct calls, relocations, data segments, normalized duplicates; source mappings from the debug metadata each delegated member carries | implemented; members are enumerated and delegated, so the capabilities are the delegated members'; thin members are not followed outside the archive |

## Attribution granularity

A capability says what a format can establish; how precisely it can attribute
bytes back to source follows from it. A format whose parses attach source line
frames to symbols reaches a source line range, so a clone group's byte
attribution is available for it. A format that only names symbols reaches whole
symbols and no line range, however complete its names are.

WebAssembly is the format where that distinction bites. A core module's name
section carries names and no line information, and this backend reads no DWARF
from a module, so symbol-level correspondence is reachable and clone-group byte
attribution is not. Emitting DWARF would change the size being measured, which
is usually why the module is being inspected. The report guidance derives that
statement from the definitions rather than restating it.

## Archives

An archive is modelled as a collection of object members. The backend
enumerates each local member and delegates its bytes to the appropriate object
backend; it does not treat the archive byte stream as one executable. Member
provenance and any individual parse failure are retained in the archive IR.
Thin archive paths are never followed. Plain ELF relocatable objects already
use the ELF backend.

Because a normalizer belongs to an instruction architecture rather than to the
archive container, an archive's normalized-duplicate capability is the union of
what its parsed members declare. A member whose text fails to decode therefore
does not withdraw the normalized figures of the other members.

All recognised container formats currently have a parser backend. An unknown
member within an archive is recorded as unsupported member evidence without
discarding the rest of that archive. A WebAssembly component uses the module
magic and is recognised, but no backend parses it, so it is refused as an
unsupported encoding rather than read as a module.
