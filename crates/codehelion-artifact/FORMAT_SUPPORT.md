# Artifact format extension boundary

The common `ArtifactBackend` boundary recognises these container formats before
dispatching to a parser. Recognition never causes the inspected input to run.

Each backend is a module behind the feature of the same name, so a build that
reads one format links no parser for the others.

| Format | Module and feature | Detection | Potential capabilities | Status |
| --- | --- | --- | --- | --- |
| WebAssembly | `wasm` | `\0asm` | symbols, direct calls, data segments | implemented |
| ELF | `elf` | `\x7fELF` | symbols, relocations, direct calls, data segments, normalized duplicates; source mappings from embedded DWARF or a build-ID-matched debug companion | implemented |
| Mach-O | `macho` | Mach-O magic values | symbols, relocations, data segments, normalized duplicates; source mappings with a matching dSYM DWARF image | implemented; call graph is unavailable |
| PE/COFF | `pe` | DOS `MZ` header or recognised COFF machine | symbols, relocations, data segments, normalized duplicates; PE source mappings with a matching PDB | implemented; call graph is unavailable |
| Archive | `archive` | `!<arch>\n` or `!<thin>\n` | member enumeration, then the delegated local-member capabilities | implemented; thin members are not followed outside the archive |

An archive is modelled as a collection of object members. The backend
enumerates each local member and delegates its bytes to the appropriate object
backend; it does not treat the archive byte stream as one executable. Member
provenance and any individual parse failure are retained in the archive IR.
Thin archive paths are never followed. Plain ELF relocatable objects already
use the ELF backend.

All recognised container formats currently have a parser backend. An unknown
member within an archive is recorded as unsupported member evidence without
discarding the rest of that archive.
