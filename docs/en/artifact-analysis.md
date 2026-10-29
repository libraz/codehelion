# Artifact analysis

The `artifact` commands read a compiled artifact locally. They parse bytes; they
never load or execute the inspected artifact. Source scanning does not depend on
any of it — the clone engine has no dependency on the artifact reader, and a
source scan is complete with no artifact anywhere.

```sh
codehelion artifact analyze path/to/binary
codehelion artifact analyze path/to/binary --format csv  # also json, or text by default
codehelion artifact report              # render the latest saved analysis
codehelion artifact compare before/binary after/binary
```

## What each format can establish

![What each artifact format can establish](../images/artifact.svg)

Observed size and duplicate code are reported for every format. The rest is what
the format itself can establish: retained and shared size need a call graph,
which is derived for WASM, ELF and static archives; duplicate data needs
independently sized data regions, which WASM has; a source location needs debug
evidence — DWARF for ELF, a matching dSYM for Mach-O, a matching PDB for PE/COFF,
a recorded source-map URL for WASM.

A quantity the format cannot supply is reported as unavailable beside an
assumption naming what was missing, rather than as a number.

Static archives and relocatable objects attribute whole symbols only, with no
source line range: a relocatable object has no load address for a line table to
join. Linking the members into an image is what reaches a line range.

For ELF, retained sizes and dead-code candidates follow direct calls, jumps that
leave a function (tail calls) and functions whose address is taken, since those
run with no call edge reaching them. A jump or call through a register or a
memory slot reaches a callee the reader cannot name, so where one occurs the
dead-code list is a list of candidates and not a proof.

The per-format capability table is generated from the definitions the backends
themselves return, in `crates/codehelion-artifact/FORMAT_SUPPORT.md`.

### WebAssembly correlates one symbol at a time

ELF, Mach-O and PE/COFF reach a source line through DWARF, a matching dSYM or a
matching PDB, and a source line is what lets a clone group's line range be
attributed bytes. A core module carries function names in its name section and no
line information, so correlation names whole functions and leaves clone-group
byte attribution unavailable. Building the module with DWARF would change the size
being measured, which is usually the reason to inspect it, so the reports say what
the name section can and cannot support instead of asking for a build that answers
a different question.

## Debug companions

A companion is accepted only after the matching ELF build ID, Mach-O UUID or PE
CodeView/PDB identity has been verified — an unverified companion would attribute
bytes from one build to the source of another.

```sh
codehelion artifact analyze path/to/binary --debug-file companion
```

That works without a source scan. Add `--source-run` and `--build-variant` only
when requesting source-artifact correlation.

## Build variants

`--build-variant` takes a file you write, not one to go looking for. Its contents
are yours to choose; what they buy is that only artifacts built the same way are
compared with one another:

```sh
echo '{"profile":"release","target":"wasm32","toolchain":"emcc-5.0.2"}' > build-variant.json
codehelion artifact analyze dist/app.wasm --build-variant build-variant.json --source-run 2
```

When an artifact command receives `--build-variant manifest.json`, its identity
uses the canonical JSON value, so whitespace and object-member ordering do not
change the build variant.

A source run also has a build variant, and the JSON and SARIF reports carry its
digest; the text report prints it only beside an artifact savings estimate. The two are
separate conditions — how the sources were read, and how the artifact was built —
recorded side by side rather than checked against each other. There is
no source digest to find and copy into the manifest.

## Instantiation multiplicity

How many copies exist in the source and how many bodies exist in the binary are
different axes, and only the first is in codehelion's search model. One source
template can become a dozen distinct instantiations in the artifact, because the
closure or type at each call site differs. There is one copy to find in the
source, so no clone group describes that multiplicity.

Correlating a source run reports it separately:

```sh
codehelion artifact analyze path/to/binary --source-run 1 --build-variant build-variant.json
```

lists the source units the artifact emitted as more than one body, with how many
bodies and their observed size. Those bytes are what the artifact spends today and
not a saving — consolidating the one source copy removes none of the bodies, and
shrinking that figure means emitting fewer of them. The count needs only that a
mapping named a single source unit, so symbol names are enough for it and debug
line information is not required.

## Who owns the code

> **Pre-1.0 surface.** This is documented and tested, but has not had the real
> use that would make it worth a promise, so it can change between releases.

`artifact analyze` splits the code bytes of the symbols it reports by owner, and
names the non-toolchain functions that keep toolchain code in the artifact. Both
read symbol names only, so they apply to every format and language once a name
exists; the holder view also needs the call graph and retained sizes (see
[What each format can establish](#what-each-format-can-establish)).

The **owner** of a symbol is the first element of its defining path: a Rust
crate, a top-level C++ namespace, or `<global>` for an unqualified name. Each
owner falls into one class:

- `toolchain` — the Rust sysroot crates, C++ `std` and the global allocation
  operators, C17 Annex B functions, identifiers C17 reserves for the
  implementation, and runtime support.
- `own` — an owner listed in `[artifact] own`, see
  [Configuration](configuration.md#artifact).
- `other` — a named owner that is neither, such as a third-party crate.
- `unnamed` — a function without a name, which no owner can be assigned to.

Toolchain classification never depends on the declaration. With `own` empty,
named code outside the toolchain is reported as `other`, and the report says so.

For a C function `parse` that returns `strtof(s, 0)`, built with emscripten at
`-O1` and analysed with `own = ["<global>"]`:

```
ownership: own 6768 bytes (5 symbols), toolchain 10629 bytes (35 symbols), other 0 bytes (0 symbols), unnamed 0 bytes (0 symbols)
  declared own: <global>
  reserved (toolchain, reserved): 9013 bytes, 25 symbols
  <global> (own): 6768 bytes, 5 symbols
  c-std (toolchain, c_std): 1540 bytes, 6 symbols
  runtime (toolchain, runtime): 76 bytes, 4 symbols
  outside symbols: 61 bytes
  assumption: ownership follows the defining path of each symbol name, so generic code instantiated for your types is counted under the library that defines it
toolchain holders (held bytes are part of the holder's retained size):
  parse (own) f31665862c71112cfffda8f55fc54dd2: 17307 bytes in 34 symbols, 6756 bytes in 4 symbols absorbed
    head strtof 320251c57384d307522b489a48cc4e39: 17307 bytes
  shared: 78 bytes in 5 symbols, 0 bytes in 0 symbols absorbed
    setThrew ba286dbdc84dc40e5966ae8f29485879: 38 bytes (root)
    _initialize 4feb66b59715a8dcbf2af30ae02ec5d6: 20 bytes (root)
    _emscripten_stack_restore ef2222560055353cb931a59336cb3e00: 10 bytes (root)
    emscripten_stack_get_current 4eaae22504bd0bae04ab33f12aeef742: 8 bytes (root)
    __wasm_call_ctors a0d352ddbe45c0d90cb9d358e3fa1f9d: 2 bytes (root)
      caller _initialize 4feb66b59715a8dcbf2af30ae02ec5d6 (toolchain)
  assumption: unqualified functions whose immediate dominator is toolchain code are counted as toolchain code, except main and static initializers
  assumption: toolchain holders treat every recorded function reference as a root, so code reached through a function table is reported as shared
```

`outside symbols` is the executable section's size minus the symbols' sizes, so
the figures add up to the section. Text output lists the ten largest owners; the
JSON output carries all of them. `artifact compare` splits the byte delta the
same way, attributing a symbol to its owner in the after build (in the before
build when it was removed) and stating the remainder as `outside symbols`.

A **holder** is a function that is not toolchain code but keeps toolchain code in
the artifact: the toolchain code is reachable only through it. Each toolchain
function is attributed to its nearest non-toolchain dominator in the call graph.
The toolchain functions entered directly below a holder are its **heads**, and the
holder's line gives the bytes held by everything under them. An unqualified
function whose immediate dominator is toolchain code is counted as toolchain code,
so a libc helper does not appear to hold the libc code it calls; these bytes are
reported separately as absorbed. `main` and static initializers are never
absorbed.

Held bytes are part of the holder's retained size. They show where toolchain code
enters and what dropping the entry would unlink, not a guaranteed reduction: the
same code may be reached again by another route in the next build.

Toolchain code that no single non-toolchain function dominates is **shared
toolchain code**. It is totalled, and each entry is followed by the functions that
call it directly, one per line, the first three by fingerprint and the rest
counted. An entry the artifact exports is marked `(root)`. Shared bytes belong to no
holder and are not split among the callers. Holders are unavailable whenever
retained sizes are, and the report says so instead of giving a figure. The limits of
name-based ownership are in
[Limitations](limitations.md#artifact-inspection-depends-on-symbols).

Owner labels are derived each time a report is rendered, from the stored symbol
names and the current `[artifact] own`; nothing about ownership is written to the
database. `artifact report` therefore follows the configuration as it is when you
run it, and `artifact compare` reads the configuration in the working directory
the same way `artifact analyze` does.

## Copies of one function

Several functions of one artifact can share a name and a body, as identical libc
functions do in a statically linked build. Each copy keeps its own fingerprint, so
each has its own size and place in the call graph. The shared content is named by
`content_fingerprint` in the JSON report. A copy that no caller, callee, root,
size or body can tell from another is told apart by file order and is marked
`identity_by_order`. `artifact compare` pairs copies by content rather than by
fingerprint. Archive symbols also keep a `content_fingerprint` independent of the
member bytes, so changing one function does not change the comparison identity of
other functions in the same member.

## Name stems

Several bodies of one artifact can differ only in a template argument, a closure
number or a parameter list: `int probe<f::$_0>(char const*, f::$_0)`,
`int probe<f::$_1>(char const*, f::$_1)` and `int probe<f::$_2>(char const*, f::$_2)`
are three bodies of one template. A name stem is the name cut at its first
parameterized component, with the template arguments written `<>`, closures
written `{closure}`, and no parameter list or return type. The three bodies above
share the stem `probe<>` and keep their own spellings as instances.

The cut is at the first parameterized component and not at the end of the name, so
members of one container share a stem whatever they do:
`std::__2::deque<int>::push_back(int&&)` and `std::__2::deque<int>::pop_front()`
both belong to `std::__2::deque<>`, and their sizes add up to what that container
costs. A name with no parameterized component, such as
`solo()`, has the stem `solo`, and overloads (`foo(int)`, `foo(unsigned int)`)
share one.

`artifact analyze` lists the stems with at least two bodies, from symbol names
alone, so no source run is needed:

```text
name stems emitted as several bodies (observed, not savings):
  probe<> (other): 3 bodies in 3 instances, 948 bytes
```

Each row gives the owner class, the number of bodies, the number of distinct
instances and the summed size of the bodies. `--verbose` adds one line per
instance under each row:

```text
    probe<f::$_2>: 1 body, 340 bytes
```

The ten largest rows are listed and the rest are counted. The JSON report carries
the rows as `name_stems` and CSV carries `name-stem` and `name-stem-instance`
records.

These are observed bytes, not savings. One template written once in the source
can account for every body of a stem, so the figure is what the artifact spends
and not what consolidating the source would remove. Grouping is by exact equality
of the stem, not by similarity, so the non-transitivity concerns of
[grouping](grouping.md) do not arise. A set of identical copies appears
both as an exact duplicate group and as a stem with several bodies in one
instance; the two reports describe the same bytes from different directions.

The section is absent when no stem has two bodies. That also holds for an artifact
whose symbols carry no names, so an absent section does not tell a stripped
artifact from one without repeated names; the ownership section reports the
unnamed symbols.

## Names in the lists

The dead code, retained size and duplicate group lists identify symbols by
fingerprint, and each line shows the symbol's name before it, or `<unnamed>` when
the symbol has none:

```text
dead code candidates: 17 symbols
  std::length_error::~length_error() 23cc6ca1f6351904707d8f9001147b09
retained sizes (overlapping dominator regions):
  emscripten_builtin_malloc 4c854ab40f762e03399b96e39b6dcbab: 5861 bytes
exact duplicate groups:
  8d725494f65c077c2ff7deaa1f341067: 27 observed duplicate bytes, 4 members
    __cxa_throw 6eccc9e8e9fd06a9b57ee2236e2020b3 offset 4670 size 9
```

Distinct symbols can share one fingerprint. The line then shows each of their
names, joined with ` | `, because naming only one would label the others wrongly.
Members of a data duplicate group are data segments, not symbols, so those lines
carry the fingerprint alone. CSV fills the `name` column for the same records.

Text output shortens long names: every template argument list that opens inside
another bracket is written `<…>`. `--verbose` (`-v`) on `analyze`, `report` and
`compare` prints names in full, and JSON and CSV always carry them in full:

```text
std::__2::basic_string<char, std::__2::char_traits<…>, std::__2::allocator<…>>::append(char const*)
```

Shortening only affects what the text shows. The fingerprint on the same line is
what identifies the symbol, and comparisons never use the shortened name.

## Compressed size

```sh
codehelion artifact analyze path/to/binary --compressed gzip --compressed brotli
```

measures the whole input once per algorithm and prints one line each:

```text
compressed bytes (gzip, level 9, flate2 (miniz_oxide)): 209710
```

The value is the length of the complete compressed stream. gzip runs at level 9
through `flate2` with its `miniz_oxide` backend, with a zero timestamp and no file
name in the header. brotli runs at quality 11 with a 22-bit window. The flag is
opt-in and repeatable; without it no compression runs and no line, JSON entry or
CSV record appears. The JSON report carries `compressed_sizes`, and CSV carries
`compressed-size` records. `artifact report` shows the values recorded with the
analysis and does not read the artifact again.

The value is never divided among symbols, stems, owners or duplicate groups. A
compressor's output for one function depends on what precedes it, so moving
functions around changes the figure without changing any function, and a share
computed per part would not add up to the whole. The report states this beside
the figure.

The encoders are not the external tools. An external compressor at the same level
differs by a fraction of a percent, so a number from `gzip -9` cannot be set
against one printed here. Compare two builds inside one `artifact compare`, which
measures both with the same encoder.

brotli at quality 11 is much slower than gzip, and the measurement runs inside
`--timeout-seconds`. A timeout during it names the `compression` phase; raise the
limit or ask for gzip only.

## Comparing two builds

> **Pre-1.0 surface.** This is documented and tested, but has not had the real
> use that would make it worth a promise, so it can change between releases.

```sh
codehelion artifact compare before/binary after/binary
```

reports the measured byte delta between two artifacts of the same format. Given
both build-variant manifests, it warns when the build conditions differ rather
than presenting a difference as if it came from a source change alone. A native
symbol whose bytes changed while its size did not is reported as modified, with
the retained code bytes standing in for a body identity where the backend decodes
none. Given a
source run and a clone group as well, it also records a calibration measurement —
see [Calibration](calibration.md).

With `--compressed gzip` (or `brotli`), the comparison also measures both
artifacts in one process, so both sides use the same encoder and settings, and
prints the difference beside the other byte deltas:

```text
compressed bytes (gzip, level 9, flate2 (miniz_oxide)): 209828 before, 209710 after, -118 bytes (smaller)
```

JSON carries these as `compressed_deltas` and CSV as `compressed-delta` records.
The compressed delta is shown only when both sides were measured with the same
algorithm and settings.

Symbol deltas pair symbols by content, so a function whose signature changed from
`foo(int)` to `foo(unsigned int)` with a different body appears as one removed
symbol and one added symbol under two different names. The stem delta sums those
under the stem `foo`, and it also counts bodies, so a template whose three
instances became one reads:

```text
stem delta:
  probe<> (other): 3 -> 1 body, -608 bytes
```

A row appears when at least two symbol deltas share a stem, or when the stem's
number of bodies changes and either side has at least two. The bodies are counted
over the whole of each artifact, not only over the changed symbols, and the byte
difference is the sum of the symbol deltas. The section is omitted when there are
no such rows; JSON carries `stem_deltas` and CSV `stem-delta` records.

A function rebuilt under the same name has a new content identity, so it is
recorded as one removed and one added symbol. When the name belongs to exactly one
symbol on each side, the two entries carry each other's fingerprint in
`counterpart_fingerprint`, in JSON and in CSV. Text output prints the pair as one
line, ordered with the other symbol changes by the size of its net difference.
Text output lists the twenty largest symbol changes and counts the rest; JSON and
CSV carry every entry:

```text
symbol changes:
  added prepend_alloc 5ed12a758531a2034188ea446b10c840 +1057 bytes
  replaced emscripten_builtin_malloc b59a247d540cc3c724f6b08e5961d7b8 -> 4c854ab40f762e03399b96e39b6dcbab -404 bytes
```

The line has the form `replaced <name> <before> -> <after> <net> bytes`, where
`<net>` is the sum of both entries. JSON and CSV keep both entries, and the facts
`symbols added` and `symbols removed` count both. A name that is repeated on
either side, or that has no counterpart, is listed as plain added and removed
entries with `counterpart_fingerprint` null.

The text report reads from the coarsest summary to the detail: the ownership
delta, the stem delta, the symbol changes, and then the changes to duplicate
groups under their own heading:

```text
duplicate group changes:
  exact 7a4bb1d56eafb391d09d8fd25d800c55 +4 bytes, +2 members
  exact ec96a463ac6702ea108315dd3a8bbc11 +2 bytes, +1 member
```

When both artifacts record an architecture and the two differ, every rendering of
the comparison says so. A calibration is refused outright for artifacts of
different formats or architectures, and for an architecture selected from a
universal Mach-O, whose observed byte counts cover the whole container.

## Limits and isolation

`artifact analyze` and `artifact compare` reject inputs above 512 MiB by default
and run parsing, correlation, persistence and rendering in a separate worker
process with one 30-second deadline. The worker is a separate process, so the
deadline remains enforceable when a malformed input makes a parser stop making
progress, and timeout diagnostics name the phase that was running.

- `--max-bytes` and `--timeout-seconds` adjust the input and time ceilings. The
  input ceiling also bounds how far DWARF and PDB debug information is expanded
  into frames and line records.
- `--max-memory-bytes <bytes>` enforces a worker virtual-memory ceiling on Linux;
  other platforms reject the option rather than silently ignoring it.
- `--untrusted` clamps all three at once, so it is available on Linux only:
  elsewhere it fails rather than accept an artifact nobody vouches for under a
  memory ceiling that cannot be enforced.

`artifact report` and `artifact calibration` re-read what is already in the local
database and run in process, so none of these options apply to them. The versioned
IR retained for `artifact report` is separately capped at 64 MiB. Raw code and
data bytes are part of it, so a binary well below the input ceiling can exceed it;
`artifact analyze` then prints its report without an analysis id, warns that the
analysis was not saved, and writes no database record for it.

## Reading the result

What these commands measure is the artifact as it was built. They do not forecast
what consolidating duplication in the source would take out of it, and the gap
between the two is wide enough to matter — see [Limitations](limitations.md)
before using a size figure to justify a refactor.
