# Limitations

## A finding measures maintainability, not size

A finding names code a reader has to keep in step, not bytes a compiler emits.
Optimisers routinely fold identical code that is still duplicated in the source,
so removing a reported clone need not make the built artifact any smaller.

Identical code folding can already remove same-signature functions with identical
bodies in C++ and Rust. Type-1 copies are therefore often folded by the linker
already. Type-2 and Type-3 copies that change identifiers or literals can leave
distinct machine code, so they can matter more when size is the reason to inspect
duplication. The two are not the same size of problem: in an optimised build,
what is still byte-for-byte identical in the artifact is a negligible part of it,
while the code that matches only after register and immediate differences are
normalized away is thousands of times larger.
[`codehelion artifact analyze`](artifact-analysis.md) reports the
exact and the normalized figure side by side, so the ratio for your own build is
something you measure rather than assume.

## How much a consolidation actually removes

These are measurements of one project, recorded because the gap between the two
axes surprises people, not because the ratio transfers.

In one measured project, removing 238 lines of real code — 2,714 duplicated
tokens — took 3,554 bytes (0.14%) off the uncompressed build and 584 bytes
(0.09%) off the Brotli-compressed one; two releases later, consolidating 14 clone
groups took off 15,323 bytes (0.56%) uncompressed and 928 bytes (0.13%)
compressed, 6% of the uncompressed figure. The reason sits upstream of the
refactor: the linker and `wasm-opt` fold identical code before it ships, and a
2.6 MiB shipped WASM module was measured to hold 20 bytes of byte-identical
duplicate in all.

In another measured tree, 1,730 of the 2,726 bytes recovered — 63% — came from a
single source-level template that the compiler had turned into 14 distinct
instantiations, because the predicate closure type differed at every call site.
There is one copy to find in the source, so no clone group describes the
multiplicity; the group codehelion did report on that tree accounted for the
other 996 bytes, the smaller half. See
[instantiation multiplicity](artifact-analysis.md#instantiation-multiplicity).

## Compressed size moves less than uncompressed size does

What removing duplication takes out of an artifact is a repeated byte sequence,
and a repeated byte sequence is the first thing a compressor folds away. The
uncompressed binary shrinks by roughly what was removed; the compressed one
shrinks by much less, because the compressor was already paying almost nothing
for the second copy.

If your size budget is a compressed number, deduplication is not the tool for it.
If it is an uncompressed number — a memory-mapped image, an embedded firmware
image, a WASM module measured before transport encoding — it is.
Measure both before and after your own refactor rather than taking a ratio from
anywhere else; nothing here re-derives one for you.

## Fast mode reports more than you want to read

The suppression policies for boilerplate, test code and integer-width families
need structural classifications, so Fast mode cannot apply them and says so in the
report. On a tree of any size, `--mode structural` is what produces a list worth
reading top-down.

## Incomplete or edited copies are harder to detect

Structural and Semantic modes run two sibling channels. The similarity channel
always runs: it retains an ungrouped unit that measures close to a group's
canonical member and sits in a file that group already occupies. The signature
channel is opt-in with `--siblings-by-signature` and off by default; enabled, it
can retain a low-confidence sibling when its normalized signature matches the
group's canonical function and the otherwise ungrouped function is in the
same directory.

A shared signature is evidence only while it is rare, so a signature that more
units share than `limits.signature-sibling-max-units-per-signature` allows is left
out of the search entirely, and the summary names how many signatures were left
out and how far the widest one reached. Candidates removed by that limit are
counted apart from those a search ceiling dropped, so a reader can tell which of
the two to move; both are configurable, and the counts are deterministic for a
given tree and settings rather than a property of the machine.
`--show-siblings` only changes text visibility; JSON and SARIF retain generated
sibling data.

A mirror in another directory, a changed signature, or a candidate beyond the
sibling-search ceiling can still keep a copy out; codehelion is not a
mirror-consistency checker. It does not prove that every mirror has been found or
that two same-signature bodies behave alike.

An intact copy is maintenance debt; a copy that has drifted is a bug today — and
the drifted one is the harder of the two to detect, which is the reverse of the
order a mirror audit wants. In one measured case an enum-to-string mapping had
been hand-mirrored across three surfaces: the three intact copies were all
grouped, and the one copy actually missing three names — the copy causing a live
bug — landed in no group at all. In another, three functions built the same path;
the two exact ones were grouped, and the third, differing only in taking an early
return where the others used an else branch, appeared neither under
`--show-siblings` nor under `--show-near-misses`. Both were found by hand, with
`grep`. So when a group is reported, read what sits beside it: the same-shaped
neighbours the group does not include are where a drifted copy is most likely to
be.

## A layer built on one signature gets nothing from that channel

Where a dispatch or callback table gives a hundred functions the same callable
shape, the signature separates nothing, and the channel has no evidence to offer
about that layer at all. Saying so is the point of the sharing limit: the
alternative is thousands of siblings that each pair one arbitrary function with
another, which reads like a result until it is examined.

## Large trees hit ceilings

The candidate budget and the high-frequency posting cap bound the search, and a
run that hits either reports how much it left unexamined. The index is held in
memory, so a very large tree is bounded by the ceilings rather than by disk.

## Artifact inspection depends on symbols

A stripped binary yields almost nothing; supply the unstripped build or a
verified debug companion. Duplicate detection that sees past register and
immediate differences covers native machine code built for x86 and, separately,
WebAssembly, which is normalized over its own opcode stream; on a native artifact
built for another architecture, only byte-identical duplicates are found.

Correlating an artifact back to the sources reads a name out of each symbol, which
is done for Rust and for the Itanium C++ ABI; a C++ artifact decorated for the
Microsoft ABI is still read for size and duplication, but reports no source
correspondence rather than a guessed one.

## The audit database is not migrated

A database written under a different schema is never converted, so no history
carries across one. At the default path a run leaves that database exactly where
it is, records into `audit-v<schema>.db` beside it, and says which file it used; a
database named with `--db` is refused instead, since writing somewhere else would
ignore the path that was asked for. `doctor` lists every audit database in the
directory, which of them this build can open, and which one a run would take.
This will change before 1.0.
