# Glossary

**baseline** — a file recording the findings a project has accepted, which later
scans read to report what came after it. Names whole groups. See
[Baselines](baselines.md).

**boilerplate classification** — a shape a body was recognised as: a trivial
body, a forwarding call, a guarded dispatch. Recorded whatever the suppression
policy does with it.

**build variant** — the conditions something was produced under. A source run has
one, describing how the sources were read; an artifact has one you write as a JSON
manifest, describing how it was built. The two are recorded side by side and never
checked against each other.

**canonical member** — the occurrence a group is measured against, marked `◆` in
the listing. Every other member cleared the gate against it.

**candidate** — a pair proposed by the index and not yet verified. The candidate
pipeline is what `-vv` prints.

**clone class** — Type-1, Type-2 or Type-3. See [Clone types](clone-types.md).

**clone group** — the set of occurrences reported together as one finding, with
one stable id.

**cohesion** — how tightly a group's members agree with one another, as opposed
to each agreeing with the canonical member.

**content entropy** — how much the content of a group varies, used to tell a
routine from degenerate repetition of the same few tokens.

**duplicated tokens** — the tokens a group repeats past its canonical member; one
of the axes `--sort` accepts.

**finding id** — the stable id of one occurrence, printed as `[finding <ID>]`
under `-v`. Distinct from the group's id.

**fragment** — a run of statements inside one body, as opposed to a whole body.

**gate** — the similarity threshold a candidate must clear against the canonical
member to join a group.

**identifier agreement** — how much two occurrences' identifiers overlap,
measured on whole units. High agreement usually means nobody has diverged the two
copies yet.

**lineage** — the recorded link from a group in one run to the group it inherited
from in the run before, when content changed enough to move the id.

**near miss** — a proposal that landed just under the gate, retained as a
diagnostic. `--show-near-misses` lists them.

**normalization** — removing comments and whitespace and rewriting identifiers
and literals before comparison. The literal part is configurable.

**occurrence** — one place a group's duplication appears: a file, a line range,
and the unit it sits in.

**posting** — an entry in the content index. A posting list shared by too many
units is dropped, because it proposes work rather than duplication.

**priority** — the composed ranking value a report is ordered on, derived from
clone confidence, maintenance risk and refactoring difficulty. Only the
composition is configurable.

**run** — one completed scan, recorded in the local database with an id that
replays it.

**sibling** — an ungrouped unit retained beside a group as evidence: close to the
canonical member, or matching its normalized signature. See
[Grouping](grouping.md).

**signature** — a function's normalized callable shape. Evidence only while it is
rare.

**split pair** — a verified pair that no complete group can hold, reported below
the complete groups.

**suppressed** — hidden by a rule, and counted in the totals. `--show-suppressed`
lists them with the reason each was hidden.

**unit** — one whole body: a function, a method.

**verified savings** — the observed size difference between two real builds,
attributed to one named clone group. Means what it says only for a pair of builds
that differ in nothing else. See [Calibration](calibration.md).
