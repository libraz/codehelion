use super::{
    BTreeMap, BTreeSet, BuildVariant, ByteRange, CloneClass, ContentNorm, FileContext,
    FragmentFingerprint, LiteralNorm, RegionOccurrence, RegionSide, SharedRegion, StructuralRegion,
    SyntaxIrFile, Token, line_range, maximal, stable_id,
};

/// Confirm candidate runs against the tokens they cover and split them into
/// classes that genuinely hold the same content.
pub(super) fn confirm_regions(
    candidates: &[SharedRegion],
    files: &[SyntaxIrFile],
    offsets: &[usize],
    variant: &BuildVariant,
    literals: LiteralNorm,
) -> (Vec<Confirmed>, Dropped) {
    let mut regions = Vec::new();
    let mut dropped = Dropped::default();
    for candidate in candidates {
        // Occurrences whose normalized content agrees are the same run up to
        // renaming; that is the coarsest claim this stage is willing to make.
        let mut classes: BTreeMap<FragmentFingerprint, Vec<(RegionOccurrence, RegionSide)>> =
            BTreeMap::new();
        for &side in &candidate.occurrences {
            let Some((occurrence, normalized)) =
                resolve_occurrence(side, files, offsets, variant, literals)
            else {
                dropped.singletons += 1;
                continue;
            };
            classes
                .entry(normalized)
                .or_default()
                .push((occurrence, side));
        }
        for (normalized_content, class) in classes {
            let class = distinct(class, &mut dropped);
            if class.len() < 2 {
                dropped.singletons += class.len();
                continue;
            }
            let (occurrences, sides): (Vec<RegionOccurrence>, Vec<RegionSide>) =
                class.into_iter().unzip();
            let contents: Vec<FragmentFingerprint> =
                occurrences.iter().map(|entry| entry.content).collect();
            // Identical raw content everywhere means the copies differ in
            // nothing but whitespace and comments.
            let clone_type = if contents.iter().all(|&content| content == contents[0]) {
                CloneClass::Type1
            } else {
                CloneClass::Type2
            };
            regions.push(Confirmed {
                region: StructuralRegion {
                    fingerprint: stable_id::clone_group_fingerprint(
                        variant,
                        clone_type,
                        if clone_type == CloneClass::Type1 {
                            &contents
                        } else {
                            std::slice::from_ref(&normalized_content)
                        },
                    ),
                    clone_type,
                    statements: candidate.statements,
                    occurrences,
                },
                sides,
            });
        }
    }
    // Position-free order: two runs are told apart by content, never by where
    // they happen to sit.
    regions.sort_by(|a, b| {
        a.region
            .fingerprint
            .cmp(&b.region.fingerprint)
            .then_with(|| a.region.clone_type.name().cmp(b.region.clone_type.name()))
    });
    regions.dedup_by(|a, b| {
        a.region.fingerprint == b.region.fingerprint && a.region.occurrences == b.region.occurrences
    });
    (regions, dropped)
}

/// What confirmation set aside, by reason.
///
/// Kept apart rather than summed because the three say different things about
/// the detector: a singleton is a summary that promised more than the code
/// delivered, while the other two are one stretch of code arriving as several
/// occurrences of itself.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Dropped {
    /// Occurrences left without a partner holding the same content.
    pub(super) singletons: usize,
    /// Occurrences covering source a kept occurrence already covers.
    pub(super) overlapping: usize,
    /// Occurrences continuing a kept occurrence, statement for statement.
    pub(super) adjoining: usize,
}

/// Keep one occurrence per stretch of source, dropping any that overlaps or
/// continues one already kept.
///
/// A candidate set is the transitive closure over pairwise matches, so two
/// occurrences that overlap each other can still arrive together by way of a
/// third they both match — even though the pairwise stage rejects an
/// overlapping pair as one stretch of code rather than two. That rejection has
/// to hold here too, or a run of interchangeable statements comes back as a
/// clone of itself: every shifted window of the run matches every other, and
/// each window arrives as its own occurrence.
///
/// This is the stage that can decide it. Overlapping occurrences reach it only
/// once they are known to hold the same content, so dropping one really does
/// leave the same code behind. Deciding it earlier, on statement summaries
/// alone, discards whichever overlapping window happens to sit first — which is
/// not always the one that holds the shared content.
///
/// Occurrences that merely continue one another are the same case seen from
/// one step further along: a run whose every window matches the next tiles its
/// block instead of overlapping inside it. Neither describes two sites, so
/// neither survives — see [`maximal::adjoins`].
///
/// A class left with one occurrence is not a duplication and is dropped by the
/// caller. `class` must be in occurrence order, which makes the survivor of an
/// overlapping cluster its first member rather than an artefact of match order.
fn distinct(
    class: Vec<(RegionOccurrence, RegionSide)>,
    dropped: &mut Dropped,
) -> Vec<(RegionOccurrence, RegionSide)> {
    let mut kept: Vec<(RegionOccurrence, RegionSide)> = Vec::with_capacity(class.len());
    for entry in class {
        if kept.iter().any(|(_, other)| {
            other.file == entry.1.file && maximal::intersects(other.range, entry.1.range)
        }) {
            dropped.overlapping += 1;
            continue;
        }
        if kept
            .iter()
            .any(|(_, other)| maximal::adjoins(other, &entry.1))
        {
            dropped.adjoining += 1;
            continue;
        }
        kept.push(entry);
    }
    kept
}

/// Join the confirmed runs that describe one stretch at several offsets,
/// confirm the joins in turn, and return how many longer runs that produced.
///
/// Confirmation is what makes the joins possible, so it has to run first: an
/// occurrence's extent is part of its identity while the runs are still
/// candidates, and only once the occurrences that do not hold the content are
/// gone does a family of runs turn out to be one stretch.
///
/// One sweep is enough. [`merge_adjacent`] grows each chain to its maximum in
/// a single pass, so a second round would have nothing left to reach; joining
/// pair by pair and repeating would instead emit every intermediate length,
/// which on a long repetitive block is quadratically many candidates to
/// confirm.
pub(super) fn grow_runs(
    confirmed: &mut Vec<Confirmed>,
    dropped: &mut Dropped,
    files: &[SyntaxIrFile],
    offsets: &[usize],
    variant: &BuildVariant,
    literals: LiteralNorm,
) -> usize {
    let candidates = merge_adjacent(confirmed);
    if candidates.is_empty() {
        return 0;
    }
    let (grown, again) = confirm_regions(&candidates, files, offsets, variant, literals);
    dropped.singletons += again.singletons;
    dropped.overlapping += again.overlapping;
    dropped.adjoining += again.adjoining;
    let before = confirmed.len();
    confirmed.extend(grown);
    confirmed.sort_by_key(|entry| entry.region.fingerprint);
    confirmed.dedup_by(|a, b| {
        a.region.fingerprint == b.region.fingerprint && a.region.occurrences == b.region.occurrences
    });
    confirmed.len() - before
}

/// A confirmed run together with the candidate sides it was confirmed from.
///
/// The sides carry the statement indices [`merge_adjacent`] needs and the
/// report does not, so they travel beside the region rather than inside it.
pub(super) struct Confirmed {
    pub(super) region: StructuralRegion,
    pub(super) sides: Vec<RegionSide>,
}

/// Candidate runs made by joining confirmed runs that continue one another.
///
/// The window fold already joins seeds that touch, but it works on candidate
/// occurrence sets, and an occurrence's extent is part of its identity there:
/// a stretch shared six statements deep with one neighbour and four with
/// another is two sets, deliberately, because merging them would credit the
/// second neighbour with statements it does not have. Confirmation then drops
/// whichever occurrences do not really hold the content — and once the short
/// neighbour is gone, what is left of the two sets is one run reported twice,
/// at two offsets, with the same occurrences.
///
/// Joining them is sound for the same reason the fold is: runs at one
/// alignment that overlap or touch compose into their union, every statement
/// of which is covered by one of them at the same relative position. Nothing
/// is assumed about the join — the result goes back through confirmation like
/// any other candidate, and the parts it covers are dropped afterwards by
/// [`drop_subsumed`], which keeps a part making a stricter claim than the
/// whole.
///
/// Runs are grown in one sweep per alignment rather than pair by pair. Pairing
/// every run with every other would emit each intermediate length as its own
/// candidate, and a long repetitive block has quadratically many of those; the
/// sweep emits only the maximal run each chain reaches, which is the only one
/// that survives [`drop_subsumed`] anyway.
pub(super) fn merge_adjacent(confirmed: &[Confirmed]) -> Vec<SharedRegion> {
    // Runs join only if their occurrences sit in the same places and hold the
    // same offsets relative to one another, so that is the bucket key: within
    // one bucket the runs differ in nothing but where the chain starts.
    let mut alignments: BTreeMap<Alignment, Vec<&Confirmed>> = BTreeMap::new();
    for entry in confirmed {
        let Some(alignment) = alignment_of(entry) else {
            continue;
        };
        alignments.entry(alignment).or_default().push(entry);
    }

    let mut joined = Vec::new();
    for mut runs in alignments.into_values() {
        runs.sort_by_key(|entry| entry.sides[0].run.start);
        let mut chain: Option<Chain> = None;
        for run in runs {
            let touches = chain
                .as_ref()
                .is_some_and(|grown| run.sides[0].run.start <= grown.sides[0].run.end());
            match chain.as_mut() {
                Some(grown) if touches => grown.absorb(&run.sides),
                _ => {
                    if let Some(region) = chain.take().and_then(Chain::finish) {
                        joined.push(region);
                    }
                    chain = Some(Chain::starting_at(&run.sides));
                }
            }
        }
        if let Some(region) = chain.and_then(Chain::finish) {
            joined.push(region);
        }
    }
    joined.sort_unstable();
    joined.dedup();
    joined
}

/// A run of runs, grown along one alignment.
struct Chain {
    /// The union so far, one entry per occurrence.
    sides: Vec<RegionSide>,
    /// The longest single run the chain has absorbed. The union is only worth
    /// proposing when it is longer than this: a chain of one says nothing new,
    /// and a run wholly inside another is containment, which
    /// [`drop_subsumed`] settles without a fresh confirmation.
    longest: u32,
}

impl Chain {
    fn starting_at(sides: &[RegionSide]) -> Self {
        Self {
            sides: sides.to_vec(),
            longest: sides.first().map_or(0, |side| side.run.length),
        }
    }

    fn absorb(&mut self, sides: &[RegionSide]) {
        for (grown, part) in self.sides.iter_mut().zip(sides) {
            grown.run.length = part.run.end().max(grown.run.end()) - grown.run.start;
            grown.range.start = grown.range.start.min(part.range.start);
            grown.range.end = grown.range.end.max(part.range.end);
        }
        self.longest = self
            .longest
            .max(sides.first().map_or(0, |side| side.run.length));
    }

    /// Whether growing the chain has made two of its occurrences reach into
    /// each other. Repetitive code matches a shifted copy of itself, and a
    /// long enough union of those matches runs into its own other end: that is
    /// one stretch of source, not two instances of anything. The fold has the
    /// same guard for the same reason.
    fn overlaps_itself(&self) -> bool {
        self.sides.iter().enumerate().any(|(index, here)| {
            self.sides[index + 1..].iter().any(|there| {
                here.file == there.file && maximal::intersects(here.range, there.range)
            })
        })
    }

    fn finish(mut self) -> Option<SharedRegion> {
        let statements = self.sides.first()?.run.length;
        if statements <= self.longest {
            return None;
        }
        if self.overlaps_itself() {
            return None;
        }
        self.sides.sort_unstable();
        Some(SharedRegion {
            occurrences: self.sides,
            statements,
        })
    }
}

/// How a run's occurrences sit relative to one another: where each is, and how
/// far it starts from the first. Two runs with the same alignment describe the
/// same stretch at different offsets along it.
type Alignment = Vec<(usize, usize, u32, i64)>;

/// A run's alignment, or `None` when it has no occurrences to align.
fn alignment_of(entry: &Confirmed) -> Option<Alignment> {
    let anchor = i64::from(entry.sides.first()?.run.start);
    Some(
        entry
            .sides
            .iter()
            .map(|side| {
                (
                    side.file,
                    side.unit,
                    side.run.block,
                    i64::from(side.run.start) - anchor,
                )
            })
            .collect(),
    )
}

/// Drop the runs a longer run already accounts for, returning how many went.
///
/// The window lengths overlap by construction, so one duplicated stretch
/// surfaces as a family of runs: the same eight statements confirm at length
/// eight, and their first six confirm again with whatever extra copies share
/// only those six. A run is dropped when *every* one of its occurrences sits
/// inside an occurrence of another run — the covering run reports the same
/// code in the same places, and more of it.
///
/// Coverage alone is not enough. A verbatim run nested inside a longer run
/// that only matches up to renaming makes the stronger claim of the two:
/// "these eight statements match up to renaming, and these six of them match
/// verbatim" is two facts, not one repeated. So a run is only dropped by a
/// cover that classifies at least as strictly, [`CloneClass`] ordering running
/// from exact to gapped.
pub(super) fn drop_subsumed(regions: &mut Vec<StructuralRegion>) -> usize {
    let before = regions.len();
    // Widest cover first, so a run is judged against the longest thing that
    // could account for it before anything shorter is considered.
    let mut order: Vec<usize> = (0..regions.len()).collect();
    order.sort_by_key(|&index| {
        (
            std::cmp::Reverse(regions[index].statements),
            regions[index].fingerprint,
        )
    });

    let mut dropped = vec![false; regions.len()];
    let mut coverage = RegionCoverageIndex::default();
    for &inner in &order {
        // Only wider runs, and among equals only those already settled, enter
        // the index. A pair of runs covering each other therefore cannot
        // remove both.
        let covered = coverage
            .candidates(&regions[inner])
            .into_iter()
            .any(|outer| covers_run(&regions[outer], &regions[inner]));
        if covered {
            dropped[inner] = true;
        } else {
            coverage.insert(inner, &regions[inner]);
        }
    }
    *regions = std::mem::take(regions)
        .into_iter()
        .zip(&dropped)
        .filter_map(|(region, &drop)| (!drop).then_some(region))
        .collect();
    before - regions.len()
}

/// An occurrence index over the regions that survived the containment pass.
///
/// Every outer region that can subsume an inner one must cover each of its
/// occurrences. Querying the occurrence with the fewest indexed covers avoids
/// the former scan over every earlier region; [`covers_run`] remains the
/// authority for the complete multi-occurrence and clone-class check.
#[derive(Default)]
struct RegionCoverageIndex {
    by_file: BTreeMap<usize, BTreeMap<usize, Vec<IndexedOccurrence>>>,
}

#[derive(Clone, Copy)]
struct IndexedOccurrence {
    end: usize,
    region: usize,
}

impl RegionCoverageIndex {
    fn insert(&mut self, region: usize, value: &StructuralRegion) {
        for occurrence in &value.occurrences {
            self.by_file
                .entry(occurrence.file)
                .or_default()
                .entry(occurrence.range.start)
                .or_default()
                .push(IndexedOccurrence {
                    end: occurrence.range.end,
                    region,
                });
        }
    }

    /// Return IDs of regions covering the least-popular occurrence of `value`.
    fn candidates(&self, value: &StructuralRegion) -> BTreeSet<usize> {
        let mut best: Option<BTreeSet<usize>> = None;
        for occurrence in &value.occurrences {
            let candidates = self.covering(occurrence);
            if candidates.is_empty() {
                return candidates;
            }
            if best
                .as_ref()
                .is_none_or(|current| candidates.len() < current.len())
            {
                best = Some(candidates);
            }
        }
        best.unwrap_or_default()
    }

    fn covering(&self, occurrence: &RegionOccurrence) -> BTreeSet<usize> {
        let Some(starts) = self.by_file.get(&occurrence.file) else {
            return BTreeSet::new();
        };
        starts
            .range(..=occurrence.range.start)
            .flat_map(|(_, covers)| covers)
            .filter(|cover| occurrence.range.end <= cover.end)
            .map(|cover| cover.region)
            .collect()
    }
}

/// Whether `outer` accounts for every occurrence of `inner`.
pub(super) fn covers_run(outer: &StructuralRegion, inner: &StructuralRegion) -> bool {
    if outer.fingerprint == inner.fingerprint || outer.clone_type > inner.clone_type {
        return false;
    }
    inner.occurrences.iter().all(|occurrence| {
        outer.occurrences.iter().any(|cover| {
            cover.file == occurrence.file
                && cover.range.start <= occurrence.range.start
                && occurrence.range.end <= cover.range.end
        })
    })
}

/// Resolve one candidate occurrence into its tokens, returning the reportable
/// occurrence and its normalized content fingerprint (the class key).
fn resolve_occurrence(
    side: RegionSide,
    files: &[SyntaxIrFile],
    offsets: &[usize],
    variant: &BuildVariant,
    literals: LiteralNorm,
) -> Option<(RegionOccurrence, FragmentFingerprint)> {
    let file = files.get(side.file)?;
    let (start, end) = token_span(&file.tokens, side.range);
    if start >= end {
        return None;
    }
    let tokens = &file.tokens[start..end];
    let context = FileContext {
        frontend_version: file.frontend_version,
        language: file.language,
    };
    let fingerprint =
        |norm| stable_id::fragment_fingerprint(variant, &context, "statement-run", tokens, norm);
    let lines = line_range(tokens);
    Some((
        RegionOccurrence {
            file: side.file,
            unit: offsets[side.file] + side.unit,
            range: side.range,
            start_line: lines.0,
            end_line: lines.1,
            token_start: start,
            token_end: end,
            content: fingerprint(ContentNorm::Raw),
        },
        fingerprint(ContentNorm::Normalized(literals)),
    ))
}

/// The half-open token index range fully inside a byte range. Tokens are in
/// source order, so both ends are found by binary search.
fn token_span(tokens: &[Token], range: ByteRange) -> (usize, usize) {
    let start = tokens.partition_point(|token| token.span.start_byte < range.start);
    let end = tokens.partition_point(|token| token.span.end_byte <= range.end);
    (start, end.max(start))
}
