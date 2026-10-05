//! Unique symbol fingerprints for symbols that share one content identity.
//!
//! Two symbols with the same name and body carry the same content
//! fingerprint, yet each occupies its own bytes and its own place in the call
//! graph. Copies are told apart by Weisfeiler–Lehman colour refinement over
//! the call graph: a copy's colour starts from its content, reachability bit,
//! size and body identity, and each round folds in the colours of its callers
//! and callees and its unresolved calls. Refinement runs separately per weakly
//! connected component of copy-to-copy edges, so adding an unrelated group of
//! copies never moves another copy's identity. Copies the refinement cannot
//! separate are numbered in file order and marked as such.
//!
//! Every set that feeds a hash is ordered, so the result depends only on the
//! input and never on hash-map iteration order.

#![allow(clippy::redundant_pub_crate)] // reached from the format backends

use std::collections::{BTreeMap, BTreeSet};

use crate::{ArtifactCall, ArtifactFingerprint, ArtifactSymbol, UnresolvedCall};

/// A call between two symbols of one parse, by position in the symbol list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PositionalCall {
    /// Position of the calling symbol.
    pub(crate) caller: usize,
    /// Position of the called symbol, when the call has a local target.
    pub(crate) target: Option<usize>,
    /// Why no exact target is asserted.
    pub(crate) unresolved: Option<UnresolvedCall>,
}

/// Make every symbol's `fingerprint` unique within `symbols`.
///
/// `roots` are the positions the backend treats as reachable from outside
/// (exports are read from the symbols themselves). On return each copy
/// carries `content_fingerprint`, and `identity_by_order` when its
/// fingerprint needed file order. Calls are returned by fingerprint.
pub(crate) fn assign_identities(
    symbols: &mut [ArtifactSymbol],
    roots: &BTreeSet<usize>,
    calls: Vec<PositionalCall>,
) -> Vec<ArtifactCall> {
    let graph = Graph::new(symbols.len(), &calls);
    let mut ties: BTreeMap<Colour, Vec<usize>> = BTreeMap::new();
    for (position, colour) in refined_colours(symbols, roots, &graph) {
        ties.entry(colour).or_default().push(position);
    }
    for (colour, positions) in ties {
        let by_order = positions.len() > 1;
        for (number, position) in positions.into_iter().enumerate() {
            let symbol = &mut symbols[position];
            let content = symbol.fingerprint;
            symbol.fingerprint =
                copy_fingerprint(content, colour, by_order.then_some(number as u64));
            symbol.content_fingerprint.get_or_insert(content);
            symbol.identity_by_order |= by_order;
        }
    }
    debug_assert!(
        fingerprints_are_unique(symbols),
        "assigned symbol fingerprints collide"
    );
    calls
        .into_iter()
        .map(|call| ArtifactCall {
            caller: symbols[call.caller].fingerprint,
            target: call.target.map(|target| symbols[target].fingerprint),
            unresolved: call.unresolved,
        })
        .collect()
}

/// A refinement colour; copies end up sharing one only when indistinguishable.
type Colour = ArtifactFingerprint;

/// Callers, callees and unresolved calls of every symbol, as sets.
struct Graph {
    callers: Vec<BTreeSet<usize>>,
    callees: Vec<BTreeSet<usize>>,
    unresolved: Vec<BTreeSet<&'static str>>,
}

impl Graph {
    fn new(len: usize, calls: &[PositionalCall]) -> Self {
        let mut graph = Self {
            callers: vec![BTreeSet::new(); len],
            callees: vec![BTreeSet::new(); len],
            unresolved: vec![BTreeSet::new(); len],
        };
        for call in calls {
            if let Some(target) = call.target {
                graph.callees[call.caller].insert(target);
                graph.callers[target].insert(call.caller);
            }
            if let Some(reason) = call.unresolved {
                graph.unresolved[call.caller].insert(unresolved_label(reason));
            }
        }
        graph
    }

    /// One Weisfeiler–Lehman round for the symbol at `position`.
    fn next_colour(&self, position: usize, colours: &[Colour]) -> Colour {
        let mut payload = Vec::new();
        field(&mut payload, &colours[position].as_bytes());
        for neighbours in [&self.callers[position], &self.callees[position]] {
            let set: BTreeSet<Colour> = neighbours.iter().map(|other| colours[*other]).collect();
            payload.extend((set.len() as u64).to_le_bytes());
            for colour in set {
                payload.extend(colour.as_bytes());
            }
        }
        let unresolved = &self.unresolved[position];
        payload.extend((unresolved.len() as u64).to_le_bytes());
        for label in unresolved {
            field(&mut payload, label.as_bytes());
        }
        ArtifactFingerprint::from_content("artifact-symbol-colour-round", &payload)
    }
}

/// The final colour of every copy, keyed by position.
fn refined_colours(
    symbols: &[ArtifactSymbol],
    roots: &BTreeSet<usize>,
    graph: &Graph,
) -> BTreeMap<usize, Colour> {
    let mut sharing: BTreeMap<ArtifactFingerprint, Vec<usize>> = BTreeMap::new();
    for (position, symbol) in symbols.iter().enumerate() {
        sharing
            .entry(symbol.fingerprint)
            .or_default()
            .push(position);
    }
    let copies: BTreeSet<usize> = sharing
        .into_values()
        .filter(|positions| positions.len() > 1)
        .flatten()
        .collect();
    // A symbol outside the copies keeps its content as its colour throughout.
    let mut colours: Vec<Colour> = symbols.iter().map(|symbol| symbol.fingerprint).collect();
    for &position in &copies {
        let symbol = &symbols[position];
        colours[position] = initial_colour(symbol, symbol.exported || roots.contains(&position));
    }
    for component in components(&copies, graph) {
        refine(&component, graph, &mut colours);
    }
    copies
        .into_iter()
        .map(|position| (position, colours[position]))
        .collect()
}

/// Weakly connected components of `copies` over edges between two copies.
fn components(copies: &BTreeSet<usize>, graph: &Graph) -> Vec<Vec<usize>> {
    let mut seen = BTreeSet::new();
    let mut components = Vec::new();
    for &start in copies {
        if !seen.insert(start) {
            continue;
        }
        let mut component = Vec::new();
        let mut pending = vec![start];
        while let Some(position) = pending.pop() {
            component.push(position);
            for &other in graph.callers[position].union(&graph.callees[position]) {
                if copies.contains(&other) && seen.insert(other) {
                    pending.push(other);
                }
            }
        }
        component.sort_unstable();
        components.push(component);
    }
    components
}

/// Refine one component's colours until its partition stops splitting.
///
/// Each colour folds in the previous one, so the partition only gets finer.
/// Each splitting round adds at least one class, so at most
/// `component.len() - initial_count` splitting rounds are possible.
fn refine(component: &[usize], graph: &Graph, colours: &mut [Colour]) {
    let distinct = |colours: &[Colour]| {
        component
            .iter()
            .map(|position| colours[*position])
            .collect::<BTreeSet<_>>()
            .len()
    };
    let mut before = distinct(colours);
    loop {
        let next: Vec<Colour> = component
            .iter()
            .map(|position| graph.next_colour(*position, colours))
            .collect();
        for (position, colour) in component.iter().zip(next) {
            colours[*position] = colour;
        }
        let after = distinct(colours);
        if after <= before {
            break;
        }
        before = after;
    }
}

/// Colour a copy starts from: its content, whether something outside the
/// artifact reaches it, its size, and its body identity.
fn initial_colour(symbol: &ArtifactSymbol, rooted: bool) -> Colour {
    let mut payload = Vec::new();
    field(&mut payload, &symbol.fingerprint.as_bytes());
    field(&mut payload, &[u8::from(rooted)]);
    field(&mut payload, &symbol.size.to_le_bytes());
    match symbol.body_fingerprint {
        Some(body) => field(&mut payload, &body.as_bytes()),
        None => field(&mut payload, &[]),
    }
    ArtifactFingerprint::from_content("artifact-symbol-colour-initial", &payload)
}

/// The fingerprint a copy carries: its content, its final colour, and its
/// file-order number when the colour alone does not single it out.
fn copy_fingerprint(content: Colour, colour: Colour, number: Option<u64>) -> ArtifactFingerprint {
    let mut payload = Vec::new();
    field(&mut payload, &content.as_bytes());
    field(&mut payload, &colour.as_bytes());
    field(&mut payload, &[u8::from(number.is_some())]);
    if let Some(number) = number {
        field(&mut payload, &number.to_le_bytes());
    }
    ArtifactFingerprint::from_content("artifact-symbol-copy-v1", &payload)
}

/// Append `bytes` behind its length, so adjacent fields cannot run together.
fn field(payload: &mut Vec<u8>, bytes: &[u8]) {
    payload.extend((bytes.len() as u64).to_le_bytes());
    payload.extend(bytes);
}

/// The serialized spelling of an unresolved call, fixed here so a renamed
/// variant cannot silently move a copy's identity.
const fn unresolved_label(reason: UnresolvedCall) -> &'static str {
    match reason {
        UnresolvedCall::IndirectTable => "indirect-table",
        UnresolvedCall::ExternalImport => "external-import",
        UnresolvedCall::NativeIndirect => "native-indirect",
        UnresolvedCall::MissingRelocation => "missing-relocation",
    }
}

fn fingerprints_are_unique(symbols: &[ArtifactSymbol]) -> bool {
    let distinct: BTreeSet<_> = symbols.iter().map(|symbol| symbol.fingerprint).collect();
    distinct.len() == symbols.len()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn content(key: u8) -> ArtifactFingerprint {
        ArtifactFingerprint::from_content("identity-test-content", &[key])
    }

    fn symbol(key: u8) -> ArtifactSymbol {
        ArtifactSymbol {
            fingerprint: content(key),
            name: None,
            exported: false,
            section: None,
            offset: 0,
            size: 1,
            size_inferred: false,
            code: Vec::new(),
            normalized: None,
            body_fingerprint: None,
            inline_stack: Vec::new(),
            content_fingerprint: None,
            identity_by_order: false,
        }
    }

    fn call(caller: usize, target: usize) -> PositionalCall {
        PositionalCall {
            caller,
            target: Some(target),
            unresolved: None,
        }
    }

    fn assigned(
        keys: &[u8],
        roots: &[usize],
        calls: &[PositionalCall],
    ) -> (Vec<ArtifactSymbol>, Vec<ArtifactCall>) {
        let mut symbols: Vec<_> = keys.iter().copied().map(symbol).collect();
        let roots = roots.iter().copied().collect();
        let calls = assign_identities(&mut symbols, &roots, calls.to_vec());
        (symbols, calls)
    }

    fn assert_unique(symbols: &[ArtifactSymbol]) {
        let distinct: BTreeSet<_> = symbols.iter().map(|symbol| symbol.fingerprint).collect();
        assert_eq!(distinct.len(), symbols.len(), "{symbols:#?}");
    }

    #[test]
    fn identical_input_gives_identical_fingerprints() {
        // 0 and 1 call one copy each; 2..=5 are copies of key 9, two of which
        // nothing tells apart.
        let keys = [1, 2, 9, 9, 9, 9];
        let calls = [call(0, 2), call(1, 3), call(0, 4), call(0, 5)];

        let first = assigned(&keys, &[0], &calls);
        let second = assigned(&keys, &[0], &calls);

        assert!(
            first
                .0
                .iter()
                .filter(|s| s.content_fingerprint.is_some())
                .count()
                >= 2
        );
        assert_eq!(first, second);
        assert_unique(&first.0);
    }

    #[test]
    fn indistinguishable_copies_are_numbered_and_marked() {
        let (symbols, calls) = assigned(&[1, 9, 9], &[0], &[call(0, 1), call(0, 2)]);

        assert_unique(&symbols);
        assert!(!symbols[0].identity_by_order);
        assert_eq!(symbols[0].content_fingerprint, None);
        for copy in &symbols[1..] {
            assert!(copy.identity_by_order, "{copy:#?}");
            assert_eq!(copy.content_fingerprint, Some(content(9)));
        }
        assert_eq!(calls[0].target, Some(symbols[1].fingerprint));
        assert_eq!(calls[1].target, Some(symbols[2].fingerprint));
    }

    #[test]
    fn a_copy_told_apart_by_its_caller_is_not_marked() {
        let (symbols, calls) = assigned(&[1, 2, 9, 9], &[], &[call(0, 2), call(1, 3)]);

        assert_unique(&symbols);
        assert!(symbols.iter().all(|symbol| !symbol.identity_by_order));
        assert_eq!(calls[0].caller, content(1));
        assert_eq!(calls[0].target, Some(symbols[2].fingerprint));
        assert_eq!(calls[1].target, Some(symbols[3].fingerprint));
    }

    #[test]
    fn an_unrelated_copy_group_does_not_move_other_copies() {
        // Copies of 9 told apart by callers 1 and 2.
        let alone = assigned(&[1, 2, 9, 9], &[], &[call(0, 2), call(1, 3)]);
        // The same graph after a second group of copies, with a caller of its
        // own, was laid out in front of and between it.
        let joined = assigned(
            &[8, 1, 8, 2, 9, 9, 3],
            &[],
            &[call(1, 4), call(3, 5), call(6, 0), call(6, 2)],
        );

        assert_unique(&joined.0);
        assert_eq!(alone.0[2].fingerprint, joined.0[4].fingerprint);
        assert_eq!(alone.0[3].fingerprint, joined.0[5].fingerprint);
    }

    #[test]
    fn unique_symbols_keep_their_fingerprints() {
        let keys = [1, 2, 9, 3, 9];
        let (symbols, _) = assigned(&keys, &[0], &[call(0, 1), call(1, 2), call(3, 4)]);

        for position in [0, 1, 3] {
            let unique = &symbols[position];
            assert_eq!(unique.fingerprint, content(keys[position]));
            assert_eq!(unique.content_fingerprint, None);
            assert!(!unique.identity_by_order);
        }
        assert_ne!(symbols[2].fingerprint, content(9));
        assert_unique(&symbols);
    }

    #[test]
    fn a_copy_referenced_as_a_root_differs_from_an_unreferenced_twin() {
        let (symbols, _) = assigned(&[9, 9], &[1], &[]);

        assert_unique(&symbols);
        assert!(symbols.iter().all(|symbol| !symbol.identity_by_order));

        let mut exported: Vec<_> = [9, 9].into_iter().map(symbol).collect();
        exported[0].exported = true;
        assign_identities(&mut exported, &BTreeSet::new(), Vec::new());
        assert_unique(&exported);
        assert!(exported.iter().all(|symbol| !symbol.identity_by_order));
    }

    #[test]
    fn an_existing_content_fingerprint_is_kept() {
        let mut symbols: Vec<_> = [9, 9].into_iter().map(symbol).collect();
        symbols[0].content_fingerprint = Some(content(7));

        assign_identities(&mut symbols, &BTreeSet::new(), Vec::new());

        assert_eq!(symbols[0].content_fingerprint, Some(content(7)));
        assert_eq!(symbols[1].content_fingerprint, Some(content(9)));
    }

    /// A label a symbol is seen by from its neighbours in the reference
    /// partition: its content for a unique symbol, its class for a copy.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    enum Label {
        Fixed(ArtifactFingerprint),
        Class(usize),
    }

    /// The coarsest stable partition of the copies, by repeated splitting of
    /// explicit classes until no class splits.
    fn naive_partition(
        symbols: &[ArtifactSymbol],
        roots: &BTreeSet<usize>,
        calls: &[PositionalCall],
    ) -> BTreeSet<BTreeSet<usize>> {
        let mut sharing: BTreeMap<ArtifactFingerprint, usize> = BTreeMap::new();
        for symbol in symbols {
            *sharing.entry(symbol.fingerprint).or_default() += 1;
        }
        let copies: Vec<usize> = (0..symbols.len())
            .filter(|position| sharing[&symbols[*position].fingerprint] > 1)
            .collect();
        let mut class: BTreeMap<usize, usize> = BTreeMap::new();
        let mut initial = BTreeMap::new();
        for &position in &copies {
            let symbol = &symbols[position];
            let rooted = roots.contains(&position) || symbol.exported;
            let key = (
                symbol.fingerprint,
                rooted,
                symbol.size,
                symbol.body_fingerprint,
            );
            let next = initial.len();
            class.insert(position, *initial.entry(key).or_insert(next));
        }
        loop {
            let label = |position: usize| {
                class.get(&position).map_or_else(
                    || Label::Fixed(symbols[position].fingerprint),
                    |class| Label::Class(*class),
                )
            };
            let mut signatures = BTreeMap::new();
            let mut next_class = BTreeMap::new();
            for &position in &copies {
                let called_by: BTreeSet<Label> = calls
                    .iter()
                    .filter(|call| call.target == Some(position))
                    .map(|call| label(call.caller))
                    .collect();
                let callees: BTreeSet<Label> = calls
                    .iter()
                    .filter(|call| call.caller == position)
                    .filter_map(|call| call.target.map(label))
                    .collect();
                let unresolved: BTreeSet<String> = calls
                    .iter()
                    .filter(|call| call.caller == position)
                    .filter_map(|call| call.unresolved.map(|reason| format!("{reason:?}")))
                    .collect();
                let signature = (class[&position], called_by, callees, unresolved);
                let next = signatures.len();
                next_class.insert(position, *signatures.entry(signature).or_insert(next));
            }
            let before: BTreeSet<_> = class.values().collect();
            let after: BTreeSet<_> = next_class.values().collect();
            let stable = before.len() == after.len();
            class = next_class;
            if stable {
                break;
            }
        }
        let mut groups: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
        for (position, class) in class {
            groups.entry(class).or_default().insert(position);
        }
        groups.into_values().collect()
    }

    /// A 64-bit linear congruential generator, enough to vary small graphs.
    struct Lcg(u64);

    impl Lcg {
        fn below(&mut self, bound: u64) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 33) % bound
        }
    }

    #[test]
    fn refinement_matches_naive_partition_on_random_graphs() {
        let mut random = Lcg(0x5eed_1de0);
        let mut graphs_with_copies = 0;
        for _ in 0..256 {
            let count = usize::try_from(2 + random.below(11)).unwrap();
            let mut symbols: Vec<_> = (0..count)
                .map(|_| {
                    let mut symbol = symbol(u8::try_from(random.below(4)).unwrap());
                    symbol.exported = random.below(6) == 0;
                    symbol.size = 1 + random.below(2);
                    symbol.body_fingerprint = (random.below(3) != 0)
                        .then(|| ArtifactFingerprint::from_content("identity-test-body", &[0]));
                    symbol
                })
                .collect();
            let roots: BTreeSet<usize> = (0..count).filter(|_| random.below(6) == 0).collect();
            let calls: Vec<PositionalCall> = (0..random.below(2 * count as u64 + 1))
                .map(|_| {
                    let caller = usize::try_from(random.below(count as u64)).unwrap();
                    if random.below(5) == 0 {
                        PositionalCall {
                            caller,
                            target: None,
                            unresolved: Some(if random.below(2) == 0 {
                                UnresolvedCall::IndirectTable
                            } else {
                                UnresolvedCall::ExternalImport
                            }),
                        }
                    } else {
                        call(caller, usize::try_from(random.below(count as u64)).unwrap())
                    }
                })
                .collect();

            let expected = naive_partition(&symbols, &roots, &calls);
            let colours = refined_colours(&symbols, &roots, &Graph::new(count, &calls));
            let mut by_colour: BTreeMap<Colour, BTreeSet<usize>> = BTreeMap::new();
            for (position, colour) in &colours {
                by_colour.entry(*colour).or_default().insert(*position);
            }
            let actual: BTreeSet<BTreeSet<usize>> = by_colour.into_values().collect();
            assert_eq!(actual, expected, "{symbols:#?} {roots:?} {calls:#?}");
            graphs_with_copies += usize::from(!expected.is_empty());

            assign_identities(&mut symbols, &roots, calls);
            assert_unique(&symbols);
            for class in &expected {
                for position in class {
                    assert_eq!(symbols[*position].identity_by_order, class.len() > 1);
                }
            }
        }
        assert!(graphs_with_copies > 200, "{graphs_with_copies}");
    }

    #[test]
    fn refinement_matches_naive_partition_on_a_long_directed_chain() {
        let count = 40;
        let symbols: Vec<_> = (0..count).map(|_| symbol(9)).collect();
        let roots = BTreeSet::from([0]);
        let calls: Vec<_> = (0..count - 1)
            .map(|position| call(position, position + 1))
            .collect();

        let expected = naive_partition(&symbols, &roots, &calls);
        let colours = refined_colours(&symbols, &roots, &Graph::new(count, &calls));
        let mut by_colour: BTreeMap<Colour, BTreeSet<usize>> = BTreeMap::new();
        for (position, colour) in colours {
            by_colour.entry(colour).or_default().insert(position);
        }
        let actual: BTreeSet<BTreeSet<usize>> = by_colour.into_values().collect();
        let singleton_classes: BTreeSet<_> = (0..count)
            .map(|position| BTreeSet::from([position]))
            .collect();

        assert_eq!(expected, singleton_classes);
        assert_eq!(actual, expected);
    }

    #[test]
    fn long_chain_identities_are_invariant_under_symbol_order() {
        let count = 40;
        let keys = vec![9; count];
        let calls: Vec<_> = (0..count - 1)
            .map(|position| call(position, position + 1))
            .collect();
        let baseline = assigned(&keys, &[0], &calls);

        // Move the root and reorder all middle nodes while preserving the
        // logical chain by remapping both calls and the root position.
        let logical_to_position: Vec<_> = (0..count).rev().collect();
        let remapped_calls: Vec<_> = (0..count - 1)
            .map(|logical| {
                call(
                    logical_to_position[logical],
                    logical_to_position[logical + 1],
                )
            })
            .collect();
        let remapped = assigned(&keys, &[logical_to_position[0]], &remapped_calls);

        for (logical, position) in logical_to_position.iter().copied().enumerate() {
            let original = &baseline.0[logical];
            let reordered = &remapped.0[position];
            assert_eq!(
                original.fingerprint, reordered.fingerprint,
                "logical symbol {logical}"
            );
            assert!(!original.identity_by_order, "logical symbol {logical}");
            assert!(!reordered.identity_by_order, "logical symbol {logical}");
        }
    }
}
