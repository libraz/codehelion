//! Owner labels of artifact symbols and the toolchain code each function holds.
//!
//! Labels are derived at render time from the symbol names and the
//! `[artifact] own` declaration; neither the IR nor the database stores them.
//! Every table here is built from the reported symbol list, so its totals add
//! up to the symbols' sizes and the remainder of the code section is stated as
//! lying outside every symbol.

use codehelion_artifact::ArtifactFingerprint;
use codehelion_artifact::ownership::{
    OwnDeclaration, Ownership, SymbolOwner, ToolchainFamily, owner_of, strips_platform_underscore,
};

use super::code_section_bytes;
use crate::artifact::{ArtifactIr, BTreeMap, Serialize, metrics};

/// Stated for every ownership table.
pub(in crate::artifact) const DEFINING_PATH: &str = "ownership follows the defining path of each symbol name, so generic code instantiated for your types is counted under the library that defines it";

/// Stated while no key is declared own.
pub(in crate::artifact) const NO_OWN_DECLARED: &str = "no own owners are declared in [artifact] own, so named code outside the toolchain is reported as other";

/// Stated when a table counts symbols without a name.
const UNNAMED_UNOWNED: &str = "functions without a name cannot be assigned an owner";

/// The fixed order of the class rows.
const CLASSES: [Ownership; 4] = [
    Ownership::Own,
    Ownership::Toolchain,
    Ownership::Other,
    Ownership::Unnamed,
];

/// Code bytes of one artifact split by owner.
#[derive(Debug, Serialize)]
pub(in crate::artifact) struct OwnershipReport {
    pub(in crate::artifact) declared_own: Vec<String>,
    pub(in crate::artifact) classes: Vec<OwnershipClassTotal>,
    pub(in crate::artifact) owners: Vec<OwnerTotal>,
    /// Executable section bytes minus the sum of symbol sizes.
    pub(in crate::artifact) outside_symbols_bytes: i128,
    pub(in crate::artifact) assumptions: Vec<String>,
}

/// Symbol bytes of one ownership class.
#[derive(Debug, Serialize)]
pub(in crate::artifact) struct OwnershipClassTotal {
    pub(in crate::artifact) ownership: Ownership,
    pub(in crate::artifact) size_bytes: u64,
    pub(in crate::artifact) symbols: usize,
}

/// Symbol bytes of one owner key.
#[derive(Debug, Clone, Serialize)]
pub(in crate::artifact) struct OwnerTotal {
    pub(in crate::artifact) key: String,
    pub(in crate::artifact) ownership: Ownership,
    pub(in crate::artifact) family: Option<ToolchainFamily>,
    pub(in crate::artifact) size_bytes: u64,
    pub(in crate::artifact) symbols: usize,
}

/// Toolchain code attributed to the nearest non-toolchain dominator.
#[derive(Debug, Serialize)]
pub(in crate::artifact) struct ToolchainHoldingsReport {
    pub(in crate::artifact) holdings: Vec<HoldingReport>,
    pub(in crate::artifact) shared: Vec<SharedHeadReport>,
    pub(in crate::artifact) shared_bytes: u64,
    pub(in crate::artifact) shared_symbols: usize,
    pub(in crate::artifact) shared_absorbed_bytes: u64,
    pub(in crate::artifact) shared_absorbed_symbols: usize,
    pub(in crate::artifact) assumptions: Vec<String>,
}

/// The toolchain code one function holds; a part of its retained size.
#[derive(Debug, Serialize)]
pub(in crate::artifact) struct HoldingReport {
    pub(in crate::artifact) holder: String,
    pub(in crate::artifact) holder_name: Option<String>,
    pub(in crate::artifact) holder_ownership: Ownership,
    pub(in crate::artifact) held_bytes: u64,
    pub(in crate::artifact) held_symbols: usize,
    pub(in crate::artifact) absorbed_bytes: u64,
    pub(in crate::artifact) absorbed_symbols: usize,
    pub(in crate::artifact) heads: Vec<HeadReport>,
}

/// One toolchain entry directly below a holder.
#[derive(Debug, Serialize)]
pub(in crate::artifact) struct HeadReport {
    pub(in crate::artifact) symbol: String,
    pub(in crate::artifact) name: Option<String>,
    pub(in crate::artifact) held_bytes: u64,
}

/// One toolchain entry no single non-toolchain function dominates.
#[derive(Debug, Serialize)]
pub(in crate::artifact) struct SharedHeadReport {
    pub(in crate::artifact) symbol: String,
    pub(in crate::artifact) name: Option<String>,
    pub(in crate::artifact) held_bytes: u64,
    pub(in crate::artifact) root: bool,
    pub(in crate::artifact) callers: Vec<CallerReport>,
}

/// One function calling a shared toolchain entry directly.
#[derive(Debug, Serialize)]
pub(in crate::artifact) struct CallerReport {
    pub(in crate::artifact) symbol: String,
    pub(in crate::artifact) name: Option<String>,
    pub(in crate::artifact) ownership: Ownership,
}

/// Change in code bytes between two artifacts split by owner.
#[derive(Debug, Serialize)]
pub(in crate::artifact) struct OwnershipDeltaReport {
    pub(in crate::artifact) classes: Vec<OwnershipClassDelta>,
    pub(in crate::artifact) owners: Vec<OwnerDelta>,
    /// Executable section delta minus the sum of symbol deltas.
    pub(in crate::artifact) outside_symbols_delta_bytes: i128,
}

/// Change in symbol bytes of one ownership class.
#[derive(Debug, Serialize)]
pub(in crate::artifact) struct OwnershipClassDelta {
    pub(in crate::artifact) ownership: Ownership,
    pub(in crate::artifact) delta_bytes: i128,
}

/// Change in symbol bytes of one owner key.
#[derive(Debug, Serialize)]
pub(in crate::artifact) struct OwnerDelta {
    pub(in crate::artifact) key: String,
    pub(in crate::artifact) ownership: Ownership,
    pub(in crate::artifact) delta_bytes: i128,
}

/// The JSON spelling of an ownership class.
pub(in crate::artifact) const fn ownership_label(ownership: Ownership) -> &'static str {
    match ownership {
        Ownership::Own => "own",
        Ownership::Toolchain => "toolchain",
        Ownership::Other => "other",
        Ownership::Unnamed => "unnamed",
    }
}

/// The JSON spelling of a toolchain family.
pub(in crate::artifact) const fn family_label(family: ToolchainFamily) -> &'static str {
    match family {
        ToolchainFamily::LanguageStd => "language_std",
        ToolchainFamily::CStd => "c_std",
        ToolchainFamily::Reserved => "reserved",
        ToolchainFamily::Runtime => "runtime",
    }
}

/// The class `ownership` moves to under `declared`: only other code moves.
pub(in crate::artifact) fn declared_ownership(
    ownership: Ownership,
    key: &str,
    declared: &OwnDeclaration,
) -> Ownership {
    if ownership == Ownership::Other && declared.contains(key) {
        Ownership::Own
    } else {
        ownership
    }
}

impl OwnershipReport {
    /// The table of `symbols`, each given as its owner and size, against the
    /// executable section bytes they lie in.
    pub(in crate::artifact) fn new<'a>(
        symbols: impl IntoIterator<Item = (&'a SymbolOwner, u64)>,
        code_section_bytes: u64,
    ) -> Self {
        let (classes, owners) = tally(symbols.into_iter().map(|(owner, size)| OwnerTotal {
            key: owner.key.clone(),
            ownership: owner.ownership,
            family: owner.family,
            size_bytes: size,
            symbols: 1,
        }));
        let symbol_bytes: i128 = classes
            .iter()
            .map(|class| i128::from(class.size_bytes))
            .sum();
        let mut assumptions = vec![DEFINING_PATH.to_owned(), NO_OWN_DECLARED.to_owned()];
        if classes
            .iter()
            .any(|class| class.ownership == Ownership::Unnamed && class.symbols > 0)
        {
            assumptions.push(UNNAMED_UNOWNED.to_owned());
        }
        Self {
            declared_own: Vec::new(),
            classes,
            owners,
            outside_symbols_bytes: i128::from(code_section_bytes) - symbol_bytes,
            assumptions,
        }
    }

    /// Move every other owner `declared` lists into own.
    pub(in crate::artifact) fn declare(&mut self, keys: &[String], declared: &OwnDeclaration) {
        let owners = std::mem::take(&mut self.owners)
            .into_iter()
            .map(|owner| OwnerTotal {
                ownership: declared_ownership(owner.ownership, &owner.key, declared),
                ..owner
            });
        (self.classes, self.owners) = tally(owners);
        let mut keys = keys.to_vec();
        keys.sort();
        keys.dedup();
        self.declared_own = keys;
        self.assumptions.retain(|text| text != NO_OWN_DECLARED);
    }
}

/// Class rows and owner rows of a set of owner contributions, merging
/// contributions of one key, class and family.
fn tally(
    contributions: impl IntoIterator<Item = OwnerTotal>,
) -> (Vec<OwnershipClassTotal>, Vec<OwnerTotal>) {
    let mut merged: BTreeMap<(String, Ownership, Option<ToolchainFamily>), OwnerTotal> =
        BTreeMap::new();
    for owner in contributions {
        merged
            .entry((owner.key.clone(), owner.ownership, owner.family))
            .and_modify(|total| {
                total.size_bytes += owner.size_bytes;
                total.symbols += owner.symbols;
            })
            .or_insert(owner);
    }
    let mut owners: Vec<OwnerTotal> = merged.into_values().collect();
    owners.sort_by(|left, right| {
        right
            .size_bytes
            .cmp(&left.size_bytes)
            .then_with(|| left.key.cmp(&right.key))
            .then_with(|| left.ownership.cmp(&right.ownership))
    });
    let classes = CLASSES
        .into_iter()
        .map(|ownership| {
            let members = owners.iter().filter(|owner| owner.ownership == ownership);
            OwnershipClassTotal {
                ownership,
                size_bytes: members.clone().map(|owner| owner.size_bytes).sum(),
                symbols: members.map(|owner| owner.symbols).sum(),
            }
        })
        .collect();
    (classes, owners)
}

/// The name and class of each symbol, keyed by fingerprint.
type SymbolLabels<'a> = BTreeMap<ArtifactFingerprint, (Option<&'a str>, Ownership)>;

/// Owner labels of every symbol of `artifact`, in order, judged without a
/// declaration.
pub(in crate::artifact) fn symbol_owners(artifact: &ArtifactIr) -> Vec<SymbolOwner> {
    let strip = strips_platform_underscore(artifact);
    artifact
        .symbols
        .iter()
        .map(|symbol| owner_of(symbol.name.as_deref(), strip, &OwnDeclaration::default()))
        .collect()
}

/// The ownership table and the toolchain holders of `artifact`, whose
/// symbols `owners` labels in order.
pub(in crate::artifact) fn ownership_of(
    artifact: &ArtifactIr,
    graph: &metrics::CallGraph<'_>,
    owners: &[SymbolOwner],
) -> (OwnershipReport, Option<ToolchainHoldingsReport>) {
    let table = OwnershipReport::new(
        owners
            .iter()
            .zip(&artifact.symbols)
            .map(|(owner, symbol)| (owner, symbol.size)),
        code_section_bytes(artifact),
    );
    let labels: SymbolLabels<'_> = artifact
        .symbols
        .iter()
        .zip(owners)
        .map(|(symbol, owner)| {
            (
                symbol.fingerprint,
                (symbol.name.as_deref(), owner.ownership),
            )
        })
        .collect();
    let holdings = graph
        .toolchain_holdings()
        .map(|holdings| ToolchainHoldingsReport::new(holdings, &labels));
    (table, holdings)
}

impl ToolchainHoldingsReport {
    /// The report of `holdings`, naming each symbol from `labels`.
    pub(in crate::artifact) fn new(
        holdings: metrics::ToolchainHoldings,
        labels: &SymbolLabels<'_>,
    ) -> Self {
        let name = |symbol: &ArtifactFingerprint| {
            labels
                .get(symbol)
                .and_then(|(name, _)| name.map(ToOwned::to_owned))
        };
        let ownership = |symbol: &ArtifactFingerprint| {
            labels
                .get(symbol)
                .map_or(Ownership::Unnamed, |(_, ownership)| *ownership)
        };
        Self {
            holdings: holdings
                .holdings
                .iter()
                .map(|holding| HoldingReport {
                    holder: holding.holder.to_hex(),
                    holder_name: name(&holding.holder),
                    holder_ownership: ownership(&holding.holder),
                    held_bytes: holding.held_bytes,
                    held_symbols: holding.held_symbols,
                    absorbed_bytes: holding.absorbed_bytes,
                    absorbed_symbols: holding.absorbed_symbols,
                    heads: holding
                        .heads
                        .iter()
                        .map(|head| HeadReport {
                            symbol: head.symbol.to_hex(),
                            name: name(&head.symbol),
                            held_bytes: head.held_bytes,
                        })
                        .collect(),
                })
                .collect(),
            shared: holdings
                .shared
                .iter()
                .map(|shared| SharedHeadReport {
                    symbol: shared.head.to_hex(),
                    name: name(&shared.head),
                    held_bytes: shared.held_bytes,
                    root: shared.root,
                    callers: shared
                        .callers
                        .iter()
                        .map(|caller| CallerReport {
                            symbol: caller.to_hex(),
                            name: name(caller),
                            ownership: ownership(caller),
                        })
                        .collect(),
                })
                .collect(),
            shared_bytes: holdings.shared_bytes,
            shared_symbols: holdings.shared_symbols,
            shared_absorbed_bytes: holdings.shared_absorbed_bytes,
            shared_absorbed_symbols: holdings.shared_absorbed_symbols,
            assumptions: holdings.assumptions,
        }
    }

    /// Move each other holder and caller `relabelled` lists as own into own.
    pub(in crate::artifact) fn declare(&mut self, relabelled: &BTreeMap<&str, Ownership>) {
        let relabel = |symbol: &str, ownership: &mut Ownership| {
            if *ownership == Ownership::Other
                && let Some(declared) = relabelled.get(symbol)
            {
                *ownership = *declared;
            }
        };
        for holding in &mut self.holdings {
            relabel(&holding.holder, &mut holding.holder_ownership);
        }
        for caller in self
            .shared
            .iter_mut()
            .flat_map(|shared| shared.callers.iter_mut())
        {
            relabel(&caller.symbol, &mut caller.ownership);
        }
    }
}

impl OwnershipDeltaReport {
    /// The split of `deltas`, each given as owner key, class and signed size
    /// change, against the executable section delta.
    pub(in crate::artifact) fn new<'a>(
        deltas: impl IntoIterator<Item = (&'a str, Ownership, i128)>,
        code_section_delta_bytes: i128,
    ) -> Self {
        let mut merged: BTreeMap<(&str, Ownership), i128> = BTreeMap::new();
        for (key, ownership, delta) in deltas {
            *merged.entry((key, ownership)).or_default() += delta;
        }
        let classes = CLASSES
            .into_iter()
            .map(|ownership| OwnershipClassDelta {
                ownership,
                delta_bytes: merged
                    .iter()
                    .filter(|((_, class), _)| *class == ownership)
                    .map(|(_, delta)| delta)
                    .sum(),
            })
            .collect::<Vec<_>>();
        let symbol_delta: i128 = classes.iter().map(|class| class.delta_bytes).sum();
        let mut owners: Vec<OwnerDelta> = merged
            .into_iter()
            .filter(|(_, delta)| *delta != 0)
            .map(|((key, ownership), delta_bytes)| OwnerDelta {
                key: key.to_owned(),
                ownership,
                delta_bytes,
            })
            .collect();
        owners.sort_by(|left, right| {
            right
                .delta_bytes
                .unsigned_abs()
                .cmp(&left.delta_bytes.unsigned_abs())
                .then_with(|| left.key.cmp(&right.key))
                .then_with(|| left.ownership.cmp(&right.ownership))
        });
        Self {
            classes,
            owners,
            outside_symbols_delta_bytes: code_section_delta_bytes - symbol_delta,
        }
    }
}
