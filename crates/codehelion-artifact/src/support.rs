//! Static, input-independent description of every supported artifact format.
//!
//! A format's abilities are stated in several places: the backend's declared
//! [`ArtifactBackend::capabilities`], the extension table in
//! `FORMAT_SUPPORT.md`, and the guidance a report prints about which artifact
//! to supply for source correspondence. Each of those reads [`format_support`]
//! rather than restating the facts, so they cannot drift apart, and a format
//! added to [`ArtifactFormat`] cannot be left out: [`format_support`] matches
//! every variant and each arm names a row of [`FORMAT_SUPPORT`].
//!
//! [`ArtifactBackend::capabilities`]: crate::ArtifactBackend::capabilities

use crate::{ArtifactCapabilities, ArtifactFormat, ArtifactSourceLocationEvidenceKind};

/// How precisely a format's source evidence can attribute artifact bytes.
///
/// The distinction is what a size report can promise. A symbol name locates a
/// whole function; only a source line locates the line range a clone group is
/// made of, so a format without line frames can never attribute bytes to a
/// clone group however complete its symbol names are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SourceAttribution {
    /// No source correspondence at all.
    None,
    /// Whole symbols, by name; no source line range.
    Symbol,
    /// Source file and line, so a clone group's line range is attributable.
    LineRange,
}

/// What a format can contribute towards source correspondence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceEvidence {
    /// Debug metadata families a parse of this format may attach to a symbol
    /// as [`ArtifactInlineFrame`]s. Empty means no parse of this format ever
    /// establishes a source line.
    ///
    /// [`ArtifactInlineFrame`]: crate::ArtifactInlineFrame
    pub line_frames: &'static [ArtifactSourceLocationEvidenceKind],
    /// What carries this format's source correspondence, named the way a user
    /// supplies it.
    pub carrier: &'static str,
    /// What supplies symbol names when no line frames are available.
    pub symbol_carrier: &'static str,
    /// Why line attribution stays out of reach for this format, when it does.
    pub line_limit: Option<&'static str>,
}

impl SourceEvidence {
    /// Attribution granularity implied by these facts and `capabilities`.
    ///
    /// This is derived rather than declared: line frames raise a format to a
    /// line range, symbols alone stop at whole symbols, and a format with
    /// neither has nothing to correlate.
    #[must_use]
    pub const fn attribution(&self, capabilities: ArtifactCapabilities) -> SourceAttribution {
        if !self.line_frames.is_empty() {
            SourceAttribution::LineRange
        } else if capabilities.symbols {
            SourceAttribution::Symbol
        } else {
            SourceAttribution::None
        }
    }
}

/// Everything one artifact format's backend statically promises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatSupport {
    /// Format this row describes.
    pub format: ArtifactFormat,
    /// Cargo feature, and module name, carrying this backend.
    pub feature: &'static str,
    /// How the format is recognised from its leading bytes.
    pub detection: &'static str,
    /// Upper bound over every parse entry point the backend offers.
    ///
    /// A field is true when some well-formed input makes a parse set it, so a
    /// caller branching on the declaration never skips evidence a parse would
    /// have produced. [`ArtifactCapabilities::debug_info_unreadable`] observes
    /// one parse rather than an ability, so it stays false here.
    pub capabilities: ArtifactCapabilities,
    /// Source correspondence this format can establish.
    pub source_evidence: SourceEvidence,
    /// Conditions and limits that qualify the row above.
    pub limitations: &'static [&'static str],
}

impl FormatSupport {
    /// Attribution granularity this format can actually deliver.
    #[must_use]
    pub const fn attribution(&self) -> SourceAttribution {
        self.source_evidence.attribution(self.capabilities)
    }

    /// Comma-separated capability list for the format extension table.
    ///
    /// The list is rendered from the declared capabilities, so the table can
    /// neither claim an ability the backend does not declare nor omit one it
    /// does.
    #[must_use]
    pub fn capability_summary(&self) -> String {
        let capabilities = self.capabilities;
        let mut listed: Vec<String> = [
            (capabilities.symbols, "symbols"),
            (capabilities.call_graph, "direct calls"),
            (capabilities.relocations, "relocations"),
            (capabilities.data_segments, "data segments"),
            (capabilities.normalized_duplicates, "normalized duplicates"),
            (
                capabilities.independent_data_segments,
                "independent data segments",
            ),
        ]
        .into_iter()
        .filter(|(declared, _)| *declared)
        .map(|(_, phrase)| phrase.to_owned())
        .collect();
        if capabilities.source_mapping {
            let carrier = self.source_evidence.carrier;
            // A source clause names its carrier, because unlike the other
            // capabilities it is never established by the artifact alone.
            return format!("{}; source mappings from {carrier}", listed.join(", "));
        }
        if listed.is_empty() {
            listed.push("none".to_owned());
        }
        listed.join(", ")
    }

    /// Support status for the format extension table.
    #[must_use]
    pub fn status_summary(&self) -> String {
        if self.limitations.is_empty() {
            return "implemented".to_owned();
        }
        format!("implemented; {}", self.limitations.join("; "))
    }

    /// One row of the format extension table.
    #[must_use]
    pub fn extension_table_row(&self) -> String {
        format!(
            "| {} | `{}` | {} | {} | {} |",
            self.format.name(),
            self.feature,
            self.detection,
            self.capability_summary(),
            self.status_summary(),
        )
    }
}

/// The whole format extension table, header included.
///
/// `FORMAT_SUPPORT.md` carries this table verbatim, and a test compares the
/// two, so the document states what the definitions above say and nothing
/// else.
#[must_use]
pub fn extension_table() -> String {
    let mut table = String::from(
        "| Format | Module and feature | Detection | Potential capabilities | Status |\n| --- | --- | --- | --- | --- |",
    );
    for row in &FORMAT_SUPPORT {
        table.push('\n');
        table.push_str(&row.extension_table_row());
    }
    table
}

/// Every recognised format, in the order the extension table lists them.
pub const FORMAT_SUPPORT: [FormatSupport; 5] = [
    FormatSupport {
        format: ArtifactFormat::Wasm,
        feature: "wasm",
        detection: "`\\0asm`",
        capabilities: ArtifactCapabilities {
            symbols: true,
            call_graph: true,
            source_mapping: true,
            debug_info_unreadable: false,
            normalized_duplicates: true,
            independent_data_segments: true,
            relocations: false,
            data_segments: true,
        },
        source_evidence: SourceEvidence {
            // A core module carries no debug metadata this backend reads, so
            // no parse of it establishes a source line.
            line_frames: &[],
            carrier: "a recorded sourceMappingURL",
            symbol_carrier: "the name section",
            line_limit: Some(
                "source line ranges need DWARF, and emitting it changes the size being measured",
            ),
        },
        limitations: &["the component encoding is recognised but not parsed"],
    },
    FormatSupport {
        format: ArtifactFormat::Elf,
        feature: "elf",
        detection: "`\\x7fELF`",
        capabilities: ArtifactCapabilities {
            symbols: true,
            call_graph: true,
            source_mapping: true,
            debug_info_unreadable: false,
            normalized_duplicates: true,
            independent_data_segments: false,
            relocations: true,
            data_segments: true,
        },
        source_evidence: SourceEvidence {
            line_frames: &[ArtifactSourceLocationEvidenceKind::Dwarf],
            carrier: "embedded DWARF or a build-ID-matched debug companion",
            symbol_carrier: "the symbol table",
            line_limit: None,
        },
        limitations: &["normalized duplicates need an x86 instruction architecture"],
    },
    FormatSupport {
        format: ArtifactFormat::MachO,
        feature: "macho",
        detection: "Mach-O magic values",
        capabilities: ArtifactCapabilities {
            symbols: true,
            call_graph: false,
            source_mapping: true,
            debug_info_unreadable: false,
            normalized_duplicates: true,
            independent_data_segments: false,
            relocations: true,
            data_segments: true,
        },
        source_evidence: SourceEvidence {
            line_frames: &[ArtifactSourceLocationEvidenceKind::Dwarf],
            carrier: "a matching dSYM DWARF image",
            symbol_carrier: "the symbol table",
            line_limit: None,
        },
        limitations: &[
            "the call graph is unavailable",
            "normalized duplicates need an x86 instruction architecture",
        ],
    },
    FormatSupport {
        format: ArtifactFormat::PeCoff,
        feature: "pe",
        detection: "DOS `MZ` header or recognised COFF machine",
        capabilities: ArtifactCapabilities {
            symbols: true,
            call_graph: false,
            source_mapping: true,
            debug_info_unreadable: false,
            normalized_duplicates: true,
            independent_data_segments: false,
            relocations: true,
            data_segments: true,
        },
        source_evidence: SourceEvidence {
            line_frames: &[ArtifactSourceLocationEvidenceKind::Pdb],
            carrier: "a matching PDB",
            symbol_carrier: "the symbol table",
            line_limit: None,
        },
        limitations: &[
            "the call graph is unavailable",
            "normalized duplicates need an x86 instruction architecture",
        ],
    },
    FormatSupport {
        format: ArtifactFormat::Archive,
        feature: "archive",
        detection: "`!<arch>\\n` or `!<thin>\\n`",
        capabilities: ArtifactCapabilities {
            symbols: true,
            call_graph: true,
            source_mapping: true,
            debug_info_unreadable: false,
            // An archive's normalizer is its members' instruction architecture,
            // never a property of the archive container itself.
            normalized_duplicates: true,
            independent_data_segments: false,
            relocations: true,
            data_segments: true,
        },
        source_evidence: SourceEvidence {
            line_frames: &[
                ArtifactSourceLocationEvidenceKind::Dwarf,
                ArtifactSourceLocationEvidenceKind::Pdb,
            ],
            carrier: "the debug metadata each delegated member carries",
            symbol_carrier: "each member's symbol table",
            line_limit: None,
        },
        limitations: &[
            "members are enumerated and delegated, so the capabilities are the delegated members'",
            "thin members are not followed outside the archive",
        ],
    },
];

/// Static description of `format`.
///
/// The match below has one arm per [`ArtifactFormat`] and each arm names a row
/// of [`FORMAT_SUPPORT`], so a format cannot be added without a row.
#[must_use]
pub const fn format_support(format: ArtifactFormat) -> &'static FormatSupport {
    let index = match format {
        ArtifactFormat::Wasm => 0,
        ArtifactFormat::Elf => 1,
        ArtifactFormat::MachO => 2,
        ArtifactFormat::PeCoff => 3,
        ArtifactFormat::Archive => 4,
    };
    &FORMAT_SUPPORT[index]
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// An index collision between two arms would let one format answer with
    /// another's row, which no compiler check would catch.
    #[test]
    fn every_row_answers_for_the_format_it_names() {
        for row in &FORMAT_SUPPORT {
            assert_eq!(format_support(row.format), row, "{:?}", row.format);
        }
    }

    #[test]
    fn attribution_follows_the_evidence_a_format_can_establish() {
        assert_eq!(
            format_support(ArtifactFormat::Wasm).attribution(),
            SourceAttribution::Symbol
        );
        for format in [
            ArtifactFormat::Elf,
            ArtifactFormat::MachO,
            ArtifactFormat::PeCoff,
            ArtifactFormat::Archive,
        ] {
            assert_eq!(
                format_support(format).attribution(),
                SourceAttribution::LineRange,
                "{format}"
            );
        }
        let nothing = SourceEvidence {
            line_frames: &[],
            carrier: "nothing",
            symbol_carrier: "nothing",
            line_limit: None,
        };
        assert_eq!(
            nothing.attribution(ArtifactCapabilities::default()),
            SourceAttribution::None
        );
    }

    /// A core module names functions and carries no line information, and the
    /// definition has to say both, because the report guidance built on it is
    /// what a size-motivated reader acts on.
    #[test]
    fn a_wasm_module_offers_names_without_lines_and_says_so() {
        let wasm = format_support(ArtifactFormat::Wasm);

        assert!(wasm.source_evidence.line_frames.is_empty());
        assert_eq!(wasm.source_evidence.symbol_carrier, "the name section");
        let limit = wasm
            .source_evidence
            .line_limit
            .expect("the limit is named rather than left to the reader");
        assert!(limit.contains("DWARF"), "{limit}");
        assert!(limit.contains("changes the size being measured"), "{limit}");
        // A format that reaches a line range does so through a debug metadata
        // family, which is the fact the guidance turns into an instruction.
        assert!(
            format_support(ArtifactFormat::Elf)
                .source_evidence
                .line_frames
                .contains(&ArtifactSourceLocationEvidenceKind::Dwarf)
        );
        assert!(
            format_support(ArtifactFormat::PeCoff)
                .source_evidence
                .line_frames
                .contains(&ArtifactSourceLocationEvidenceKind::Pdb)
        );
    }

    /// A format that cannot reach a source line has to say why, because the
    /// report guidance built on this row is otherwise silent about it.
    #[test]
    fn a_format_without_line_frames_names_its_limit() {
        for row in &FORMAT_SUPPORT {
            if row.attribution() == SourceAttribution::Symbol {
                assert!(
                    row.source_evidence.line_limit.is_some(),
                    "{} reaches only symbols without saying why",
                    row.format
                );
            }
        }
    }

    #[test]
    fn the_capability_summary_lists_exactly_what_is_declared() {
        let wasm = format_support(ArtifactFormat::Wasm).capability_summary();
        assert_eq!(
            wasm,
            "symbols, direct calls, data segments, normalized duplicates, independent data segments; source mappings from a recorded sourceMappingURL"
        );
        assert!(!wasm.contains("relocations"), "{wasm}");
        assert_eq!(
            format_support(ArtifactFormat::MachO).status_summary(),
            "implemented; the call graph is unavailable; normalized duplicates need an x86 instruction architecture"
        );
    }
}
