//! Format-neutral artifact parsing boundary and intermediate representation.
//!
//! This crate owns no source-analysis dependency. Format backends turn bytes
//! into [`ArtifactIr`]; common metrics can then operate on that IR without
//! knowing whether it came from WebAssembly, ELF, or a later format.
//!
//! The planned-format boundary and archive delegation policy are recorded in
//! [`FORMAT_SUPPORT.md`](../FORMAT_SUPPORT.md).

use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

pub mod dwarf;
pub mod metrics;
pub mod symbols;
pub mod x86;

/// Version of the artifact IR document.
pub const ARTIFACT_IR_SCHEMA_VERSION: &str = "artifact-ir-v2";

/// Version of the fingerprint recipe for parsed artifact entities.
pub const ARTIFACT_FINGERPRINT_VERSION: &str = "artifact-fingerprint-v1";

/// A binary container format that codehelion recognises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArtifactFormat {
    /// A WebAssembly core module or component.
    Wasm,
    /// An ELF executable, shared library, or relocatable object.
    Elf,
    /// A Mach-O executable, dynamic library, or relocatable object.
    MachO,
    /// A PE image or COFF relocatable object.
    PeCoff,
    /// A static archive.
    Archive,
}

impl ArtifactFormat {
    /// Stable format label used in reports and fingerprint inputs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Wasm => "wasm",
            Self::Elf => "elf",
            Self::MachO => "macho",
            Self::PeCoff => "pe-coff",
            Self::Archive => "archive",
        }
    }
}

impl fmt::Display for ArtifactFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl Serialize for ArtifactFormat {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.name())
    }
}

impl<'de> Deserialize<'de> for ArtifactFormat {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match String::deserialize(deserializer)?.as_str() {
            "wasm" => Ok(Self::Wasm),
            "elf" => Ok(Self::Elf),
            "macho" => Ok(Self::MachO),
            "pe-coff" => Ok(Self::PeCoff),
            "archive" => Ok(Self::Archive),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["wasm", "elf", "macho", "pe-coff", "archive"],
            )),
        }
    }
}

/// Information a format backend could establish without guessing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)] // Independent facts a backend may establish.
pub struct ArtifactCapabilities {
    /// Whether symbol or function boundaries are available.
    pub symbols: bool,
    /// Whether direct call edges are available.
    pub call_graph: bool,
    /// Whether source locations or mappings are available.
    pub source_mapping: bool,
    /// Whether relocations are available.
    pub relocations: bool,
    /// Whether data segments can be independently inspected.
    pub data_segments: bool,
}

/// The stable content fingerprint of an artifact or entity inside one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ArtifactFingerprint([u8; 16]);

impl ArtifactFingerprint {
    /// Hash `bytes` under a domain that keeps artifact identities apart from
    /// source-audit fingerprints.
    #[must_use]
    pub fn from_content(domain: &str, bytes: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ARTIFACT_FINGERPRINT_VERSION.as_bytes());
        hasher.update(&(domain.len() as u64).to_le_bytes());
        hasher.update(domain.as_bytes());
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
        let mut fingerprint = [0_u8; 16];
        fingerprint.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        Self(fingerprint)
    }

    /// Raw fingerprint bytes for persistence.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }

    /// Lowercase hexadecimal representation used in reports.
    #[must_use]
    pub fn to_hex(self) -> String {
        self.to_string()
    }
}

impl fmt::Display for ArtifactFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// One parsed artifact, independent of the container that supplied it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactIr {
    /// Version of this document's shape.
    pub schema_version: String,
    /// Container format that supplied this IR.
    pub format: ArtifactFormat,
    /// Facts that the parser could establish for this individual input.
    pub capabilities: ArtifactCapabilities,
    /// Stable identity of the complete byte input.
    pub fingerprint: ArtifactFingerprint,
    /// Input length measured directly from the byte stream.
    pub observed_bytes: u64,
    /// Parsed sections, when the format exposes them.
    pub sections: Vec<ArtifactSection>,
    /// Object members when this artifact is an archive.
    ///
    /// Ordinary containers leave this empty. Archive members retain their own
    /// content identity and parser outcome even though their parsed facts are
    /// also flattened into this IR for the format-neutral metrics layer.
    pub archive_members: Vec<ArtifactArchiveMember>,
    /// Declared imports, when the format exposes them.
    pub imports: Vec<ArtifactImport>,
    /// Parsed functions or symbols.
    pub symbols: Vec<ArtifactSymbol>,
    /// Parser-established entry points in the local symbol identity space.
    pub entry_points: Vec<ArtifactFingerprint>,
    /// Functions retained by an indirect-dispatch table or equivalent parser
    /// evidence. These are roots for conservative reachability, not IDs.
    pub indirect_references: Vec<ArtifactFingerprint>,
    /// Direct and unresolved call relations.
    pub calls: Vec<ArtifactCall>,
    /// Relocation anchors, when a format preserves them.
    pub relocations: Vec<ArtifactRelocation>,
    /// Source-map references the artifact itself declares.
    pub source_mappings: Vec<ArtifactSourceMapping>,
    /// Independent data regions that can participate in duplicate detection.
    pub data_segments: Vec<ArtifactDataSegment>,
}

impl ArtifactIr {
    /// Start an IR for `bytes`; backends add only facts they actually parsed.
    #[must_use]
    pub fn empty(format: ArtifactFormat, bytes: &[u8]) -> Self {
        Self {
            schema_version: ARTIFACT_IR_SCHEMA_VERSION.to_owned(),
            format,
            capabilities: ArtifactCapabilities::default(),
            fingerprint: ArtifactFingerprint::from_content("artifact", bytes),
            observed_bytes: bytes.len() as u64,
            sections: Vec::new(),
            archive_members: Vec::new(),
            imports: Vec::new(),
            symbols: Vec::new(),
            entry_points: Vec::new(),
            indirect_references: Vec::new(),
            calls: Vec::new(),
            relocations: Vec::new(),
            source_mappings: Vec::new(),
            data_segments: Vec::new(),
        }
    }
}

/// One object member observed inside a static archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactArchiveMember {
    /// Archive-provided member name, preserved only as display evidence.
    pub name: String,
    /// Content-derived identity of this member's bytes.
    pub fingerprint: ArtifactFingerprint,
    /// Byte offset of the member data in the archive, never an identity input.
    pub offset: u64,
    /// Member byte length observed in the archive.
    pub size: u64,
    /// Container format recognised inside this member, when any.
    pub format: Option<ArtifactFormat>,
    /// Whether this member is thin and therefore has no local bytes to parse.
    pub thin: bool,
    /// Parser failure or deliberate non-support for this individual member.
    ///
    /// This retains a partial archive result rather than hiding unsupported or
    /// malformed member bytes behind a successful outer container parse.
    pub parse_error: Option<String>,
}

/// One named or numbered region of an artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactSection {
    /// A format-provided name, when one exists.
    pub name: Option<String>,
    /// Offset in the input byte stream.
    pub offset: u64,
    /// Length in bytes.
    pub size: u64,
    /// Whether executable code resides in this section.
    pub executable: bool,
}

/// A dependency the artifact declares without requiring it to be loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactImport {
    /// Importing module or library namespace, when the format uses one.
    pub module: Option<String>,
    /// Imported item name, when supplied by the format.
    pub name: Option<String>,
    /// Declared kind of the imported item.
    pub kind: ArtifactImportKind,
}

/// Kind of an [`ArtifactImport`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactImportKind {
    /// Callable import.
    Function,
    /// Table import.
    Table,
    /// Linear-memory import.
    Memory,
    /// Global-value import.
    Global,
    /// Exception tag import.
    Tag,
    /// A format-specific kind that this IR version does not classify further.
    Other,
}

/// A function or symbol extracted from an artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactSymbol {
    /// Stable identity built from semantic name, normalized body, and section.
    pub fingerprint: ArtifactFingerprint,
    /// Demangled name when a format supplied one.
    pub name: Option<String>,
    /// Whether the container declares this symbol as externally reachable.
    pub exported: bool,
    /// Section index is display-only; it is never used as an identity.
    pub section: Option<u32>,
    /// Start offset in the artifact.
    pub offset: u64,
    /// Observed or conservatively inferred byte size.
    pub size: u64,
    /// Whether `size` was inferred rather than provided by the format.
    pub size_inferred: bool,
    /// Exact code bytes, when a boundary could be established.
    pub code: Vec<u8>,
    /// Versioned normalized instruction stream, when decoding is supported.
    pub normalized: Option<NormalizedInstructions>,
    /// Inline source locations, when debug information established them.
    pub inline_stack: Vec<ArtifactInlineFrame>,
}

/// One source frame associated with an inlined artifact symbol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactInlineFrame {
    /// Debug metadata family that established this location.
    pub evidence_kind: ArtifactSourceLocationEvidenceKind,
    /// Source file or source-map URL supplied by debug metadata.
    pub source: String,
    /// One-based source line, when supplied.
    pub line: Option<u32>,
    /// One-based source column, when supplied.
    pub column: Option<u32>,
}

/// Debug metadata family that established one artifact source location.
///
/// This is evidence provenance, not an artifact or source identity. The
/// correlation layer preserves it so a PDB-derived location is never reported
/// as DWARF evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactSourceLocationEvidenceKind {
    /// DWARF debug metadata established the source location.
    Dwarf,
    /// PDB debug metadata established the source location.
    Pdb,
}

/// A versioned representation used for normalized duplicate detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedInstructions {
    /// Version of the format-specific normalization recipe.
    pub version: String,
    /// Normalized instruction bytes or tokens.
    pub bytes: Vec<u8>,
}

/// One relation from a caller to a direct target or an unresolved dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactCall {
    /// Caller symbol fingerprint.
    pub caller: ArtifactFingerprint,
    /// A direct target, when the format makes one provable.
    pub target: Option<ArtifactFingerprint>,
    /// Why no exact target is asserted.
    pub unresolved: Option<UnresolvedCall>,
}

/// A relocation anchor retained as parsed evidence rather than a stable ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRelocation {
    /// Section index used only to locate this parser observation.
    pub section: Option<u32>,
    /// Offset in the artifact byte stream.
    pub offset: u64,
    /// Parser-provided relocation kind label.
    pub kind: String,
    /// Display target, when the format makes one available.
    pub target: Option<String>,
}

/// A source-map reference declared by an artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactSourceMapping {
    /// URL or path declared by the artifact, without fetching it.
    pub uri: String,
}

/// A conservative reason a call edge has no direct target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnresolvedCall {
    /// A WebAssembly indirect call whose possible targets require table flow.
    IndirectTable,
    /// A direct call whose target is imported rather than defined in this
    /// artifact, so there is no local symbol fingerprint to reference.
    ExternalImport,
    /// A native indirect call through a register or memory location.
    NativeIndirect,
    /// A relocation or symbol target was unavailable.
    MissingRelocation,
}

/// A data region eligible for exact duplicate analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactDataSegment {
    /// Stable identity of the segment's bytes.
    pub fingerprint: ArtifactFingerprint,
    /// Source section, when known.
    pub section: Option<u32>,
    /// Offset in the artifact.
    pub offset: u64,
    /// Bytes as observed; later storage may deduplicate the payload.
    pub bytes: Vec<u8>,
}

/// A parser failure that preserves the source artifact and never executes it.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ArtifactError {
    /// The bytes do not belong to this backend's format.
    #[error("expected {expected} input")]
    WrongFormat {
        /// Format the backend handles.
        expected: ArtifactFormat,
    },
    /// The bytes were recognised but could not be safely parsed.
    #[error("malformed {format} input: {message}")]
    Malformed {
        /// Recognised binary format.
        format: ArtifactFormat,
        /// Parser-provided error explanation.
        message: String,
    },
    /// The backend is a recognised future format with no parser yet.
    #[error("{format} is recognised but not supported")]
    Unsupported {
        /// Recognised format without a backend.
        format: ArtifactFormat,
    },
}

/// Format-specific parser isolated behind a common Artifact IR boundary.
pub trait ArtifactBackend: Send + Sync {
    /// Format this backend accepts.
    fn format(&self) -> ArtifactFormat;

    /// Whether `bytes` begin with this format's magic number.
    fn detects(&self, bytes: &[u8]) -> bool;

    /// Parse bytes without executing the artifact.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactError::WrongFormat`] for input with another magic and
    /// [`ArtifactError::Malformed`] for a recognised but invalid input.
    fn parse(&self, bytes: &[u8]) -> Result<ArtifactIr, ArtifactError>;

    /// Facts this backend can potentially provide for a well-formed input.
    fn capabilities(&self) -> ArtifactCapabilities;
}

/// Recognise supported and planned artifact formats from their magic bytes.
#[must_use]
pub fn detect_format(bytes: &[u8]) -> Option<ArtifactFormat> {
    if bytes.starts_with(b"\0asm") {
        Some(ArtifactFormat::Wasm)
    } else if bytes.starts_with(b"\x7fELF") {
        Some(ArtifactFormat::Elf)
    } else if bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || bytes.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
        || bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbf])
    {
        Some(ArtifactFormat::MachO)
    } else if bytes.starts_with(b"!<arch>\n") || bytes.starts_with(b"!<thin>\n") {
        Some(ArtifactFormat::Archive)
    } else if is_pe_coff(bytes) {
        Some(ArtifactFormat::PeCoff)
    } else {
        None
    }
}

/// Whether the input starts as a supported PE image or COFF object.
///
/// `MZ` alone also names historical DOS executables, so treating it as PE/COFF
/// would promise a backend for bytes the parser cannot read. COFF has no DOS
/// header; its file-header machine value is the only inexpensive dispatch fact.
fn is_pe_coff(bytes: &[u8]) -> bool {
    if matches!(
        bytes.get(..2),
        Some([0x4c, 0x01] | [0x64, 0x86 | 0xaa] | [0xaa, 0x64])
    ) {
        return true;
    }
    let Some(offset_bytes) = bytes.get(0x3c..0x40) else {
        return false;
    };
    let offset = u32::from_le_bytes(offset_bytes.try_into().unwrap_or([0; 4]));
    usize::try_from(offset)
        .ok()
        .and_then(|offset| bytes.get(offset..offset.saturating_add(4)))
        == Some(b"PE\0\0".as_slice())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn magic_detection_distinguishes_supported_planned_and_unknown_inputs() {
        let mut pe = [0_u8; 68];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&64_u32.to_le_bytes());
        pe[64..68].copy_from_slice(b"PE\0\0");
        assert_eq!(
            detect_format(b"\0asm\x01\0\0\0"),
            Some(ArtifactFormat::Wasm)
        );
        assert_eq!(detect_format(b"\x7fELF\x02"), Some(ArtifactFormat::Elf));
        assert_eq!(
            detect_format(b"\xcf\xfa\xed\xfe"),
            Some(ArtifactFormat::MachO)
        );
        assert_eq!(
            detect_format(b"\xca\xfe\xba\xbe"),
            Some(ArtifactFormat::MachO)
        );
        assert_eq!(detect_format(&pe), Some(ArtifactFormat::PeCoff));
        assert_eq!(detect_format(&[0x64, 0x86]), Some(ArtifactFormat::PeCoff));
        assert_eq!(detect_format(b"MZ\x90\0"), None);
        assert_eq!(detect_format(b"!<arch>\n"), Some(ArtifactFormat::Archive));
        assert_eq!(detect_format(b"!<thin>\n"), Some(ArtifactFormat::Archive));
        assert_eq!(detect_format(b"not an artifact"), None);
    }

    #[test]
    fn artifact_identity_is_content_based_and_format_ir_starts_empty() {
        let wasm = ArtifactIr::empty(ArtifactFormat::Wasm, b"\0asm\x01\0\0\0");
        let same = ArtifactIr::empty(ArtifactFormat::Wasm, b"\0asm\x01\0\0\0");
        let changed = ArtifactIr::empty(ArtifactFormat::Wasm, b"\0asm\x01\0\0\x01");
        assert_eq!(wasm.schema_version, ARTIFACT_IR_SCHEMA_VERSION);
        assert_eq!(wasm.observed_bytes, 8);
        assert_eq!(wasm.fingerprint, same.fingerprint);
        assert_ne!(wasm.fingerprint, changed.fingerprint);
        assert!(wasm.symbols.is_empty());
    }

    #[test]
    fn serde_uses_the_same_format_labels_as_every_other_surface() {
        for format in [
            ArtifactFormat::Wasm,
            ArtifactFormat::Elf,
            ArtifactFormat::MachO,
            ArtifactFormat::PeCoff,
            ArtifactFormat::Archive,
        ] {
            let encoded = serde_json::to_string(&format).expect("format serializes");
            assert_eq!(encoded, format!("\"{}\"", format.name()));
            let decoded: ArtifactFormat = serde_json::from_str(&encoded).expect("format reads");
            assert_eq!(decoded, format);
        }
        assert!(serde_json::from_str::<ArtifactFormat>("\"mach-o\"").is_err());
    }
}
