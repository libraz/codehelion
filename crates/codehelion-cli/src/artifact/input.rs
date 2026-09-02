//! Artifact input reading, format selection, and WASM source-map resolution.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::Path as FilePath;

use anyhow::{Context, Result, bail};
use codehelion_artifact::archive::ArchiveBackend;
use codehelion_artifact::dwarf::DwarfBudget;
use codehelion_artifact::elf::ElfBackend;
use codehelion_artifact::macho::MachOBackend;
use codehelion_artifact::pe::PeCoffBackend;
use codehelion_artifact::wasm::WasmBackend;
use codehelion_artifact::{
    ArtifactBackend, ArtifactFormat as BinaryFormat, ArtifactIr, detect_format,
};
use codehelion_store::artifact::ArtifactAnalysisSourceMapReason as SourceMapReason;

use super::{
    ArtifactContainment, SourceMapLocation, SourceMapResolution, SourceMapResolutionStatus,
};
use crate::cli::{ArtifactArgs, ArtifactCompareArgs, ArtifactInputFormat};

pub(super) fn untrusted_containment(args: &ArtifactArgs) -> Option<ArtifactContainment> {
    untrusted_ceilings(
        args.untrusted,
        args.max_bytes,
        args.timeout_seconds,
        args.max_memory_bytes,
    )
}

/// The `artifact compare` twin of [`untrusted_containment`]: both artifacts
/// were clamped under the same `--untrusted` preset, so one containment
/// statement covers the whole comparison.
pub(super) fn compare_untrusted_containment(
    args: &ArtifactCompareArgs,
) -> Option<ArtifactContainment> {
    untrusted_ceilings(
        args.untrusted,
        args.max_bytes,
        args.timeout_seconds,
        args.max_memory_bytes,
    )
}

/// Which ceiling each `--untrusted` preset installs, stated once for every
/// command that installs them.
///
/// `None` for a run nobody asked to contain, and for one that named no memory
/// ceiling: the memory limit is part of the preset rather than optional, so a
/// run without one was never under it.
pub(super) fn untrusted_ceilings(
    untrusted: bool,
    max_bytes: u64,
    timeout_seconds: u64,
    max_memory_bytes: Option<u64>,
) -> Option<ArtifactContainment> {
    if !untrusted {
        return None;
    }
    let memory = max_memory_bytes?;
    Some(ArtifactContainment {
        max_input_bytes: max_bytes,
        worker_timeout_seconds: timeout_seconds,
        worker_memory_limit_bytes: memory,
        max_debug_derived_items: max_bytes,
    })
}

pub(super) fn inspect(
    path: &std::path::Path,
    max_bytes: u64,
    required_format: Option<ArtifactInputFormat>,
    debug_file: Option<&std::path::Path>,
    architecture: Option<&str>,
    untrusted: bool,
) -> Result<ArtifactIr> {
    // An operator who capped how many bytes an untrusted artifact may be read
    // from has already capped the structures those bytes expand into: each one
    // takes at least a byte of debug information to describe. Applying that
    // same ceiling here is what carries the instruction through to them,
    // instead of leaving one bound nobody set.
    let budget = if untrusted {
        DwarfBudget::default().bounded_by(max_bytes)
    } else {
        DwarfBudget::default()
    };
    let bytes = read_artifact_input(path, max_bytes, "artifact")?;
    let (debug_companion, automatically_discovered) = match debug_file {
        Some(path) => (
            Some(read_artifact_input(
                path,
                max_bytes,
                "external debug companion",
            )?),
            None,
        ),
        None => match discover_macho_dsym(path, &bytes, max_bytes) {
            Some(companion) => (Some(companion.bytes), Some(companion.path)),
            None => (None, None),
        },
    };
    match parse_input_format_within(
        &bytes,
        required_format,
        debug_companion.as_deref(),
        architecture,
        budget,
    ) {
        Ok(artifact) => Ok(artifact),
        Err(error) if let Some(path) = automatically_discovered => {
            // An automatically discovered bundle is optional evidence. Its
            // malformed bytes or a stale UUID must not make a valid artifact
            // unanalyzable; an explicitly supplied companion remains strict.
            let artifact =
                parse_input_format_within(&bytes, required_format, None, architecture, budget)?;
            eprintln!(
                "warning: automatically discovered dSYM {} was ignored: {error}",
                path.display()
            );
            Ok(artifact)
        }
        Err(error) => Err(error),
    }
}

/// One conventional dSYM companion discovered next to a Mach-O artifact.
pub(super) struct DiscoveredDsym {
    path: std::path::PathBuf,
    bytes: Vec<u8>,
}

/// Read the conventional sibling dSYM image only when it stays within the
/// configured input limit. This performs no directory traversal: a Mach-O
/// artifact named `app` maps to exactly `app.dSYM/Contents/Resources/DWARF/app`.
pub(super) fn discover_macho_dsym(
    path: &FilePath,
    artifact: &[u8],
    max_bytes: u64,
) -> Option<DiscoveredDsym> {
    if detect_format(artifact) != Some(BinaryFormat::MachO) {
        return None;
    }
    let name = path.file_name()?.to_str()?;
    let candidate = path
        .with_file_name(format!("{name}.dSYM"))
        .join("Contents/Resources/DWARF")
        .join(name);
    read_artifact_input(&candidate, max_bytes, "automatically discovered dSYM")
        .ok()
        .map(|bytes| DiscoveredDsym {
            path: candidate,
            bytes,
        })
}

/// Read one regular artifact-side input under the same explicit size ceiling.
///
/// The byte count comes from the read itself, rather than filesystem metadata:
/// special files can report a misleading or zero length. Reading one extra
/// byte bounds memory before reporting an oversized regular file.
pub(super) fn read_artifact_input(
    path: &std::path::Path,
    max_bytes: u64,
    label: &str,
) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("reading {label} metadata {}", path.display()))?;
    if !metadata.is_file() {
        bail!("{label} {} is not a regular file", path.display());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .with_context(|| format!("opening {label} {}", path.display()))?
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {label} {}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        bail!(
            "{label} {} exceeds the configured maximum of {max_bytes} bytes",
            path.display(),
        );
    }
    Ok(bytes)
}

/// Resolve source maps declared by a WASM artifact without ever fetching a URI.
///
/// Only a relative reference that resolves inside the artifact's directory is
/// read. The source map's source contents are deliberately neither loaded nor
/// included in the report.
pub(super) fn resolve_wasm_source_maps(
    artifact_path: &FilePath,
    artifact: &ArtifactIr,
    max_bytes: u64,
) -> Vec<SourceMapResolution> {
    if artifact.format != BinaryFormat::Wasm {
        return Vec::new();
    }
    artifact
        .source_mappings
        .iter()
        .map(|mapping| resolve_wasm_source_map(artifact_path, &mapping.uri, max_bytes))
        .collect()
}

pub(super) fn resolve_wasm_source_map(
    artifact_path: &FilePath,
    uri: &str,
    max_bytes: u64,
) -> SourceMapResolution {
    // The reasons come from the stored vocabulary, so what a report prints,
    // what the database accepts, and what a re-render reads back are one list.
    let unavailable = |reason: SourceMapReason| SourceMapResolution {
        uri: uri.to_owned(),
        status: SourceMapResolutionStatus::Unavailable {
            reason: reason.as_sql(),
        },
    };
    if uri.starts_with("data:")
        || uri.starts_with("//")
        || uri.contains("://")
        || FilePath::new(uri).is_absolute()
    {
        return unavailable(SourceMapReason::NonLocalReference);
    }
    let Some(parent) = artifact_path.parent() else {
        return unavailable(SourceMapReason::ArtifactParentUnavailable);
    };
    // A bare filename's parent is the empty path, not the current directory,
    // even though that is where it resolves. Left as-is, canonicalizing it
    // fails and blames a parent that is not in fact unavailable.
    let parent = if parent.as_os_str().is_empty() {
        FilePath::new(".")
    } else {
        parent
    };
    let Ok(root) = codehelion_core::paths::canonical(parent) else {
        return unavailable(SourceMapReason::ArtifactParentUnavailable);
    };
    let Ok(path) = codehelion_core::paths::canonical(&parent.join(uri)) else {
        return unavailable(SourceMapReason::MapNotFound);
    };
    if !path.starts_with(&root) {
        return unavailable(SourceMapReason::OutsideArtifactDirectory);
    }
    let Ok(metadata) = fs::metadata(&path) else {
        return unavailable(SourceMapReason::MapNotReadable);
    };
    if !metadata.is_file() {
        return unavailable(SourceMapReason::MapNotReadable);
    }
    if metadata.len() > max_bytes {
        return unavailable(SourceMapReason::MapExceedsSizeLimit);
    }
    let Ok(bytes) = read_artifact_input(&path, max_bytes, "source map") else {
        return unavailable(SourceMapReason::MapNotReadable);
    };
    match sourcemap::decode_slice(&bytes) {
        Ok(sourcemap::DecodedMap::Regular(map)) => {
            let sources = map
                .sources()
                .map(ToOwned::to_owned)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let locations = map
                .tokens()
                .filter(|token| token.get_dst_line() == 0)
                .filter_map(|token| {
                    token.get_source().map(|source_url| SourceMapLocation {
                        generated_offset: u64::from(token.get_dst_col()),
                        source_url: source_url.to_owned(),
                        source_line: token.get_src_line().checked_add(1),
                    })
                })
                .collect();
            SourceMapResolution {
                uri: uri.to_owned(),
                status: SourceMapResolutionStatus::Resolved {
                    local_path: path.display().to_string(),
                    sources,
                    locations,
                },
            }
        }
        Ok(_) => unavailable(SourceMapReason::UnsupportedSourceMapKind),
        Err(_) => unavailable(SourceMapReason::InvalidSourceMap),
    }
}

pub(super) fn source_map_locations(source_maps: &[SourceMapResolution]) -> Vec<SourceMapLocation> {
    source_maps
        .iter()
        .flat_map(|resolution| match &resolution.status {
            SourceMapResolutionStatus::Resolved { locations, .. } => locations.iter(),
            SourceMapResolutionStatus::Unavailable { .. } => [].iter(),
        })
        .cloned()
        .collect()
}

/// Read one artifact, bounding what its debug information may expand into.
///
/// `budget` is the ceiling on structures derived from debug bytes. It travels
/// with the parse rather than being a property of the backend, because the
/// same backend reads a tree the operator vouches for and one they do not.
pub(super) fn parse_input_format_within(
    bytes: &[u8],
    required_format: Option<ArtifactInputFormat>,
    debug_companion: Option<&[u8]>,
    architecture: Option<&str>,
    budget: DwarfBudget,
) -> Result<ArtifactIr> {
    let detected = detect_format(bytes).ok_or_else(|| {
        anyhow::anyhow!("could not recognise input as a supported artifact format")
    })?;
    let format = required_format.map_or(detected, input_format);
    if format != detected {
        bail!("detected input format {detected} conflicts with requested input format {format}");
    }
    parse(format, bytes, debug_companion, architecture, budget)
}

/// The same read, under what this build can afford rather than what an
/// operator narrowed.
#[cfg(test)]
pub(super) fn parse_input_format(
    bytes: &[u8],
    required_format: Option<ArtifactInputFormat>,
    debug_companion: Option<&[u8]>,
    architecture: Option<&str>,
) -> Result<ArtifactIr> {
    parse_input_format_within(
        bytes,
        required_format,
        debug_companion,
        architecture,
        DwarfBudget::default(),
    )
}

pub(super) const fn input_format(format: ArtifactInputFormat) -> BinaryFormat {
    match format {
        ArtifactInputFormat::Wasm => BinaryFormat::Wasm,
        ArtifactInputFormat::Elf => BinaryFormat::Elf,
        ArtifactInputFormat::MachO => BinaryFormat::MachO,
        ArtifactInputFormat::Archive => BinaryFormat::Archive,
        ArtifactInputFormat::PeCoff => BinaryFormat::PeCoff,
    }
}

pub(super) fn parse(
    format: BinaryFormat,
    bytes: &[u8],
    debug_companion: Option<&[u8]>,
    architecture: Option<&str>,
    budget: DwarfBudget,
) -> Result<ArtifactIr> {
    if architecture.is_some() && format != BinaryFormat::MachO {
        bail!("--arch is only supported for Mach-O artifacts");
    }
    match format {
        BinaryFormat::Wasm => {
            if debug_companion.is_some() {
                bail!("--debug-file is only supported for ELF, Mach-O, and PE artifacts");
            }
            // A WebAssembly module carries no DWARF, so nothing here expands
            // out of debug bytes and the budget has nothing to bound.
            WasmBackend.parse(bytes).map_err(Into::into)
        }
        BinaryFormat::Elf => ElfBackend
            .parse_within(bytes, debug_companion, budget)
            .map_err(Into::into),
        BinaryFormat::MachO => MachOBackend
            .parse_within(bytes, debug_companion, architecture, budget)
            .map_err(Into::into),
        BinaryFormat::PeCoff => PeCoffBackend
            .parse_with_pdb(bytes, debug_companion)
            .map_err(Into::into),
        BinaryFormat::Archive => {
            if debug_companion.is_some() {
                bail!("--debug-file is not supported for archive artifacts");
            }
            ArchiveBackend
                .parse_within(bytes, budget)
                .map_err(Into::into)
        }
    }
}
