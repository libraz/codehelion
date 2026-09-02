//! Freezing a recorded result as a baseline, and reading or writing the
//! configuration that describes a run.

#![allow(
    clippy::redundant_pub_crate,
    reason = "the implementation module exposes both commands to the command layer"
)]

use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::baseline::{self};
use crate::cli::{BaselineAction, ConfigAction};
use crate::config::{self, ConfigSource};
use crate::{Outcome, scan};

/// Freeze or prune a baseline against the last recorded scan of a tree.
///
/// Both actions read a scan that already happened rather than performing one:
/// a baseline is a judgement about a result, and taking it from the recorded
/// result keeps the judgement and the report it refers to the same thing.
#[allow(
    clippy::too_many_lines,
    reason = "create and update share the same invocation and compatibility contract"
)]
pub(crate) fn baseline(action: &BaselineAction, out: &mut impl Write) -> Result<Outcome> {
    let (args, create, force) = match action {
        BaselineAction::Create(args) => (&args.common, true, args.force),
        BaselineAction::Update(args) => (args, false, false),
    };
    let root = codehelion_core::paths::canonical(&args.path)
        .with_context(|| format!("resolving path {}", args.path.display()))?;
    let resolved_config = config::load(args.config.as_deref(), &root)?;
    // Reading: a baseline is taken from runs that are already recorded, so a
    // neighbour this build just created would hold nothing to take one from.
    let db_path = scan::database_path_for(
        scan::DatabaseUse::Reading,
        &root,
        args.db.as_deref(),
        &resolved_config,
        false,
    )?;
    if !db_path.is_file() {
        bail!(
            "no local database at {}; run `codehelion scan` first",
            db_path.display()
        );
    }
    let store = scan::open_recorded_store(&db_path)?;
    let root_path = scan::path_key(&root);
    let invocation = store.latest_completed_invocation(&root_path)?;
    if invocation.is_empty() {
        bail!(
            "{} holds no completed scan of {}; run `codehelion scan` first",
            db_path.display(),
            root.display()
        );
    }
    let runs: Vec<_> = invocation
        .into_iter()
        .map(|origin| {
            let groups = store.run_groups(origin.id)?;
            Ok((origin, groups))
        })
        .collect::<Result<_>>()?;

    if create {
        if args.file.exists() && !force {
            bail!(
                "{} already exists; pass --force to overwrite",
                args.file.display()
            );
        }
        let recorded = baseline::Baseline::from_runs(&runs, &scan::rfc3339_now())?;
        recorded.write(&args.file)?;
        writeln!(
            out,
            "wrote {} ({} findings frozen across {} build variants from {} run parts)",
            args.file.display(),
            recorded
                .partitions
                .iter()
                .map(|partition| partition.entries.len())
                .sum::<usize>(),
            recorded.partitions.len(),
            runs.len(),
        )?;
        return Ok(Outcome::Success);
    }

    let existing = baseline::Baseline::load(&args.file)?;
    let mut pruned = existing.clone();
    let mut dropped = Vec::new();
    for (origin, groups) in &runs {
        let Some(partition) = existing.partition(&origin.variant_fingerprint) else {
            bail!(
                "{} does not describe run {}: it has no partition for build variant {}",
                args.file.display(),
                origin.id,
                origin.variant_fingerprint
            );
        };
        let fit = partition.compatibility(&origin.detector_versions, origin.min_clone_tokens);
        if let Some(reason) = fit.mismatch {
            bail!(
                "{} does not describe run {}: {}",
                args.file.display(),
                origin.id,
                reason
            );
        }
        let present: std::collections::BTreeSet<String> = groups
            .iter()
            .map(|group| group.fingerprint_hex.clone())
            .collect();
        let (next, part_dropped) = pruned.pruned_partition(&origin.variant_fingerprint, &present);
        pruned = next;
        dropped.extend(
            part_dropped
                .into_iter()
                .map(|id| (origin.variant_fingerprint.clone(), id)),
        );
    }
    pruned.write(&args.file)?;
    writeln!(
        out,
        "updated {} ({} entries kept across {} build variants, {} resolved and dropped)",
        args.file.display(),
        pruned
            .partitions
            .iter()
            .map(|partition| partition.entries.len())
            .sum::<usize>(),
        pruned.partitions.len(),
        dropped.len(),
    )?;
    for (variant, id) in &dropped {
        writeln!(
            out,
            "  resolved [{}]: {id}",
            variant.get(..12).unwrap_or(variant)
        )?;
    }
    Ok(Outcome::Success)
}

pub(crate) fn config_command(action: &ConfigAction, out: &mut impl Write) -> Result<Outcome> {
    match action {
        ConfigAction::Show { config } => {
            let start = std::env::current_dir().context("resolving the current directory")?;
            let resolved = config::load(config.as_deref(), &start)?;
            match &resolved.source {
                ConfigSource::Explicit(path) | ConfigSource::Discovered(path) => {
                    writeln!(out, "# source: {}", path.display())?;
                }
                ConfigSource::Defaults => writeln!(out, "# source: built-in defaults")?,
            }
            write!(out, "{}", resolved.config.to_display_toml()?)?;
            Ok(Outcome::Success)
        }
        ConfigAction::Init { output, force } => {
            let path = output
                .clone()
                .unwrap_or_else(|| PathBuf::from(config::CONFIG_FILE_NAME));
            if path.exists() && !force {
                bail!(
                    "{} already exists; pass --force to overwrite",
                    path.display()
                );
            }
            std::fs::write(&path, config::TEMPLATE)
                .with_context(|| format!("writing {}", path.display()))?;
            writeln!(out, "wrote {}", path.display())?;
            Ok(Outcome::Success)
        }
    }
}
