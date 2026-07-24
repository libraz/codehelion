//! Development CLI for scan-performance benchmarks.
//!
//! Generates deterministic large corpora, measures cold scans of the real
//! `codehelion` binary (wall time + peak RSS), and times snapshot inserts
//! in isolation. A dev/CI tool; not part of the shipped CLI.

use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};

use codehelion_eval::bench::{
    CorpusSpec, default_binary, generate_corpus, measure_scan, measure_store_insert,
};

/// Benchmark harness for the Fast scan path.
#[derive(Debug, Parser)]
#[command(name = "codehelion-bench", version, about, long_about = None)]
struct Args {
    /// Subcommand to run.
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a deterministic benchmark corpus.
    Corpus {
        /// Directory to write the corpus into (must not already have one).
        #[arg(long)]
        out: PathBuf,
        /// Target size in source lines.
        #[arg(long)]
        lines: u64,
        /// Generator seed.
        #[arg(long, default_value_t = 42)]
        seed: u64,
        /// Percent of functions emitted as clones of an earlier function.
        #[arg(long, default_value_t = 5)]
        clone_percent: u8,
    },
    /// Measure cold scans of a corpus with the real binary.
    Scan {
        /// Corpus directory to scan.
        #[arg(long)]
        corpus: PathBuf,
        /// Path of the `codehelion` binary (default: the release build).
        #[arg(long)]
        binary: Option<PathBuf>,
        /// Number of cold runs.
        #[arg(long, default_value_t = 3)]
        runs: u32,
        /// Worker threads to pass through to the scan.
        #[arg(long)]
        jobs: Option<usize>,
    },
    /// Time one snapshot insert of synthetic rows.
    Store {
        /// Unit rows to write.
        #[arg(long, default_value_t = 20_000)]
        units: usize,
        /// Group rows to write.
        #[arg(long, default_value_t = 10_000)]
        groups: usize,
        /// Members per group.
        #[arg(long, default_value_t = 3)]
        members: usize,
    },
}

#[allow(clippy::cast_precision_loss)] // float conversions are display-only
fn main() -> Result<()> {
    match Args::parse().command {
        Command::Corpus {
            out,
            lines,
            seed,
            clone_percent,
        } => {
            let spec = CorpusSpec {
                target_lines: lines,
                seed,
                clone_percent,
            };
            let stats = generate_corpus(&spec, &out)?;
            println!(
                "corpus: {} files, {} lines, {} functions ({} cloned) in {}",
                stats.files,
                stats.lines,
                stats.functions,
                stats.cloned_functions,
                out.display()
            );
        }
        Command::Scan {
            corpus,
            binary,
            runs,
            jobs,
        } => {
            ensure!(runs > 0, "at least one run is required");
            let binary = binary.unwrap_or_else(default_binary);
            ensure!(
                binary.is_file(),
                "binary {} not found; build it with `cargo build --release`",
                binary.display()
            );
            let work = tempfile::tempdir().context("creating a work directory")?;
            println!("| run | wall_s | max_rss_mib |");
            println!("| --- | ------ | ----------- |");
            let mut last_summary = String::new();
            for run in 1..=runs {
                let measurement = measure_scan(&binary, &corpus, jobs, work.path())?;
                let rss = measurement.max_rss_bytes.map_or_else(
                    || "n/a".to_string(),
                    |bytes| format!("{:.1}", bytes as f64 / (1024.0 * 1024.0)),
                );
                println!("| {run} | {:.2} | {rss} |", measurement.wall.as_secs_f64());
                last_summary = measurement.summary;
            }
            if !last_summary.is_empty() {
                println!("\nreport summary:\n{last_summary}");
            }
        }
        Command::Store {
            units,
            groups,
            members,
        } => {
            let work = tempfile::tempdir().context("creating a work directory")?;
            let measurement = measure_store_insert(units, groups, members, work.path())?;
            let rows = measurement.units + measurement.groups + measurement.members;
            println!(
                "store insert: {} units + {} groups + {} members in {:.3}s ({:.0} rows/s)",
                measurement.units,
                measurement.groups,
                measurement.members,
                measurement.elapsed.as_secs_f64(),
                rows as f64 / measurement.elapsed.as_secs_f64(),
            );
        }
    }
    Ok(())
}
