//! Development CLI for scan-performance benchmarks.
//!
//! Generates deterministic large corpora, measures cold scans of the real
//! `codehelion` binary (wall time + peak RSS), and times snapshot inserts
//! in isolation. A dev/CI tool; not part of the shipped CLI.

use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};

use codehelion_eval::bench::{
    CorpusSpec, ScanMeasurement, ScanStart, Slo, default_binary, generate_corpus, measure_scan,
    measure_store_insert,
};

/// Benchmark harness for the scan paths.
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
    /// Measure cold and warm scans of a corpus with the real binary.
    Scan {
        /// Corpus directory to scan.
        #[arg(long)]
        corpus: PathBuf,
        /// Path of the `codehelion` binary (default: the release build).
        #[arg(long)]
        binary: Option<PathBuf>,
        /// Scan mode to measure.
        #[arg(long, default_value = "fast")]
        mode: String,
        /// Number of cold/warm run pairs.
        #[arg(long, default_value_t = 3)]
        runs: u32,
        /// Worker threads to pass through to the scan.
        #[arg(long)]
        jobs: Option<usize>,
        /// Judge the last run against the size targets and exit non-zero if
        /// it misses any of them.
        #[arg(long)]
        check_slo: bool,
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

/// Peak memory as a display string, or `n/a` where the platform does not
/// report it.
#[allow(clippy::cast_precision_loss)] // display-only conversion
fn mib(bytes: Option<u64>) -> String {
    bytes.map_or_else(
        || "n/a".to_string(),
        |bytes| format!("{:.1}", bytes as f64 / (1024.0 * 1024.0)),
    )
}

/// Say how the measured scan stood against the targets for its size, and fail
/// the run when asked to hold it to them.
///
/// Judged on the cold run: a periodic audit of a tree nobody has scanned
/// before is the case the targets are about, and it is the slower of the two.
fn report_slo(measurement: &ScanMeasurement, enforce: bool) -> Result<()> {
    let slo = Slo::for_lines(measurement.lines);
    let missed = slo.shortfalls(measurement);
    if missed.is_empty() {
        println!(
            "\nsize targets met at {} lines: {:.1}s of {}s, {} MiB of {} MiB, \
             whole search completed",
            measurement.lines,
            measurement.wall.as_secs_f64(),
            slo.wall.as_secs(),
            mib(measurement.max_rss_bytes),
            mib(Some(slo.max_rss_bytes)),
        );
        return Ok(());
    }
    println!("\nsize targets missed at {} lines:", measurement.lines);
    for shortfall in &missed {
        println!("  {shortfall}");
    }
    ensure!(!enforce, "the scan missed {} size target(s)", missed.len());
    Ok(())
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
            mode,
            runs,
            jobs,
            check_slo,
        } => {
            ensure!(runs > 0, "at least one run is required");
            let binary = binary.unwrap_or_else(default_binary);
            ensure!(
                binary.is_file(),
                "binary {} not found; build it with `cargo build --release`",
                binary.display()
            );
            let work = tempfile::tempdir().context("creating a work directory")?;
            println!("scan mode: {mode}");
            // Each run is a pair: one scan with no history of the tree, then
            // one with the first scan's database in place. What separates
            // them is what the second knows, which is the whole question a
            // warm number answers.
            println!("| run | cold_s | warm_s | cold_rss_mib | warm_rss_mib |");
            println!("| --- | ------ | ------ | ------------ | ------------ |");
            let mut last = None;
            for run in 1..=runs {
                let cold =
                    measure_scan(&binary, &corpus, &mode, jobs, work.path(), ScanStart::Cold)?;
                let warm =
                    measure_scan(&binary, &corpus, &mode, jobs, work.path(), ScanStart::Warm)?;
                println!(
                    "| {run} | {:.2} | {:.2} | {} | {} |",
                    cold.wall.as_secs_f64(),
                    warm.wall.as_secs_f64(),
                    mib(cold.max_rss_bytes),
                    mib(warm.max_rss_bytes),
                );
                last = Some(cold);
            }
            if let Some(last) = last {
                println!("\nreport summary:\n{}", last.summary);
                report_slo(&last, check_slo)?;
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
