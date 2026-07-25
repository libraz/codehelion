//! Development CLI for the `codehelion` evaluation harness.
//!
//! Scores a scan report against a corpus label file and prints accuracy
//! metrics. With `--compare`, it also reports run-to-run stability against a
//! second report. This binary is a dev/CI tool; it is not part of the shipped
//! `codehelion` CLI.
//!
//! For the committed corpora the same measurement runs as a test, so it does
//! not depend on anyone remembering to invoke this. Reach for this binary to
//! score a corpus that is not committed, or to compare two saved reports.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

use codehelion_eval::detected;
use codehelion_eval::labels::LabelSet;
use codehelion_eval::metrics::{DEFAULT_MATCH_THRESHOLD, evaluate, stability};
use codehelion_eval::schema::DetectionResult;

/// Score detection-prototype output against a labelled corpus.
#[derive(Debug, Parser)]
#[command(name = "codehelion-eval", version, about, long_about = None)]
struct Args {
    /// Scan report JSON, as `codehelion scan --format json` writes it.
    #[arg(long)]
    results: PathBuf,
    /// Corpus label JSON to score against.
    #[arg(long)]
    labels: PathBuf,
    /// Lines of analysed code, used for the per-KLOC rates. Defaults to the
    /// line count the scan itself measured.
    #[arg(long)]
    loc: Option<u32>,
    /// Overlap threshold for the "covers" relation.
    #[arg(long, default_value_t = DEFAULT_MATCH_THRESHOLD)]
    threshold: f64,
    /// Number of top-scoring findings for precision@k.
    #[arg(long, default_value_t = 10)]
    top_k: usize,
    /// A second results JSON; when given, also report stability vs `--results`.
    #[arg(long)]
    compare: Option<PathBuf>,
}

/// Read a scan report as a scorable result, with the line count it measured.
fn read_detection(path: &PathBuf) -> Result<(DetectionResult, u32)> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading results file {}", path.display()))?;
    detected::from_report_json(&text)
        .with_context(|| format!("reading scan report {}", path.display()))
}

fn main() -> Result<()> {
    let args = Args::parse();

    let (results, scanned_lines) = read_detection(&args.results)?;
    let labels_text = fs::read_to_string(&args.labels)
        .with_context(|| format!("reading labels file {}", args.labels.display()))?;
    let labels = LabelSet::from_json(&labels_text)
        .with_context(|| format!("parsing labels {}", args.labels.display()))?;

    let loc = args.loc.unwrap_or(scanned_lines);
    let metrics = evaluate(&results, &labels, loc, args.threshold, args.top_k);
    println!("{metrics}");

    if let Some(compare_path) = &args.compare {
        let (other, _) = read_detection(compare_path)?;
        let stability = stability(&results, &other);
        println!();
        println!("stability vs {}", compare_path.display());
        println!("{stability}");
    }

    Ok(())
}
