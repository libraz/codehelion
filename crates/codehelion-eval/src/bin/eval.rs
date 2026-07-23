//! Development CLI for the `codehelion` evaluation harness.
//!
//! Scores a detection prototype's JSON output against a corpus label file and
//! prints accuracy metrics. With `--compare`, it also reports run-to-run
//! stability against a second results file. This binary is a dev/CI tool built
//! only under the `eval` feature; it is not part of the shipped `codehelion`
//! CLI.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

use codehelion_eval::labels::LabelSet;
use codehelion_eval::metrics::{DEFAULT_MATCH_THRESHOLD, evaluate, stability};
use codehelion_eval::schema::DetectionResult;

/// Score detection-prototype output against a labelled corpus.
#[derive(Debug, Parser)]
#[command(name = "codehelion-eval", version, about, long_about = None)]
struct Args {
    /// Detection-result JSON produced by a prototype.
    #[arg(long)]
    results: PathBuf,
    /// Corpus label JSON to score against.
    #[arg(long)]
    labels: PathBuf,
    /// Lines of analysed code, used for the per-KLOC rates.
    #[arg(long)]
    loc: u32,
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

fn read_detection(path: &PathBuf) -> Result<DetectionResult> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading results file {}", path.display()))?;
    DetectionResult::from_json(&text)
        .with_context(|| format!("parsing detection result {}", path.display()))
}

fn main() -> Result<()> {
    let args = Args::parse();

    let results = read_detection(&args.results)?;
    let labels_text = fs::read_to_string(&args.labels)
        .with_context(|| format!("reading labels file {}", args.labels.display()))?;
    let labels = LabelSet::from_json(&labels_text)
        .with_context(|| format!("parsing labels {}", args.labels.display()))?;

    let metrics = evaluate(&results, &labels, args.loc, args.threshold, args.top_k);
    println!("{metrics}");

    if let Some(compare_path) = &args.compare {
        let other = read_detection(compare_path)?;
        let stability = stability(&results, &other);
        println!();
        println!("stability vs {}", compare_path.display());
        println!("{stability}");
    }

    Ok(())
}
