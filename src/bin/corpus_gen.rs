//! Development CLI for the synthetic-corpus mutation generator.
//!
//! Derives clone variant source files and their ground-truth `labels.json`
//! from a seed source plus a declarative mutation spec (`generate`), and
//! verifies that committed corpus files still match what the spec regenerates
//! (`check`). This binary is a dev/CI tool built only under the `corpus-gen`
//! feature; it is not part of the shipped `codehelion` CLI.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

use codehelion::corpus::generate::{ChangeRate, GeneratedCorpus, first_difference, generate};
use codehelion::corpus::spec::MutationSpec;

/// Generate or verify a synthetic corpus from a mutation spec.
#[derive(Debug, Parser)]
#[command(name = "codehelion-corpus-gen", version, about, long_about = None)]
struct Args {
    /// Subcommand to run.
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate variant sources and labels.json into a directory.
    Generate {
        /// Mutation-spec JSON; the seed path inside it is resolved relative
        /// to this file's directory.
        #[arg(long)]
        spec: PathBuf,
        /// Directory to write the generated files into.
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Verify that the files in a directory match what the spec regenerates.
    Check {
        /// Mutation-spec JSON; the seed path inside it is resolved relative
        /// to this file's directory.
        #[arg(long)]
        spec: PathBuf,
        /// Directory holding the committed corpus files.
        #[arg(long)]
        dir: PathBuf,
    },
}

/// Read the spec and its seed, then run the generator in memory.
fn regenerate(spec_path: &Path) -> Result<GeneratedCorpus> {
    let spec_text = fs::read_to_string(spec_path)
        .with_context(|| format!("reading spec file {}", spec_path.display()))?;
    let spec = MutationSpec::from_json(&spec_text)
        .with_context(|| format!("parsing spec {}", spec_path.display()))?;
    let seed_path = spec_path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(&spec.seed);
    let seed_text = fs::read_to_string(&seed_path)
        .with_context(|| format!("reading seed file {}", seed_path.display()))?;
    generate(&spec, &seed_text)
        .with_context(|| format!("generating corpus from {}", spec_path.display()))
}

fn print_change_rates(rates: &[ChangeRate]) {
    for rate in rates {
        let target = rate
            .target
            .map_or_else(|| "none".to_string(), |target| format!("{target:.2}"));
        println!(
            "{} `{}`: change rate achieved {:.2} ({}/{} statements), target {}",
            rate.variant,
            rate.item,
            rate.achieved(),
            rate.changed_statements,
            rate.total_statements,
            target
        );
    }
}

fn run_generate(spec: &Path, out_dir: &Path) -> Result<()> {
    let corpus = regenerate(spec)?;
    fs::create_dir_all(out_dir)
        .with_context(|| format!("creating output directory {}", out_dir.display()))?;
    for (name, contents) in &corpus.files {
        let path = out_dir.join(name);
        fs::write(&path, contents).with_context(|| format!("writing {}", path.display()))?;
        println!("wrote {}", path.display());
    }
    print_change_rates(&corpus.change_rates);
    Ok(())
}

fn run_check(spec: &Path, dir: &Path) -> Result<()> {
    let corpus = regenerate(spec)?;
    let mut mismatches = 0usize;
    for (name, expected) in &corpus.files {
        let path = dir.join(name);
        match fs::read_to_string(&path) {
            Ok(actual) => {
                // Normalize CRLF so a line-ending-converting checkout does
                // not report false drift; all other bytes must match.
                let actual = actual.replace("\r\n", "\n");
                if let Some(line) = first_difference(expected, &actual) {
                    println!("{name}: differs from the spec output at line {line}");
                    mismatches += 1;
                }
            }
            Err(source) => {
                println!("{name}: cannot read {} ({source})", path.display());
                mismatches += 1;
            }
        }
    }
    if mismatches > 0 {
        bail!(
            "{mismatches} file(s) in {} differ from what the spec regenerates; \
             re-run `codehelion-corpus-gen generate`",
            dir.display()
        );
    }
    println!(
        "{} file(s) in {} match the spec output",
        corpus.files.len(),
        dir.display()
    );
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    match &args.command {
        Command::Generate { spec, out_dir } => run_generate(spec, out_dir),
        Command::Check { spec, dir } => run_check(spec, dir),
    }
}
