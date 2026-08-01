//! Permanent evaluation harness and synthetic-corpus generator for
//! clone-detection work.
//!
//! This is a development and CI tool: a separate workspace crate that is not
//! part of the shipped `codehelion` CLI and is never published, so the released
//! binary pulls in no serde dependency.
//!
//! The pieces are:
//!
//! - [`schema`] — the common detection-result contract that scoring reads.
//! - [`detected`] — reading the shipping scan report as that contract, so the
//!   harness scores what the tool actually reports.
//! - [`labels`] — the corpus ground-truth format (clone pairs and deliberate
//!   non-clones).
//! - [`metrics`] — matching of findings against labels plus the accuracy and
//!   stability metrics derived from that matching.
//! - `corpus` (with the `corpus-gen` feature) — the deterministic
//!   synthetic-corpus mutation generator that emits variant sources and their
//!   ground-truth labels.
//! - [`bench`](mod@bench) — large-corpus generation and cold-scan
//!   measurement for the performance targets.

pub mod bench;
#[cfg(feature = "corpus-gen")]
pub mod corpus;
pub mod detected;
pub mod labels;
pub mod metrics;
pub mod schema;
