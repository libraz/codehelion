//! Permanent evaluation harness and synthetic-corpus generator for
//! clone-detection work.
//!
//! This is a development and CI tool: a separate workspace crate that is not
//! part of the shipped `codehelion` CLI and is never published, so the released
//! binary pulls in no serde dependency.
//!
//! The pieces are:
//!
//! - [`schema`] — the common detection-result contract that every prototype
//!   emits as JSON.
//! - [`labels`] — the corpus ground-truth format (clone pairs and deliberate
//!   non-clones).
//! - [`metrics`] — matching of findings against labels plus the accuracy and
//!   stability metrics derived from that matching.
//! - [`corpus`] — the deterministic synthetic-corpus mutation generator that
//!   emits variant sources and their ground-truth labels.

pub mod corpus;
pub mod labels;
pub mod metrics;
pub mod schema;
