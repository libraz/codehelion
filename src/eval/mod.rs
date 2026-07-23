//! Permanent evaluation harness for clone-detection prototypes.
//!
//! This module scores the output of a detection prototype against a labelled
//! corpus. It is a development and CI tool: it is not part of the shipped
//! `codehelion` CLI, and it is compiled only when the `eval` feature is
//! enabled.
//!
//! The pieces are:
//!
//! - [`schema`] — the common detection-result contract that every prototype
//!   emits as JSON.
//! - [`labels`] — the corpus ground-truth format (clone pairs and deliberate
//!   non-clones).
//! - [`metrics`] — matching of findings against labels plus the accuracy and
//!   stability metrics derived from that matching.

pub mod labels;
pub mod metrics;
pub mod schema;
