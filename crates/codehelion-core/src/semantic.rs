//! Restricted Semantic Operation Graphs.
//!
//! This is deliberately a closed vocabulary. The graph is a target for
//! compiler-independent normalization, not a generic program representation:
//! code that cannot be expressed by one of these operations is left outside
//! semantic matching. That restriction keeps later findings explainable as a
//! sequence of registered transformations instead of turning this mode into a
//! claim of general semantic equivalence.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::discovery::Language;
use crate::types::TypeTag;

mod candidates;
mod cross_language;
mod graph;
mod normalization;
mod rules;

use cross_language::{
    CROSS_LANGUAGE_OPTIONAL_VALIDATION_RULE, CROSS_LANGUAGE_RESULT_DIRECT_PROPAGATION_RULE,
    CROSS_LANGUAGE_RESULT_VALIDATION_RULE, CROSS_LANGUAGE_SEQUENCE_PIPELINE_RULE,
};

#[cfg(test)]
use cross_language::DIRECT_LOOP_SEQUENCE_CORRESPONDENCE_ID;

pub use candidates::*;
pub use cross_language::*;
pub use graph::*;
pub use normalization::*;
pub use rules::*;

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests;
