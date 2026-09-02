//! Who supplied a value this run is about to act on.
//!
//! Two different things reach the tool at once: what the operator typed, and
//! whatever the directory they pointed at happens to contain. Only the first
//! may decide where the tool writes, which directory bounds that write, or
//! what the tool runs — the second is the subject of the audit, not a party to
//! it. Keeping the two apart as types is what makes the difference impossible
//! to forget: a value the tree supplied cannot be passed where a path, a
//! boundary or a piece of text is expected, so the trust decision has to be
//! made rather than skipped.
//!
//! The types live in their own module so that their contents stay private to
//! it. A tuple field declared at the crate root would be readable from every
//! module in the crate, which is exactly the guarantee this is here to give.
#![allow(
    clippy::redundant_pub_crate,
    reason = "the module is crate-visible; its items keep the crate's own visibility spelling"
)]

use std::path::{Path, PathBuf};

use codehelion_core::discovery::Language;

/// A value this run may act on because the operator, not the tree, chose
/// it.
///
/// The two constructors are the only places that authority is asserted, so
/// every assertion of it is one search away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OperatorSupplied<T>(T);

impl<T> OperatorSupplied<T> {
    /// Record that `value` arrived in this invocation's arguments.
    pub(crate) const fn from_command_line(value: T) -> Self {
        Self(value)
    }

    /// Record that `value` is this build's own default, which the tree
    /// under audit had no part in choosing.
    pub(crate) const fn from_this_build(value: T) -> Self {
        Self(value)
    }

    /// The value, with the operator's authority behind it.
    pub(crate) const fn get(&self) -> &T {
        &self.0
    }

    /// Read this value as though the tree had supplied it.
    ///
    /// `--untrusted` says precisely that about a configuration: the
    /// operator may have named the file, but this run is not to take its
    /// word about where the tool writes. Spelling the demotion as a change
    /// of type keeps the flag's whole effect on storage in one expression
    /// instead of in a condition each consumer has to repeat.
    pub(crate) fn distrusted(self) -> FromScannedTree<T> {
        FromScannedTree(self.0)
    }
}

/// A value read out of the tree under audit.
///
/// There is no accessor that hands the value over unconditionally. What
/// there is instead is one narrowing per kind of value: a path is only
/// reachable from code that already holds the boundary it is checked
/// against, and source text is only readable as the comments the file's
/// own language says it holds. Handing one of these values straight to
/// something expecting a `&Path` or a `&str` does not compile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FromScannedTree<T>(T);

impl<T> FromScannedTree<T> {
    /// Record that `value` was read out of the tree being audited.
    pub(crate) const fn found(value: T) -> Self {
        Self(value)
    }
}

impl<'a> FromScannedTree<&'a Path> {
    /// The path as the tree spelled it.
    ///
    /// What a caller does with this is check it against a boundary the
    /// operator supplied, or quote it back in the refusal that check
    /// produced. Joining it onto anything else is how a tree ends up
    /// choosing a location nobody pointed at.
    pub(crate) const fn as_written(&self) -> &'a Path {
        self.0
    }
}

impl FromScannedTree<PathBuf> {
    /// This directory as the place a database nobody configured is put.
    ///
    /// The one thing a directory found by inspecting the tree decides, and
    /// it is not a trust decision: the default location is this build's,
    /// and the tree only says where the repository holding it begins.
    /// Deliberately not a confinement boundary — a boundary decides what a
    /// *configured* path may not leave, and only a directory the operator
    /// named can do that.
    pub(crate) fn as_default_placement(&self) -> &Path {
        &self.0
    }
}

/// A value one of the two parties chose, before anything narrows it.
///
/// A configured setting arrives without its authority attached — the file
/// it came from decides that, and the file is the same file whatever the
/// setting. Pairing the two here means a consumer receives the value and
/// the question about it together, and answers the question by matching
/// rather than by remembering to ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Authority<T> {
    /// The operator chose it, through an argument or this build's default.
    Operator(OperatorSupplied<T>),
    /// The tree under audit chose it.
    Tree(FromScannedTree<T>),
}

impl<T> Authority<T> {
    /// Read this value as though the tree had supplied it, whoever did.
    ///
    /// What `--untrusted` says about every configured setting at once.
    pub(crate) fn distrusted(self) -> FromScannedTree<T> {
        match self {
            Self::Operator(value) => value.distrusted(),
            Self::Tree(value) => value,
        }
    }
}

impl<'a> FromScannedTree<&'a str> {
    /// The comment text this source holds, as `(1-based line, text)`
    /// pairs, one entry per line a comment covers.
    ///
    /// The narrowing that makes tree text safe to act on: whatever the
    /// file says, only what its own language treats as a comment comes
    /// back out.
    pub(crate) fn comments(&self, language: Language) -> Vec<(u32, &'a str)> {
        crate::suppress::comments_of(self.0, language)
    }
}
