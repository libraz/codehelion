//! Local `SQLite` audit storage for codehelion.
//!
//! This crate isolates the `SQLite` dependency from the analysis core: the
//! engine ([`codehelion-core`](https://docs.rs/codehelion-core)) stays free of
//! any storage backend, and the CLI drives persistence through this crate. It
//! is the canonical store; JSON, SARIF and CSV are export formats only. The
//! schema and query layer land here in a later step; this crate currently
//! reserves the boundary.
