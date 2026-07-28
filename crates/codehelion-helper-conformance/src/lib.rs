//! A helper that goes wrong on purpose, and the tests that watch what happens.
//!
//! The ways a compiler helper can fail — a read that never returns, a child
//! that exits mid-message, a pipe that closes half a frame in — are properties
//! of an operating-system process and do not reproduce against an in-process
//! stream. Proving the client survives them therefore needs a real program that
//! misbehaves on request, which is what `mock-helper` is.
//!
//! It lives in its own crate for two reasons. A test that locates a binary by
//! guessing a path can silently run a stale copy and report success, so the
//! mock has to be a binary of the same package as the tests that drive it,
//! where cargo passes its path in and guarantees it is current. And nothing
//! here belongs in a release, so this crate is not published.
