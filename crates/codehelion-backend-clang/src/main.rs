//! The C and C++ compiler helper: one program, one compiler, one protocol.
//!
//! codehelion never links a compiler. This program does — through libclang's
//! stable C interface, loaded when it starts rather than built into it — and
//! talks to the tool over the length-prefixed protocol in `codehelion-helper`.
//! A compiler that is not installed, will not load, or takes forever costs a
//! scan its semantic answers about C and C++ and nothing else.
//!
//! # When there is no Clang to load
//!
//! The program says which library is missing on its standard error and stops.
//! That is the whole diagnosis: the client keeps what a helper printed before
//! it went and reports it, so `doctor` shows the sentence naming what to
//! install rather than a program that mysteriously would not talk. Answering
//! the handshake and then refusing everything would be worse — it would look
//! installed and working right up until a scan came back empty.
//!
//! # Control-flow graph evidence
//!
//! libclang does not expose Clang's own CFG. When a fixed `clang` executable
//! is installed, the helper separately invokes it in syntax-only mode with
//! Clang's `debug.DumpCFG` checker. The compilation database supplies only
//! arguments that have passed a read-only filter; it never supplies an
//! executable, plugin, response file, or output path.
//!
//! It also runs nothing out of a project, at any permission, and offers no
//! execution class at all. A C++ project without a compilation database has one
//! because a configure step would write it, and running that is running the
//! project's own program — so this helper reports the files it cannot speak for
//! rather than producing the database it would need.

// In a binary crate the two visibility lints disagree: `unreachable_pub` wants
// items in these modules to be `pub(crate)`, and `redundant_pub_crate` wants
// them to be `pub` because the modules are private. Nothing here is reachable
// from outside the program either way, so one of them has to give.
#![allow(clippy::redundant_pub_crate)]

mod analysis;
mod cfg_dump;
mod database;
mod types;

use std::path::Path;

use codehelion_helper::PROTOCOL_VERSION;
use codehelion_helper::ir::{COMPILER_IR_SCHEMA_VERSION, Unavailability};
use codehelion_helper::protocol::{
    Analyze, BuildDescription, Capability, DescribeBuild, HelperIdentity,
};
use codehelion_helper::server::{Answer, Backend, Description, serve};

use crate::analysis::Outcome;
use crate::database::Databases;

/// The name this helper is known by, in `doctor` and in the audit database.
const NAME: &str = "codehelion-backend-clang";

/// Say on standard error why a request could not be answered.
///
/// The client keeps what a helper printed while a unit went unanswered and
/// reports it beside that unit, so a reason worked out here and kept here is a
/// reason nobody can act on: a count of units with no build information says
/// how many were refused and nothing about whether the fix is a compiler
/// argument this program will not forward, a database that is not there, or a
/// header that no command in the project compiles. Those have different
/// answers, and only this side knows which one happened.
///
/// One line per refusal, because what the client keeps is bounded by lines: a
/// reason spread over several would cost the reasons after it.
pub(crate) fn refused(why: &str) {
    // Standard error, for the reason the whole stream exists here: standard
    // output is the protocol, and a sentence written there is read as a
    // malformed frame.
    eprintln!("{NAME}: {why}");
}

fn main() -> std::process::ExitCode {
    if let Err(error) = codehelion_helper::enforce_current_process_limit_from_environment() {
        eprintln!("{NAME}: {error}");
        return std::process::ExitCode::FAILURE;
    }
    // Loaded before a word is exchanged. A program that has no compiler to
    // analyse with has nothing to negotiate, and the sentence naming the
    // library that is missing is more use than a handshake that succeeds into
    // an empty scan.
    let clang = match clang::Clang::new() {
        Ok(clang) => clang,
        Err(why) => {
            eprintln!(
                "{NAME}: no libclang to analyse with: {why}. Install Clang's library and, \
                 if it is somewhere unusual, point LIBCLANG_PATH at it."
            );
            return std::process::ExitCode::FAILURE;
        }
    };
    let mut backend = ClangBackend {
        clang: &clang,
        cfg_available: cfg_dump::available(),
        databases: Databases::default(),
    };
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    match serve(&mut backend, &mut input, &mut output) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            // Standard error, because standard output is the protocol: a
            // diagnostic written there would be read as a malformed frame. The
            // client collects this stream and reports it, which is usually the
            // only sentence explaining why a helper stopped.
            eprintln!("{NAME}: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// The compiler this process answers with.
struct ClangBackend<'c> {
    clang: &'c clang::Clang,
    cfg_available: bool,
    /// The compilation databases this process has already looked for, kept for
    /// as long as it lives: every unit of one project is governed by the same
    /// database, and reading it per request would make analysing a tree cost
    /// one parse of it per file.
    databases: Databases,
}

impl Backend for ClangBackend<'_> {
    fn identity(&self) -> HelperIdentity {
        HelperIdentity {
            name: NAME.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            protocol: PROTOCOL_VERSION,
            // The compiler that will answer. Unlike a helper that ships the
            // compiler it uses, this one analyses with whichever libclang the
            // machine has, so the version is read rather than named.
            toolchains: vec![clang::get_version()],
            // Only what is implemented. CFG remains auxiliary and may be
            // absent for a command whose safe frontend cannot be constructed.
            capabilities: {
                let mut capabilities = vec![
                    Capability::Types,
                    Capability::NameResolution,
                    Capability::CallTargets,
                    // Both locations of every name, which is what the capability
                    // names: a declaration a macro produced anchors where it reads
                    // and carries where it was written.
                    Capability::MacroExpansion,
                    Capability::TemplateInstantiation,
                ];
                if self.cfg_available {
                    capabilities.push(Capability::MirCfg);
                }
                capabilities
            },
            // Nothing, at any permission. Somebody who permits a configure step
            // is told this helper would not act on it, rather than left to
            // wonder why the answers did not change.
            executes: Vec::new(),
        }
    }

    fn describe(&mut self, request: &DescribeBuild) -> Description {
        // A tree with no compilation database has no C or C++ build to
        // describe, which is an answer rather than a failure: a project that is
        // entirely Rust is not missing one, and refusing here would stop a scan
        // of it because a helper it never needed happened to be installed.
        let described = self
            .databases
            .nearest(Path::new(&request.root))
            .map_or_else(BuildDescription::default, |database| BuildDescription {
                features: Vec::new(),
                // The macros a translation unit is compiled with decide which
                // declarations its headers contain at all, which is what a cfg
                // is — the same question C answers with `#if`.
                cfgs: database.definitions(),
            });
        Description::Build(described)
    }

    fn analyze(&mut self, request: &Analyze) -> Answer {
        let clang = self.clang;
        let Some(database) = self.databases.nearest(Path::new(&request.unit.file)) else {
            // Nothing above this file says how it is compiled. Reported per
            // file rather than as a failed run: a scan of a mixed tree reads
            // the half that does have a build, and the half nobody could speak
            // for is what a coverage report is for.
            refused(&format!(
                "{}: no compilation database above this file says how it is compiled",
                request.unit.unit
            ));
            return Answer::Unavailable(Unavailability::NoBuildInformation);
        };
        match analysis::analyze(
            clang,
            &request.unit,
            database,
            request.compile_command.as_ref(),
            request.read_boundary.as_deref().map(Path::new),
            &request.want,
        ) {
            Outcome::Analyzed(mut ir) => {
                ir.schema_version = COMPILER_IR_SCHEMA_VERSION.to_string();
                // One walk of a translation unit produces several kinds of
                // fact at once, and walking it again per kind would cost more
                // and risk disagreeing with itself. What was not asked for is
                // dropped before the answer leaves: a reply carrying an
                // unrequested kind cannot be told apart from one where that
                // capability was asked for and found nothing.
                ir.keep_only(&request.want);
                Answer::Analyzed(ir)
            }
            Outcome::Unavailable(reason) => Answer::Unavailable(reason),
        }
    }
}
