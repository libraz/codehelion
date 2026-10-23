//! Compiler-helper discovery, capability checks, and sandbox requests.

use crate::cli::ScanArgs;
use crate::config::Config;
use anyhow::{Context, Result, bail};
use codehelion_core::discovery::{
    BuildConfiguration, CppBuild, Language, LanguageSelection, RustBuild, SourceUnit, content_hash,
};
use codehelion_core::doctor;
use codehelion_core::execution::{Execution as PermittedExecution, ExecutionPolicy};
use codehelion_helper::protocol::Execution;
use codehelion_helper::{Helper, SandboxRequest};
use std::path::{Path, PathBuf};

pub(super) fn semantic_sandbox(args: &ScanArgs) -> Result<SandboxRequest> {
    if !args.untrusted {
        return Ok(SandboxRequest::unrestricted());
    }
    let limits = codehelion_core::execution::Limits::untrusted();
    let Some(bytes) = limits.max_subprocess_bytes else {
        bail!("the untrusted profile must require a subprocess memory ceiling");
    };
    // Helpers read the tree's own files too, under the ceiling the scanner uses.
    let request =
        SandboxRequest::require_memory_limit(bytes).with_file_ceiling(limits.max_file_bytes);
    codehelion_helper::sandbox::validate(request)?;
    Ok(request)
}

/// One helper a semantic run can ask, what it said about itself, and what it
/// is allowed to run while answering.
pub(super) struct Installed {
    pub(super) component: doctor::HelperComponent,
    pub(super) program: PathBuf,
    pub(super) greeting: doctor::Greeting,
    pub(super) permitted: Vec<Execution>,
    pub(super) sandbox: SandboxRequest,
}

impl Installed {
    /// What this helper's half of the run was analysed under.
    ///
    /// The compiler version is the helper's own, not the project's: the
    /// answers came from what this program holds, and a variant that recorded
    /// the project's toolchain would attribute them to a compiler that never
    /// ran. The lockfile is the project's, because the dependency versions are
    /// part of what its source means.
    ///
    /// The features and settings are asked of the helper, because it is the
    /// side that resolves them, and asked before anything is analysed, because
    /// they are what the answers get filed under. Two runs of one tree under
    /// different features resolve different types; recorded under one identity
    /// they would be compared against each other, and the older of the two
    /// would be reported as findings that this run did not make.
    ///
    /// # Errors
    ///
    /// Fails if the helper cannot say. A run that could not name what it
    /// analysed the tree under would file its results under conditions it
    /// guessed at, which is worse than not running.
    pub(super) fn build(
        &self,
        root: &Path,
        timeout: std::time::Duration,
    ) -> Result<BuildConfiguration> {
        let described = self.describe(root, timeout)?;
        let permitted_execution: Vec<String> = self
            .permitted
            .iter()
            .map(|class| class.name().to_string())
            .collect();
        if self.component.analyses.contains(&Language::Rust) {
            return Ok(BuildConfiguration::Rust(Box::new(RustBuild {
                compiler_version: self.greeting.toolchains.join(", "),
                lockfile_hash: self.lockfile_hash(root),
                features: described.features,
                cfgs: described.cfgs,
                permitted_execution,
                ..RustBuild::default()
            })));
        }
        Ok(BuildConfiguration::Cpp(Box::new(CppBuild {
            // The compiler that answered rather than the one the database
            // names, for the reason the Rust side records its own: what a type
            // resolved to is a fact about the compiler that resolved it.
            compiler: self.greeting.toolchains.join(", "),
            // What a C or C++ file means is decided before it is parsed, by the
            // macros its command defines — the same question a cfg answers.
            macros: described.cfgs,
            ..CppBuild::default()
        })))
    }

    /// The hash of the tree's `Cargo.lock`, when it is a regular file within
    /// the ceiling this run reads the tree under.
    ///
    /// Absent otherwise: a planted FIFO, a link or an enormous file is not a
    /// lockfile this run can vouch for, and hashing one would block or read
    /// without bound.
    fn lockfile_hash(&self, root: &Path) -> Option<String> {
        use codehelion_helper::tree_file::{Links, read_text_bounded};
        let ceiling = self.sandbox.max_file_bytes().unwrap_or(u64::MAX);
        read_text_bounded(&root.join("Cargo.lock"), Links::Refuse, ceiling)
            .ok()
            .map(|text| content_hash(&text))
    }

    /// Ask one helper what the tree is read under, and let it go again.
    ///
    /// Its own short conversation rather than the one the analysis holds: this
    /// is asked before a run knows whether it will analyse anything at all,
    /// and a scan of an unchanged tree is answered from what was recorded
    /// without a compiler being asked about a single file.
    pub(super) fn describe(
        &self,
        root: &Path,
        timeout: std::time::Duration,
    ) -> Result<codehelion_helper::BuildDescription> {
        let mut helper = Helper::start_with_sandbox(&self.program, &[], timeout, self.sandbox)
            .with_context(|| {
                format!(
                    "asking {} what this tree is built with",
                    self.program.display()
                )
            })?;
        let described = helper.describe(root);
        let _ = helper.shutdown();
        described.with_context(|| {
            format!(
                "the helper at {} could not say what this tree is built with",
                self.program.display()
            )
        })
    }
}

/// The helpers a semantic run can ask, in the order they are tried.
pub(super) struct Compilers {
    pub(super) installed: Vec<Installed>,
}

impl Compilers {
    /// Locate every helper and shake hands with it, before anything is read.
    ///
    /// Up front because the alternative is discovering after a full parse that
    /// the run cannot be what it was asked to be, and because the two failures
    /// need different answers: one is a program to install, the other a
    /// program to update.
    ///
    /// A helper that is not installed is not a failure. One machine has the
    /// Rust helper and no Clang; the tree it is pointed at may be entirely
    /// Rust, in which case nothing is missing at all. What the run cannot do
    /// without is *some* helper, and which languages went unanswered is the
    /// coverage report's answer rather than this one's.
    ///
    /// It is also where a permission meets the program it was granted to. A
    /// helper says at the handshake what it acts on; anything permitted beyond
    /// that is dropped for that helper rather than sent and ignored, because
    /// the answer that comes back from ignoring it is thinner than the one that
    /// was asked for and looks exactly like the project's own.
    pub(super) fn found(
        permitted: &ExecutionPolicy,
        sandbox: SandboxRequest,
        paths: &crate::config::Helpers,
    ) -> Result<Self> {
        let discovered = doctor::OPTIONAL_HELPERS.map(|component| {
            let configured = match component.binary {
                "codehelion-backend-rust" => paths.rust.as_deref(),
                "codehelion-backend-clang" => paths.clang.as_deref(),
                _ => None,
            };
            let facts = crate::interrogate(component.binary, configured, sandbox);
            (
                component,
                Discovered::of(component, configured, facts, permitted, sandbox),
            )
        });
        let (installed, notes) = settled(discovered)?;
        // A helper that could not be used is said even when another answers,
        // because its languages go unanswered for that reason.
        for note in notes {
            eprintln!("{note}");
        }
        for class in permitted.permitted() {
            if Execution::from_name(class.name()).is_none() {
                bail!(
                    "this build has no protocol name for the execution class {}",
                    class.name()
                );
            }
            if !installed.iter().any(|helper| {
                helper
                    .permitted
                    .iter()
                    .any(|acts| acts.name() == class.name())
            }) {
                bail!("{}", unavailable_execution_message(class));
            }
        }
        Ok(Self { installed })
    }

    /// The helpers that have something to answer about, given the languages the
    /// tree turned out to hold.
    ///
    /// Narrowed after discovery rather than at the handshake, because what a
    /// helper is worth to a run is decided by the tree and not by the machine.
    /// A Rust-only project scanned where the Clang helper happens to be
    /// installed must be identified as the same run as one scanned where it is
    /// not: a variant that moved with what is installed would make every
    /// recorded run incomparable with the next machine's.
    pub(super) fn at_work(&self, present: LanguageSelection) -> Vec<&Installed> {
        self.installed
            .iter()
            .filter(|helper| {
                helper
                    .component
                    .analyses
                    .iter()
                    .any(|language| present.includes(*language))
            })
            .collect()
    }
}

/// What is said about a helper only when it was not found at all.
const NOT_FOUND: &str = "there is none beside this program or on PATH";

/// What looking for one helper came to.
///
/// Four outcomes rather than found-or-not, because each calls for a different
/// sentence: a program to install, a program to update, and a setting that
/// names something unusable are three different things to do about it.
pub(super) enum Discovered {
    /// It answered the handshake and can be asked.
    Usable(Box<Installed>),
    /// The operator named a location for it, and that location is unusable.
    ConfiguredUnusable(Unusable),
    /// It was found where helpers are looked for and could not be talked to.
    InstalledUnusable(Unusable),
    /// Nothing was found.
    Absent,
}

/// A helper that was located, or named, and cannot be used.
pub(super) struct Unusable {
    /// Where it is, or where the operator said it would be.
    pub(super) path: PathBuf,
    /// Why it cannot be used.
    pub(super) reason: String,
}

impl Discovered {
    /// Classify what looking for `component` found, given the location the
    /// operator configured for it, if any.
    ///
    /// `facts` is what [`crate::interrogate`] returned, which reports a
    /// configured location holding no program as unusable rather than absent.
    pub(super) fn of(
        component: doctor::HelperComponent,
        configured: Option<&Path>,
        facts: Option<doctor::HelperFacts>,
        permitted: &ExecutionPolicy,
        sandbox: SandboxRequest,
    ) -> Self {
        let Some(facts) = facts else {
            return Self::Absent;
        };
        match facts.state {
            doctor::HelperState::Answered(greeting) => Self::Usable(Box::new(Installed {
                permitted: acted_on(permitted, &greeting),
                component,
                program: facts.path,
                greeting,
                sandbox,
            })),
            doctor::HelperState::Silent(reason) => {
                let unusable = Unusable {
                    path: facts.path,
                    reason,
                };
                if configured.is_some() {
                    Self::ConfiguredUnusable(unusable)
                } else {
                    Self::InstalledUnusable(unusable)
                }
            }
        }
    }
}

/// The helpers a run can ask, and a note for each one that could not be used.
///
/// # Errors
///
/// Fails when no helper is usable, naming every one that was found or
/// configured and why it is unusable; only helpers that were not found at all
/// are described as missing.
pub(super) fn settled(
    discovered: impl IntoIterator<Item = (doctor::HelperComponent, Discovered)>,
) -> Result<(Vec<Installed>, Vec<String>)> {
    let mut installed = Vec::new();
    let mut unusable = Vec::new();
    let mut absent = Vec::new();
    for (component, outcome) in discovered {
        match outcome {
            Discovered::Usable(helper) => installed.push(*helper),
            Discovered::ConfiguredUnusable(found) => unusable.push(format!(
                "{} configured at {} cannot be used: {}",
                component.binary,
                found.path.display(),
                found.reason
            )),
            Discovered::InstalledUnusable(found) => unusable.push(format!(
                "{} at {} cannot be used: {}",
                component.binary,
                found.path.display(),
                found.reason
            )),
            Discovered::Absent => absent.push(component),
        }
    }
    if installed.is_empty() {
        let mut said = unusable;
        if !absent.is_empty() {
            said.push(format!(
                "{}: {NOT_FOUND} ({})",
                absent
                    .iter()
                    .map(|component| component.binary)
                    .collect::<Vec<_>>()
                    .join(", "),
                absent
                    .iter()
                    .map(|component| component.advice)
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
        bail!(
            "semantic mode needs a compiler helper that answers: {}",
            said.join("; ")
        );
    }
    let notes = unusable
        .into_iter()
        .map(|why| format!("note: {why}; its languages go unanswered in this run"))
        .collect();
    Ok((installed, notes))
}

/// Keep a helper only after a successful handshake. A silent optional helper
/// is unavailable for its own languages, not a reason to discard answers from
/// another helper that did answer.
#[cfg(test)]
pub(super) fn installed_helper(
    component: doctor::HelperComponent,
    facts: doctor::HelperFacts,
    permitted: &ExecutionPolicy,
    sandbox: SandboxRequest,
) -> Option<Installed> {
    match Discovered::of(component, None, Some(facts), permitted, sandbox) {
        Discovered::Usable(helper) => Some(*helper),
        _ => None,
    }
}

/// The helpers this run will put files to, or `None` when it asks nobody.
///
/// Decided after discovery, because which helpers have anything to answer about
/// is a fact about the tree. The same answer serves both the identity the
/// results are filed under and the asking itself, which is what keeps a run from
/// being identified by a compiler it never put a file to.
///
/// # Errors
///
/// Fails when the tree holds sources and no installed helper reads any of their
/// languages. Semantic mode does not fall back to Structural: a run that
/// answered without a compiler and called itself semantic would be syntactic
/// results under another name. An empty tree is not that — nothing to scan and
/// nothing to scan it with are different, and only the second is a problem.
pub(super) fn asking_about<'a>(
    compilers: Option<&'a Compilers>,
    sources: &[SourceUnit],
) -> Result<Option<Vec<&'a Installed>>> {
    let present = languages_in(sources);
    let asking = compilers.map(|compilers| compilers.at_work(present));
    if let Some(asking) = &asking
        && asking.is_empty()
        && !sources.is_empty()
    {
        bail!(
            "semantic mode found no helper that reads {}; \
             `codehelion doctor` lists which languages each helper answers about, \
             and `--mode structural` analyses this tree without one",
            present
                .enabled()
                .into_iter()
                .map(Language::name)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(asking)
}

/// The languages the tree turned out to hold.
pub(super) fn languages_in(sources: &[SourceUnit]) -> LanguageSelection {
    let mut present = LanguageSelection {
        rust: false,
        c: false,
        cpp: false,
    };
    for source in sources {
        match source.language {
            Language::Rust => present.rust = true,
            Language::C => present.c = true,
            Language::Cpp => present.cpp = true,
        }
    }
    present
}

/// The permitted classes as the protocol names them, keeping the ones this
/// helper said it acts on.
///
/// The greeting carries the classes as strings, so the round trip through the
/// protocol's own spelling is also what checks that both sides mean the same
/// class by the same word.
///
/// Narrowed per helper rather than refused: one permission can be meaningful
/// for one helper and meaningless for another — the Clang helper runs nothing
/// out of a project whatever it is allowed — and refusing on behalf of all of
/// them would make permitting anything at all impossible as soon as a helper
/// that runs nothing is installed.
pub(super) fn acted_on(permitted: &ExecutionPolicy, greeting: &doctor::Greeting) -> Vec<Execution> {
    permitted
        .permitted()
        .into_iter()
        .filter(|class| greeting.executes.iter().any(|acts| acts == class.name()))
        .filter_map(|class| Execution::from_name(class.name()))
        .collect()
}

/// Explain why permitting a recognised class cannot affect this scan.
pub(super) fn unavailable_execution_message(class: PermittedExecution) -> String {
    format!(
        "execution class {} is not implemented by any compiler helper available to this scan; \
         --allow-execution={} cannot take effect. The bundled helpers currently implement only \
         build-script, so installing another copy will not enable {}. `codehelion doctor` lists \
         each helper's execution capabilities",
        class.name(),
        class.name(),
        class.name()
    )
}

/// The configured ceiling for every compiler-helper response.
pub(super) const fn helper_timeout(cfg: &Config) -> std::time::Duration {
    std::time::Duration::from_millis(cfg.limits.helper_timeout_ms)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use codehelion_core::doctor::{CLANG_HELPER, Greeting, HelperFacts, HelperState, RUST_HELPER};

    fn discovered(
        component: doctor::HelperComponent,
        configured: Option<&Path>,
        facts: Option<HelperFacts>,
    ) -> (doctor::HelperComponent, Discovered) {
        (
            component,
            Discovered::of(
                component,
                configured,
                facts,
                &ExecutionPolicy::deny_all(),
                SandboxRequest::unrestricted(),
            ),
        )
    }

    fn answering(path: &str) -> HelperFacts {
        HelperFacts {
            path: PathBuf::from(path),
            state: HelperState::Answered(Greeting {
                version: "1.0.0".to_owned(),
                protocol: 2,
                toolchains: vec!["rust-analyzer".to_owned()],
                capabilities: vec!["types".to_owned()],
                executes: Vec::new(),
            }),
        }
    }

    fn silent(path: &str, reason: &str) -> HelperFacts {
        HelperFacts {
            path: PathBuf::from(path),
            state: HelperState::Silent(reason.to_owned()),
        }
    }

    fn refusal(outcomes: Vec<(doctor::HelperComponent, Discovered)>) -> String {
        match settled(outcomes) {
            Ok(_) => panic!("no helper is usable, so discovery must fail"),
            Err(error) => format!("{error:#}"),
        }
    }

    #[test]
    fn a_found_helper_that_cannot_be_used_is_named_with_its_reason_and_not_called_missing() {
        let text = refusal(vec![
            discovered(
                RUST_HELPER,
                None,
                Some(silent("/tool/codehelion-backend-rust", "speaks protocol 3")),
            ),
            discovered(CLANG_HELPER, None, None),
        ]);
        assert!(text.contains("/tool/codehelion-backend-rust"), "{text}");
        assert!(text.contains("speaks protocol 3"), "{text}");
        assert!(
            text.contains(&format!("codehelion-backend-clang: {NOT_FOUND}")),
            "{text}"
        );
        assert!(
            !text.contains(&format!("codehelion-backend-rust: {NOT_FOUND}")),
            "{text}"
        );
    }

    #[test]
    fn a_configured_location_with_no_program_is_named_whether_or_not_another_helper_answers() {
        let missing = Path::new("/nonexistent/codehelion-backend-rust");
        let configured = || {
            let facts = crate::interrogate(
                RUST_HELPER.binary,
                Some(missing),
                SandboxRequest::unrestricted(),
            );
            assert!(facts.is_some(), "a configured location is never absent");
            discovered(RUST_HELPER, Some(missing), facts)
        };
        let alone = refusal(vec![configured(), discovered(CLANG_HELPER, None, None)]);
        assert!(
            alone.contains("/nonexistent/codehelion-backend-rust"),
            "{alone}"
        );
        assert!(alone.contains("configured"), "{alone}");

        let (installed, notes) = settled(vec![
            configured(),
            discovered(
                CLANG_HELPER,
                None,
                Some(answering("/tool/codehelion-backend-clang")),
            ),
        ])
        .expect("the answering helper is usable");
        assert_eq!(installed.len(), 1);
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(
            notes[0].contains("/nonexistent/codehelion-backend-rust"),
            "{notes:?}"
        );
    }

    #[test]
    fn an_unusable_helper_beside_an_answering_one_leaves_a_note_with_its_reason() {
        let (installed, notes) = settled(vec![
            discovered(
                RUST_HELPER,
                None,
                Some(answering("/tool/codehelion-backend-rust")),
            ),
            discovered(
                CLANG_HELPER,
                None,
                Some(silent("/tool/codehelion-backend-clang", "no libclang")),
            ),
        ])
        .expect("the answering helper is usable");
        assert_eq!(installed.len(), 1);
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].contains("no libclang"), "{notes:?}");
    }

    #[test]
    fn only_helpers_that_were_not_found_are_described_as_missing() {
        let text = refusal(vec![
            discovered(RUST_HELPER, None, None),
            discovered(CLANG_HELPER, None, None),
        ]);
        assert!(
            text.contains(&format!(
                "codehelion-backend-rust, codehelion-backend-clang: {NOT_FOUND}"
            )),
            "{text}"
        );
    }

    fn installed_with(sandbox: SandboxRequest) -> Installed {
        match Discovered::of(
            RUST_HELPER,
            None,
            Some(answering("/tool/codehelion-backend-rust")),
            &ExecutionPolicy::deny_all(),
            sandbox,
        ) {
            Discovered::Usable(helper) => *helper,
            _ => panic!("an answering helper is usable"),
        }
    }

    #[test]
    fn a_lockfile_is_hashed_only_when_it_is_a_regular_file_within_the_ceiling() {
        let directory = tempfile::tempdir().unwrap();
        let lock = directory.path().join("Cargo.lock");
        std::fs::write(&lock, "version = 4\n").unwrap();
        assert!(
            installed_with(SandboxRequest::unrestricted())
                .lockfile_hash(directory.path())
                .is_some()
        );
        assert!(
            installed_with(SandboxRequest::unrestricted().with_file_ceiling(4))
                .lockfile_hash(directory.path())
                .is_none(),
            "a lockfile over the ceiling is not read"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_lockfile_planted_as_a_link_or_a_fifo_is_not_read() {
        let directory = tempfile::tempdir().unwrap();
        let lock = directory.path().join("Cargo.lock");
        std::os::unix::fs::symlink("/dev/zero", &lock).unwrap();
        let helper = installed_with(SandboxRequest::unrestricted());
        assert!(helper.lockfile_hash(directory.path()).is_none());

        std::fs::remove_file(&lock).unwrap();
        #[allow(clippy::disallowed_types)]
        let made = std::process::Command::new("mkfifo")
            .arg(&lock)
            .status()
            .unwrap();
        assert!(made.success());
        assert!(helper.lockfile_hash(directory.path()).is_none());
    }
}
