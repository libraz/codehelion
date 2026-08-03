//! Compiler-helper discovery, capability checks, and sandbox requests.

use super::{
    BuildConfiguration, Config, Context, CppBuild, Execution, ExecutionPolicy, Helper, Language,
    LanguageSelection, Path, PathBuf, PermittedExecution, Result, RustBuild, SandboxRequest,
    ScanArgs, SourceUnit, bail, content_hash, doctor,
};

pub(super) fn semantic_sandbox(args: &ScanArgs) -> Result<SandboxRequest> {
    if !args.untrusted {
        return Ok(SandboxRequest::unrestricted());
    }
    let Some(bytes) = codehelion_core::execution::Limits::untrusted().max_subprocess_bytes else {
        bail!("the untrusted profile must require a subprocess memory ceiling");
    };
    let request = SandboxRequest::require_memory_limit(bytes);
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
                lockfile_hash: std::fs::read_to_string(root.join("Cargo.lock"))
                    .ok()
                    .map(|text| content_hash(&text)),
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
        let mut installed = Vec::new();
        for component in doctor::OPTIONAL_HELPERS {
            let configured = match component.binary {
                "codehelion-backend-rust" => paths.rust.as_deref(),
                "codehelion-backend-clang" => paths.clang.as_deref(),
                _ => None,
            };
            let Some(facts) = crate::interrogate(component.binary, configured, sandbox) else {
                continue;
            };
            if let Some(helper) = installed_helper(component, facts, permitted, sandbox) {
                installed.push(helper);
            }
        }
        if installed.is_empty() {
            bail!(
                "semantic mode needs a compiler helper, and there is none beside \
                 this program or on PATH: {}",
                doctor::OPTIONAL_HELPERS
                    .iter()
                    .map(|component| component.advice)
                    .collect::<Vec<_>>()
                    .join("; ")
            );
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

/// Keep a helper only after a successful handshake. A silent optional helper
/// is unavailable for its own languages, not a reason to discard answers from
/// another helper that did answer.
pub(super) fn installed_helper(
    component: doctor::HelperComponent,
    facts: doctor::HelperFacts,
    permitted: &ExecutionPolicy,
    sandbox: SandboxRequest,
) -> Option<Installed> {
    let doctor::HelperState::Answered(greeting) = facts.state else {
        return None;
    };
    Some(Installed {
        permitted: acted_on(permitted, &greeting),
        component,
        program: facts.path,
        greeting,
        sandbox,
    })
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
