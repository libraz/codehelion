//! The wire format core and helpers agree on.
//!
//! Everything here is data: no process is spawned and no compiler is linked.
//! A helper binary depends on this module to speak the protocol and on nothing
//! else of codehelion, which is what keeps a toolchain dependency from reaching
//! the analysis crates.
//!
//! # Framing
//!
//! Messages travel over the helper's standard input and output as
//! length-prefixed frames: a four-byte big-endian payload length, a one-byte
//! encoding tag, then the payload. The tag exists so that compiler IR too large
//! to be worth serializing as text can travel as bytes later without changing
//! how a frame is found in the stream — only [`Encoding`] gains a variant.
//!
//! A frame carries its own length so a reader never has to guess where a
//! message ends, and never has to trust the sender's promise about total
//! volume: [`MAX_FRAME_BYTES`] bounds what one frame may ask a reader to
//! allocate, so a helper that has gone wrong cannot exhaust memory before it is
//! noticed.

use std::io::{Read, Write};

use serde::{Deserialize, Serialize};

use crate::ir::{CompilerIr, Unavailability, UnitRef};

/// The only protocol revision this build speaks.
///
/// The product has not been released, so clients and helpers use the complete
/// current protocol directly.
pub const PROTOCOL_VERSION: u32 = 1;

/// Largest payload a single frame may declare.
///
/// A reader allocates what the header says before it has seen the body, so
/// this is the ceiling on what one malformed or hostile frame can cost.
pub const MAX_FRAME_BYTES: u32 = 64 * 1024 * 1024;

/// How a frame's payload is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum Encoding {
    /// UTF-8 JSON. The only encoding this revision writes.
    Json = 0,
}

impl Encoding {
    /// The tag byte written into the frame header.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// The encoding a tag byte names, or `None` if this build has no such
    /// encoding — which is how a frame from a newer peer is refused rather
    /// than misread.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Json),
            _ => None,
        }
    }
}

/// Something a helper can be asked for.
///
/// A helper reports the subset it can supply during the handshake, and a run
/// asks for nothing outside that subset. The variants are the information
/// kinds semantic analysis is built from; a helper that offers fewer is not
/// broken, it is less capable, and [`Capability::absence`] says what that costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Resolved types for expressions and bindings.
    Types,
    /// Which definition each name refers to, and whether it is outside the
    /// scanned code.
    NameResolution,
    /// Resolved call targets.
    CallTargets,
    /// A control-flow graph built from the compiler's own.
    MirCfg,
    /// Macro expansion with both spelling and expansion locations.
    MacroExpansion,
    /// Template or generic instantiation traced to its definition.
    TemplateInstantiation,
}

/// What a run does when a helper cannot supply a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Absence {
    /// Continue without it, recording what was not available.
    Degrade,
    /// Refuse semantic analysis: without this the result would be a weaker
    /// answer wearing a stronger name.
    Refuse,
}

impl Capability {
    /// Every capability this protocol revision understands.
    pub const ALL: [Self; 6] = [
        Self::Types,
        Self::NameResolution,
        Self::CallTargets,
        Self::MirCfg,
        Self::MacroExpansion,
        Self::TemplateInstantiation,
    ];

    /// Stable lowercase identifier, the same spelling this serializes as.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Types => "types",
            Self::NameResolution => "name_resolution",
            Self::CallTargets => "call_targets",
            Self::MirCfg => "mir_cfg",
            Self::MacroExpansion => "macro_expansion",
            Self::TemplateInstantiation => "template_instantiation",
        }
    }

    /// What its absence costs.
    ///
    /// Two are load-bearing, for the same reason stated twice. Semantic mode
    /// exists to answer with what the compiler knows rather than with what the
    /// text looks like: without resolved types a run reports syntactic findings
    /// under a semantic label, and without name resolution it decides which
    /// names to compare on by guessing from their spelling, which is the
    /// structural answer wearing the same stronger name.
    ///
    /// Everything else refines an answer those two make possible in the first
    /// place, so missing any of them narrows the result rather than misnaming
    /// it.
    #[must_use]
    pub const fn absence(self) -> Absence {
        match self {
            Self::Types | Self::NameResolution => Absence::Refuse,
            Self::CallTargets
            | Self::MirCfg
            | Self::MacroExpansion
            | Self::TemplateInstantiation => Absence::Degrade,
        }
    }
}

/// A message from core to a helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// The revision this message is written in.
    pub protocol_version: u32,
    /// Correlates a response with the request that asked for it.
    pub id: u64,
    /// What is being asked.
    pub body: RequestBody,
}

/// The askable things.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RequestBody {
    /// Identify yourself and say what you can do.
    Handshake(ClientIdentity),
    /// Say what the code in a tree is analyzed under.
    ///
    /// Asked before any unit is, because what a run records its answers under
    /// has to be settled before there are answers to record.
    DescribeBuild(DescribeBuild),
    /// Analyze one unit and return what the compiler knows about it.
    Analyze(Analyze),
    /// Finish outstanding work and exit.
    Shutdown,
}

/// The tree whose build is being asked about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescribeBuild {
    /// A directory inside the project, as this machine spells it.
    ///
    /// Not necessarily the project's own root: a scan can be rooted at one
    /// member of a workspace, and finding the project from there is the
    /// helper's job because it is the side that knows what a project is.
    pub root: String,
}

/// The conditions a tree's code is analyzed under.
///
/// What belongs here is what changes the answers rather than what changes the
/// build: two runs that resolve the same names to the same things are one
/// variant however differently they were invoked, and two that do not are two
/// however alike the command line looked.
///
/// Empty on both counts when the helper found no project to describe. That is
/// not the same claim as a project that enables nothing — a described build
/// always has settings, because the target alone supplies a dozen — so nothing
/// has to be spelled to tell the two apart.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildDescription {
    /// Enabled features, each qualified by the package that enables it.
    ///
    /// Qualified because a feature is declared per package: `serde/derive` and
    /// `ledger/derive` are unrelated facts, and an unqualified list would let
    /// one package's selection stand in for another's.
    pub features: Vec<String>,
    /// The conditional-compilation settings the code is read under, as the
    /// compiler spells them.
    pub cfgs: Vec<String>,
}

/// One unit to analyze, and what is wanted from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Analyze {
    /// Which unit.
    pub unit: UnitRef,
    /// The exact compilation-database entry to use for a C or C++ request.
    ///
    /// A source path is not enough: a database may intentionally list it more
    /// than once under different `-D` settings. This carries the complete
    /// recorded command identity rather than a database index, because an
    /// index changes when an unrelated command is inserted or reordered.
    pub compile_command: Option<CompileCommandSelector>,
    /// Canonical scan-root boundary for paths a compilation command may read.
    ///
    /// Set only for an untrusted scan. Helpers must refuse path-bearing
    /// compiler arguments that resolve outside this directory; omitting it
    /// preserves the configured, trusted compilation-database behaviour.
    pub read_boundary: Option<String>,
    /// What to spend time on.
    ///
    /// Never more than the helper offered at handshake. Asking for less than it
    /// can do is how a run that needs only types avoids paying for a
    /// control-flow graph nobody will read.
    pub want: Vec<Capability>,
    /// What the helper may run out of the project while answering.
    ///
    /// Empty unless somebody said otherwise.
    pub permitted: Vec<Execution>,
}

/// One stable, exact selector for an entry in `compile_commands.json`.
///
/// The path is the entry's source after resolving it against `directory`; the
/// command remains one argument per element so quoting cannot alter its
/// meaning between the scanner and helper. Together they name one database
/// entry without relying on its position in a generated file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompileCommandSelector {
    /// The translation-unit source path.
    pub file: String,
    /// The command's working directory, when the database recorded one.
    pub directory: Option<String>,
    /// The recorded compiler invocation, including its compiler and source.
    pub arguments: Vec<String>,
}

impl CompileCommandSelector {
    /// Whether this and `other` name one entry of one compilation database.
    ///
    /// Not derived equality, because the two are built by two programs out of
    /// one database and their paths are two resolvings of one file. Those are
    /// compared as paths, and past a Windows verbatim prefix that only one of
    /// the two need have come back carrying — where they are compared as
    /// strings instead, no entry matches any request and every unit of a C or
    /// C++ project comes back with no build information.
    ///
    /// The arguments are compared exactly: they are the words the database
    /// recorded, which neither side resolved and neither side may reword.
    #[must_use]
    pub fn names_the_same_entry(&self, other: &Self) -> bool {
        fn one_path(left: &str, right: &str) -> bool {
            crate::ir::ordinary(std::path::Path::new(left))
                == crate::ir::ordinary(std::path::Path::new(right))
        }
        self.arguments == other.arguments
            && one_path(&self.file, &other.file)
            && match (self.directory.as_deref(), other.directory.as_deref()) {
                (Some(mine), Some(theirs)) => one_path(mine, theirs),
                (None, None) => true,
                _ => false,
            }
    }
}

/// Something a helper may be permitted to run out of the project it is
/// analyzing.
///
/// Named per class rather than as one switch, for the reason the tool's own
/// permissions are: expanding a macro the project's developers already run and
/// executing a configure step that may reach the network are decisions of
/// different weight, and a single permission would make agreeing to either mean
/// agreeing to both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Execution {
    /// A Cargo build script.
    BuildScript,
    /// A procedural macro, expanded by compiling and calling it.
    ProcMacro,
    /// A configure step: `CMake`, autotools, or a generator script.
    Configure,
    /// A compiler wrapper the project interposes.
    CompilerWrapper,
    /// A command that generates source files.
    GeneratedSource,
}

impl Execution {
    /// Stable identifier, the same spelling this serializes as and the same
    /// one a person types to permit it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BuildScript => "build-script",
            Self::ProcMacro => "proc-macro",
            Self::Configure => "configure",
            Self::CompilerWrapper => "compiler-wrapper",
            Self::GeneratedSource => "generated-source",
        }
    }

    /// The class a name refers to, or `None` for one this build cannot name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        [
            Self::BuildScript,
            Self::ProcMacro,
            Self::Configure,
            Self::CompilerWrapper,
            Self::GeneratedSource,
        ]
        .into_iter()
        .find(|class| class.name() == name)
    }
}

/// Who is connecting, and which revisions it can speak.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientIdentity {
    /// Name of the connecting program.
    pub client: String,
    /// Its version, for diagnostics rather than for negotiation.
    pub client_version: String,
    /// The exact protocol revision it speaks.
    pub protocol: u32,
}

/// A message from a helper to core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    /// The revision this message is written in.
    pub protocol_version: u32,
    /// The request this answers.
    pub id: u64,
    /// The answer.
    pub body: ResponseBody,
}

/// The answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResponseBody {
    /// Who the helper is and what it can do.
    Handshake(Box<HelperIdentity>),
    /// What the tree's code is analyzed under.
    Build(Box<BuildDescription>),
    /// What the compiler knows about the unit.
    Analyzed(Box<CompilerIr>),
    /// Nothing can be known about the unit, and why.
    ///
    /// Distinct from [`ResponseBody::Failed`]: the helper is working, and this
    /// unit is one it cannot analyze. A scan carries on and says so.
    Unavailable {
        /// Which unit.
        unit: UnitRef,
        /// Why it cannot be analyzed.
        reason: Unavailability,
    },
    /// Shutdown acknowledged.
    Shutdown,
    /// The request could not be answered.
    Failed(Failure),
}

/// What a helper says about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperIdentity {
    /// Helper name, as `doctor` reports it.
    pub name: String,
    /// Helper version.
    pub version: String,
    /// The exact protocol revision it speaks.
    pub protocol: u32,
    /// The toolchains it was built against, as the compiler spells them.
    ///
    /// A helper built for one compiler release cannot be trusted against
    /// another, so this is matched against the project's own toolchain rather
    /// than assumed compatible.
    pub toolchains: Vec<String>,
    /// What it can supply.
    pub capabilities: Vec<Capability>,
    /// The classes of execution it will act on when it is permitted them.
    ///
    /// Stated so that permitting something this helper would not do can be
    /// refused rather than accepted and forgotten. A permission that changes
    /// nothing is worse than one that is turned down: somebody granted it, and
    /// the thin answer that follows looks like the project's own.
    pub executes: Vec<Execution>,
}

/// Why a request could not be answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    /// A stable short code for programmatic handling.
    pub code: String,
    /// What went wrong, for a person.
    pub message: String,
}

/// Something that went wrong reading or writing a frame.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The stream ended where a frame was expected.
    #[error("the stream ended mid-frame")]
    Truncated,
    /// The header named a payload larger than [`MAX_FRAME_BYTES`].
    #[error("a frame declared {declared} bytes, over the {MAX_FRAME_BYTES} ceiling")]
    TooLarge {
        /// What the header claimed.
        declared: u32,
    },
    /// The header named an encoding this build does not have.
    #[error("a frame arrived in unknown encoding {tag}")]
    UnknownEncoding {
        /// The tag byte that was read.
        tag: u8,
    },
    /// The payload was not the message it claimed to be.
    #[error("a frame's payload did not parse: {0}")]
    Malformed(#[from] serde_json::Error),
    /// The underlying stream failed.
    #[error("the stream failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Header length: four bytes of payload length plus one encoding tag.
const HEADER_BYTES: usize = 5;

/// Write `value` as one JSON frame.
///
/// # Errors
///
/// Fails if the value cannot be serialized or the stream cannot take it.
pub fn write_frame<W: Write, T: Serialize>(writer: &mut W, value: &T) -> Result<(), FrameError> {
    let payload = serde_json::to_vec(value)?;
    let length =
        u32::try_from(payload.len()).map_err(|_| FrameError::TooLarge { declared: u32::MAX })?;
    if length > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge { declared: length });
    }
    let mut header = [0u8; HEADER_BYTES];
    header[..4].copy_from_slice(&length.to_be_bytes());
    header[4] = Encoding::Json.tag();
    writer.write_all(&header)?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

/// Read one frame and parse it.
///
/// Returns `Ok(None)` when the stream ends cleanly between frames, which is how
/// a peer that has finished is told apart from one that died mid-message.
///
/// # Errors
///
/// Fails on a truncated frame, an oversized or unknown-encoding header, a
/// payload that does not parse, or a stream error.
pub fn read_frame<R: Read, T: for<'de> Deserialize<'de>>(
    reader: &mut R,
) -> Result<Option<T>, FrameError> {
    let mut header = [0u8; HEADER_BYTES];
    match read_exact_or_eof(reader, &mut header)? {
        Read0::Eof => return Ok(None),
        Read0::Partial => return Err(FrameError::Truncated),
        Read0::Full => {}
    }
    let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    if length > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge { declared: length });
    }
    if Encoding::from_tag(header[4]).is_none() {
        return Err(FrameError::UnknownEncoding { tag: header[4] });
    }
    let mut payload = vec![0u8; length as usize];
    match read_exact_or_eof(reader, &mut payload)? {
        Read0::Full => {}
        Read0::Eof | Read0::Partial => return Err(FrameError::Truncated),
    }
    Ok(Some(serde_json::from_slice(&payload)?))
}

/// How much of a buffer a read managed to fill.
enum Read0 {
    /// Nothing at all: the stream ended between frames.
    Eof,
    /// Some but not all: the stream ended inside a frame.
    Partial,
    /// All of it.
    Full,
}

fn read_exact_or_eof<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<Read0, std::io::Error> {
    let mut filled = 0;
    while filled < buffer.len() {
        let read = reader.read(&mut buffer[filled..])?;
        if read == 0 {
            return Ok(if filled == 0 {
                Read0::Eof
            } else {
                Read0::Partial
            });
        }
        filled += read;
    }
    Ok(Read0::Full)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn identity() -> HelperIdentity {
        HelperIdentity {
            name: "mock".into(),
            version: "0.1.0".into(),
            protocol: PROTOCOL_VERSION,
            toolchains: vec!["rustc 1.85.0".into()],
            capabilities: vec![Capability::Types, Capability::CallTargets],
            executes: vec![Execution::BuildScript],
        }
    }

    #[test]
    fn a_frame_survives_the_round_trip() {
        let message = Response {
            protocol_version: PROTOCOL_VERSION,
            id: 7,
            body: ResponseBody::Handshake(Box::new(identity())),
        };
        let mut buffer = Vec::new();
        write_frame(&mut buffer, &message).unwrap();
        let back: Option<Response> = read_frame(&mut buffer.as_slice()).unwrap();
        assert_eq!(back, Some(message));
    }

    #[test]
    fn frames_are_read_one_at_a_time_from_one_stream() {
        let mut buffer = Vec::new();
        for id in 0..3u64 {
            write_frame(
                &mut buffer,
                &Response {
                    protocol_version: PROTOCOL_VERSION,
                    id,
                    body: ResponseBody::Shutdown,
                },
            )
            .unwrap();
        }
        let mut stream = buffer.as_slice();
        for id in 0..3u64 {
            let message: Response = read_frame(&mut stream).unwrap().unwrap();
            assert_eq!(message.id, id);
        }
        assert!(read_frame::<_, Response>(&mut stream).unwrap().is_none());
    }

    #[test]
    fn a_stream_that_ends_between_frames_is_not_an_error() {
        let empty: &[u8] = &[];
        assert!(read_frame::<_, Response>(&mut { empty }).unwrap().is_none());
    }

    #[test]
    fn a_stream_that_ends_inside_a_frame_is_an_error() {
        let mut buffer = Vec::new();
        write_frame(
            &mut buffer,
            &Response {
                protocol_version: PROTOCOL_VERSION,
                id: 1,
                body: ResponseBody::Shutdown,
            },
        )
        .unwrap();
        buffer.truncate(buffer.len() - 1);
        let error = read_frame::<_, Response>(&mut buffer.as_slice()).unwrap_err();
        assert!(matches!(error, FrameError::Truncated), "{error:?}");
    }

    #[test]
    fn an_oversized_header_is_refused_before_anything_is_allocated() {
        let mut header = [0u8; HEADER_BYTES];
        header[..4].copy_from_slice(&(MAX_FRAME_BYTES + 1).to_be_bytes());
        let error = read_frame::<_, Response>(&mut header.as_slice()).unwrap_err();
        assert!(matches!(error, FrameError::TooLarge { .. }), "{error:?}");
    }

    #[test]
    fn an_encoding_this_build_lacks_is_refused_rather_than_guessed() {
        let mut buffer = Vec::new();
        write_frame(
            &mut buffer,
            &Response {
                protocol_version: PROTOCOL_VERSION,
                id: 1,
                body: ResponseBody::Shutdown,
            },
        )
        .unwrap();
        buffer[4] = 9;
        let error = read_frame::<_, Response>(&mut buffer.as_slice()).unwrap_err();
        assert!(
            matches!(error, FrameError::UnknownEncoding { tag: 9 }),
            "{error:?}"
        );
    }

    /// One spelling, kept in one place. A stored capability and a transmitted
    /// one that disagree would make a database written by this build unreadable
    /// by it.
    #[test]
    fn what_a_capability_is_called_is_what_it_is_sent_as() {
        for capability in Capability::ALL {
            let sent = serde_json::to_string(&capability).unwrap();
            assert_eq!(sent, format!("\"{}\"", capability.name()));
        }
    }

    /// The same rule as for capabilities, and for the same reason: what is
    /// stored, what is typed and what is sent are one spelling.
    #[test]
    fn what_an_execution_class_is_called_is_what_it_is_sent_as() {
        for class in [
            Execution::BuildScript,
            Execution::ProcMacro,
            Execution::Configure,
            Execution::CompilerWrapper,
            Execution::GeneratedSource,
        ] {
            let sent = serde_json::to_string(&class).unwrap();
            assert_eq!(sent, format!("\"{}\"", class.name()));
        }
    }

    /// A name nobody recognises is not a class. Reading it as the catch-all
    /// would let a misspelling travel as a permission, and the whole point of
    /// naming classes is that granting one grants exactly one.
    #[test]
    fn a_class_nobody_can_name_is_not_read_as_the_one_with_no_name() {
        assert_eq!(
            Execution::from_name("build-script"),
            Some(Execution::BuildScript)
        );
        assert_eq!(Execution::from_name("build-scripts"), None);
        assert_eq!(Execution::from_name("unknown"), None);
        assert!(
            serde_json::from_str::<Vec<Execution>>(r#"["build-script","something-newer"]"#)
                .is_err()
        );
    }

    #[test]
    fn a_capability_this_build_cannot_name_is_rejected() {
        assert!(
            serde_json::from_str::<Vec<Capability>>(r#"["types","overload_resolution"]"#).is_err()
        );
    }

    /// The two that decide what a comparison is made of. Everything else
    /// sharpens a comparison that these make possible at all.
    #[test]
    fn what_a_comparison_is_made_of_is_worth_refusing_over() {
        assert_eq!(Capability::Types.absence(), Absence::Refuse);
        assert_eq!(Capability::NameResolution.absence(), Absence::Refuse);
        for capability in [
            Capability::CallTargets,
            Capability::MirCfg,
            Capability::MacroExpansion,
            Capability::TemplateInstantiation,
        ] {
            assert_eq!(capability.absence(), Absence::Degrade, "{capability:?}");
        }
    }

    fn selector(file: &str, directory: Option<&str>) -> CompileCommandSelector {
        CompileCommandSelector {
            file: file.to_owned(),
            directory: directory.map(ToOwned::to_owned),
            arguments: vec!["clang++".into(), "-c".into(), "a.cpp".into()],
        }
    }

    /// The scanner and the helper each resolve the database's paths for
    /// themselves, and one of them coming back with the verbatim form is a
    /// difference in how the path was written down rather than in which file
    /// it names.
    #[test]
    fn one_entry_resolved_by_two_programs_is_one_entry() {
        let plain = selector("C:/w/a.cpp", Some("C:/w"));
        let verbatim = selector(r"\\?\C:/w/a.cpp", Some(r"\\?\C:/w"));
        assert!(plain.names_the_same_entry(&verbatim));
        assert!(verbatim.names_the_same_entry(&plain));
        assert!(plain.names_the_same_entry(&plain));
    }

    /// A database may list one source more than once under different settings,
    /// which is the whole reason a selector carries the command.
    #[test]
    fn two_commands_over_one_source_are_two_entries() {
        let mut other = selector("C:/w/a.cpp", Some("C:/w"));
        other.arguments.push("-DWIDE".into());
        assert!(!selector("C:/w/a.cpp", Some("C:/w")).names_the_same_entry(&other));
        assert!(
            !selector("C:/w/a.cpp", Some("C:/w"))
                .names_the_same_entry(&selector("C:/w/b.cpp", Some("C:/w")))
        );
        assert!(
            !selector("C:/w/a.cpp", Some("C:/w"))
                .names_the_same_entry(&selector("C:/w/a.cpp", None))
        );
    }
}
