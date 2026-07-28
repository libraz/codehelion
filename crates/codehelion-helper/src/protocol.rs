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

/// The protocol revision this build speaks.
///
/// Bumped when a change would make an older peer misread a message. Additive
/// fields with defaults do not need it; removing or repurposing one does.
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

/// An inclusive range of protocol revisions a peer can speak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionRange {
    /// Oldest revision understood.
    pub min: u32,
    /// Newest revision understood.
    pub max: u32,
}

impl VersionRange {
    /// The range that accepts exactly `version`.
    #[must_use]
    pub const fn exactly(version: u32) -> Self {
        Self {
            min: version,
            max: version,
        }
    }

    /// Whether `version` falls inside this range.
    #[must_use]
    pub const fn accepts(self, version: u32) -> bool {
        self.min <= version && version <= self.max
    }

    /// The newest revision both ranges accept.
    ///
    /// Negotiation picks the highest rather than the lowest common revision:
    /// an older revision is kept only for peers that cannot do better, so
    /// choosing it when both sides can do better would freeze every pair at
    /// the oldest thing anyone still supports.
    #[must_use]
    pub const fn best_common(self, other: Self) -> Option<u32> {
        let low = if self.min > other.min {
            self.min
        } else {
            other.min
        };
        let high = if self.max < other.max {
            self.max
        } else {
            other.max
        };
        if low <= high { Some(high) } else { None }
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
    /// Resolved call targets.
    CallTargets,
    /// A control-flow graph built from the compiler's own.
    MirCfg,
    /// Macro expansion with both spelling and expansion locations.
    MacroExpansion,
    /// Template or generic instantiation traced to its definition.
    TemplateInstantiation,
    /// Which overload a call resolved to.
    OverloadResolution,
    /// A capability this build has no name for.
    ///
    /// A newer helper may offer more than this build knows to ask for. Folding
    /// those into one variant keeps the handshake parseable; nothing requests
    /// them, so nothing depends on telling them apart.
    #[serde(other)]
    Unknown,
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
    /// What its absence costs.
    ///
    /// Only resolved types are load-bearing. Semantic mode exists to answer
    /// with what the compiler knows rather than with what the text looks like,
    /// and every other capability here refines an answer that types make
    /// possible in the first place. Missing any of those narrows the result;
    /// missing types would leave a run that reports syntactic findings under a
    /// semantic label, which is worse than not running.
    #[must_use]
    pub const fn absence(self) -> Absence {
        match self {
            Self::Types => Absence::Refuse,
            Self::CallTargets
            | Self::MirCfg
            | Self::MacroExpansion
            | Self::TemplateInstantiation
            | Self::OverloadResolution
            | Self::Unknown => Absence::Degrade,
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
    /// Finish outstanding work and exit.
    Shutdown,
}

/// Who is connecting, and which revisions it can speak.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientIdentity {
    /// Name of the connecting program.
    pub client: String,
    /// Its version, for diagnostics rather than for negotiation.
    pub client_version: String,
    /// The revisions it can speak.
    pub accepts: VersionRange,
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
    /// The protocol revisions it can speak.
    pub protocol: VersionRange,
    /// The toolchains it was built against, as the compiler spells them.
    ///
    /// A helper built for one compiler release cannot be trusted against
    /// another, so this is matched against the project's own toolchain rather
    /// than assumed compatible.
    pub toolchains: Vec<String>,
    /// What it can supply.
    pub capabilities: Vec<Capability>,
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
            protocol: VersionRange::exactly(PROTOCOL_VERSION),
            toolchains: vec!["rustc 1.85.0".into()],
            capabilities: vec![Capability::Types, Capability::CallTargets],
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

    #[test]
    fn negotiation_takes_the_newest_revision_both_sides_can_speak() {
        let core = VersionRange { min: 1, max: 3 };
        let helper = VersionRange { min: 2, max: 5 };
        assert_eq!(core.best_common(helper), Some(3));
        assert_eq!(helper.best_common(core), Some(3));
    }

    #[test]
    fn ranges_that_do_not_meet_have_no_common_revision() {
        let core = VersionRange { min: 4, max: 5 };
        let helper = VersionRange { min: 1, max: 3 };
        assert_eq!(core.best_common(helper), None);
    }

    #[test]
    fn a_capability_this_build_cannot_name_still_parses() {
        let listed: Vec<Capability> =
            serde_json::from_str(r#"["types","something_from_a_newer_helper"]"#).unwrap();
        assert_eq!(listed, vec![Capability::Types, Capability::Unknown]);
    }

    #[test]
    fn only_resolved_types_are_worth_refusing_over() {
        assert_eq!(Capability::Types.absence(), Absence::Refuse);
        for capability in [
            Capability::CallTargets,
            Capability::MirCfg,
            Capability::MacroExpansion,
            Capability::TemplateInstantiation,
            Capability::OverloadResolution,
            Capability::Unknown,
        ] {
            assert_eq!(capability.absence(), Absence::Degrade, "{capability:?}");
        }
    }
}
