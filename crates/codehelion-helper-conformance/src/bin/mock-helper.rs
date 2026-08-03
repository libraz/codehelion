//! A helper that misbehaves on request, so the client's failure paths can be
//! tested against a real process rather than against a fake stream.
//!
//! The ways a helper can go wrong are the point of the client, and none of them
//! reproduce in-process: a hung read, a killed child, a broken pipe and a
//! half-written frame are all properties of an operating-system process. So the
//! conformance tests drive this program, and its first argument says how it
//! should behave.
//!
//! ```sh
//! mock-helper well-behaved      # answers correctly
//! mock-helper ancient           # speaks a protocol revision nobody else does
//! mock-helper undescribed       # cannot say what the tree is built with
//! mock-helper inert             # runs nothing, whatever it is permitted
//! mock-helper untyped           # cannot resolve types
//! mock-helper unnamed           # cannot resolve names
//! mock-helper slow              # answers, eventually
//! mock-helper deaf              # never answers
//! mock-helper deaf-after-setup  # establishes the run, then hangs on analysis
//! mock-helper deaf-on-poison    # hangs only for a unit named `poison`
//! mock-helper dies              # exits mid-handshake
//! mock-helper noisy-death       # complains on stderr, then exits
//! mock-helper noisy-stdout       # writes a diagnostic to the protocol stream
//! mock-helper oversized-frame    # declares a response frame over the ceiling
//! mock-helper confused          # answers a request nobody made
//! mock-helper refuses           # answers with a failure
//! mock-helper chatty            # floods its standard error, then exits
//! mock-helper needs-execution   # analyzes nothing: it would have to run code
//! mock-helper wrong-schema      # answers in a schema nobody reads
//! mock-helper wrong-revision-after-setup # changes response protocol on analysis
//! mock-helper wrong-revision-on-poison # changes protocol only for `poison`
//! mock-helper allergic          # dies on any unit whose file is named `poison`
//! ```

use std::io::{Read, Write};
use std::time::Duration;

use codehelion_helper::ir::{
    Anchor, CompilerIr, ResolvedSymbol, ResolvedType, SourceRange, SymbolKind, TypeCategory,
    Unavailability, UnitRef,
};
use codehelion_helper::protocol::{
    BuildDescription, Capability, Execution, Failure, HelperIdentity, MAX_FRAME_BYTES,
    PROTOCOL_VERSION, Request, RequestBody, Response, ResponseBody, read_frame, write_frame,
};

#[allow(
    clippy::too_many_lines,
    reason = "the mock keeps each process-level fault mode visible beside its protocol response"
)]
fn main() {
    let behaviour = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("CODEHELION_MOCK_HELPER_BEHAVIOUR").ok())
        .unwrap_or_default();
    let mut input = std::io::stdin();
    let mut output = std::io::stdout();

    if behaviour == "chatty" {
        for line in 0..2000 {
            eprintln!("note {line}");
        }
        std::process::exit(5);
    }
    if behaviour == "noisy-death" {
        eprintln!("the toolchain this helper was built for is not installed");
        std::process::exit(3);
    }
    if behaviour == "noisy-stdout" {
        // Deliberately not a frame: stdout is exclusively the protocol stream.
        let _ = output.write_all(b"diagnostic\n");
        let _ = output.flush();
        return;
    }
    if behaviour == "oversized-frame" {
        let declared = MAX_FRAME_BYTES.saturating_add(1).to_be_bytes();
        let _ = output.write_all(&declared);
        let _ = output.write_all(&[0]);
        let _ = output.flush();
        return;
    }

    loop {
        let request: Request = match read_frame(&mut input) {
            Ok(Some(request)) => request,
            Ok(None) | Err(_) => return,
        };
        match behaviour.as_str() {
            "dies" => std::process::exit(4),
            "deaf" => park(),
            "deaf-after-setup" if matches!(&request.body, RequestBody::Analyze(_)) => park(),
            "deaf-on-poison" if matches!(&request.body, RequestBody::Analyze(analyze) if analyze.unit.file.contains("poison")) =>
            {
                park();
            }
            "slow" => std::thread::sleep(Duration::from_secs(30)),
            _ => {}
        }
        let id = if behaviour == "confused" {
            request.id.wrapping_add(1000)
        } else {
            request.id
        };
        let request_protocol = request.protocol_version;
        let body = match request.body {
            RequestBody::Handshake(_) if behaviour == "refuses" => ResponseBody::Failed(Failure {
                code: "no_toolchain".into(),
                message: "no toolchain this helper knows is installed".into(),
            }),
            RequestBody::Handshake(_) => {
                ResponseBody::Handshake(Box::new(identity(behaviour.as_str())))
            }
            RequestBody::DescribeBuild(_) if behaviour == "undescribed" => {
                ResponseBody::Failed(Failure {
                    code: "no_build_description".into(),
                    message: "this mock cannot read a manifest".into(),
                })
            }
            RequestBody::DescribeBuild(_) => ResponseBody::Build(Box::new(BuildDescription {
                features: vec!["mock/std".into()],
                cfgs: vec!["target_os = \"mock\"".into()],
            })),
            RequestBody::Analyze(analyze) if behaviour == "needs-execution" => {
                ResponseBody::Unavailable {
                    unit: analyze.unit,
                    reason: Unavailability::RequiresExecution,
                }
            }
            RequestBody::Analyze(analyze) => {
                if behaviour == "allergic" && analyze.unit.file.contains("poison") {
                    eprintln!("mock compiler crashed while reading {}", analyze.unit.file);
                    std::process::exit(6);
                }
                let mut ir = analyzed(analyze.unit);
                if behaviour == "wrong-schema" {
                    ir.schema_version = "compiler-ir-from-the-future".into();
                }
                ResponseBody::Analyzed(Box::new(ir))
            }
            RequestBody::Shutdown => ResponseBody::Shutdown,
        };
        let shutting_down = matches!(body, ResponseBody::Shutdown);
        let wrong_revision = behaviour == "wrong-revision-after-setup"
            || (behaviour == "wrong-revision-on-poison"
                && matches!(&body, ResponseBody::Analyzed(ir) if ir.unit.file.contains("poison")));
        let protocol_version = if wrong_revision && matches!(&body, ResponseBody::Analyzed(_)) {
            request_protocol.saturating_add(1)
        } else {
            request_protocol
        };
        let sent = write_frame(
            &mut output,
            &Response {
                protocol_version,
                id,
                body,
            },
        );
        if sent.is_err() || shutting_down {
            return;
        }
    }
}

/// A small but complete answer: one symbol of one type, anchored where it
/// reads and remembering where it was written.
fn analyzed(unit: UnitRef) -> CompilerIr {
    let range = SourceRange {
        file: unit.file.clone(),
        start_byte: 0,
        end_byte: 32,
        start_line: 1,
    };
    let mut ir = CompilerIr::empty(unit);
    ir.types.push(ResolvedType {
        display: "u64".into(),
        category: TypeCategory::Integer,
        arguments: Vec::new(),
        definition: None,
    });
    ir.symbols.push(ResolvedSymbol {
        id: "mock::counted".into(),
        name: "counted".into(),
        kind: SymbolKind::Function,
        anchor: Anchor::written_here(range),
        type_index: Some(0),
        external: false,
    });
    ir
}

/// What this mock claims to be, under the named behaviour.
fn identity(behaviour: &str) -> HelperIdentity {
    let protocol = if behaviour == "ancient" {
        PROTOCOL_VERSION.saturating_sub(1)
    } else {
        PROTOCOL_VERSION
    };
    let capabilities = if behaviour == "untyped" {
        vec![Capability::CallTargets]
    } else if behaviour == "unnamed" {
        vec![
            Capability::Types,
            Capability::CallTargets,
            Capability::MacroExpansion,
        ]
    } else {
        vec![
            Capability::Types,
            Capability::NameResolution,
            Capability::CallTargets,
            Capability::MacroExpansion,
        ]
    };
    HelperIdentity {
        name: "codehelion-mock-helper".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        protocol,
        toolchains: vec!["mock 1.0".into()],
        capabilities,
        // What it would run if permitted. `inert` says nothing, which is how
        // the refusal of a permission nobody would act on gets tested.
        executes: if behaviour == "inert" {
            Vec::new()
        } else {
            vec![Execution::BuildScript]
        },
    }
}

/// Stop answering without exiting, the way a helper stuck inside a compiler
/// does: the pipe stays open, so a reader waiting on it waits forever.
fn park() -> ! {
    let mut sink = [0u8; 1];
    loop {
        if std::io::stdin().read(&mut sink).is_err() {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }
}
