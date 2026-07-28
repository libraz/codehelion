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
//! mock-helper untyped           # cannot resolve types
//! mock-helper slow              # answers, eventually
//! mock-helper deaf              # never answers
//! mock-helper dies              # exits mid-handshake
//! mock-helper noisy-death       # complains on stderr, then exits
//! mock-helper confused          # answers a request nobody made
//! mock-helper refuses           # answers with a failure
//! mock-helper chatty            # floods its standard error, then exits
//! ```

use std::io::Read;
use std::time::Duration;

use codehelion_helper::protocol::{
    Capability, Failure, HelperIdentity, PROTOCOL_VERSION, Request, RequestBody, Response,
    ResponseBody, VersionRange, read_frame, write_frame,
};

fn main() {
    let behaviour = std::env::args().nth(1).unwrap_or_default();
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

    loop {
        let request: Request = match read_frame(&mut input) {
            Ok(Some(request)) => request,
            Ok(None) | Err(_) => return,
        };
        match behaviour.as_str() {
            "dies" => std::process::exit(4),
            "deaf" => park(),
            "slow" => std::thread::sleep(Duration::from_secs(30)),
            _ => {}
        }
        let id = if behaviour == "confused" {
            request.id.wrapping_add(1000)
        } else {
            request.id
        };
        let body = match request.body {
            RequestBody::Handshake(_) if behaviour == "refuses" => ResponseBody::Failed(Failure {
                code: "no_toolchain".into(),
                message: "no toolchain this helper knows is installed".into(),
            }),
            RequestBody::Handshake(_) => {
                ResponseBody::Handshake(Box::new(identity(behaviour.as_str())))
            }
            RequestBody::Shutdown => ResponseBody::Shutdown,
        };
        let shutting_down = matches!(body, ResponseBody::Shutdown);
        let sent = write_frame(
            &mut output,
            &Response {
                protocol_version: PROTOCOL_VERSION,
                id,
                body,
            },
        );
        if sent.is_err() || shutting_down {
            return;
        }
    }
}

/// What this mock claims to be, under the named behaviour.
fn identity(behaviour: &str) -> HelperIdentity {
    let protocol = if behaviour == "ancient" {
        // A revision far enough back that no negotiation can reach it.
        VersionRange {
            min: 0,
            max: PROTOCOL_VERSION.saturating_sub(1),
        }
    } else {
        VersionRange::exactly(PROTOCOL_VERSION)
    };
    let capabilities = if behaviour == "untyped" {
        vec![Capability::CallTargets]
    } else {
        vec![
            Capability::Types,
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
