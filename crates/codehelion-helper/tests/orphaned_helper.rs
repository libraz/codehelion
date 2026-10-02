//! A helper whose client vanishes mid-request takes its descendants with it.
//!
//! The test binary plays both parts. Run by the test runner it is the client;
//! started by the client through the sandbox entry point a scan uses, it finds
//! a marker directory named for its parent and becomes the helper.
#![cfg(unix)]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
#![allow(clippy::disallowed_types)]

use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use codehelion_helper::UnitRef;
use codehelion_helper::protocol::{
    Analyze, BuildDescription, Capability, DescribeBuild, HelperIdentity, PROTOCOL_VERSION,
    Request, RequestBody, write_frame,
};
use codehelion_helper::sandbox::{SandboxRequest, spawn};
use codehelion_helper::server::{Answer, Backend, Description, serve_stdio};
use nix::sys::signal::kill;
use nix::unistd::{Pid, getppid};

/// Where the client of process `client` and its helper meet.
fn marker_directory(client: i32) -> PathBuf {
    std::env::temp_dir().join(format!("codehelion-orphaned-helper-{client}"))
}

/// A backend whose only answer starts a long-lived child and never returns.
struct Stuck(PathBuf);

impl Backend for Stuck {
    fn identity(&self) -> HelperIdentity {
        HelperIdentity {
            name: "stuck".to_string(),
            version: "0.1.0".to_string(),
            protocol: PROTOCOL_VERSION,
            toolchains: Vec::new(),
            capabilities: vec![Capability::Types],
            executes: Vec::new(),
        }
    }

    fn describe(&mut self, _request: &DescribeBuild) -> Description {
        Description::Build(BuildDescription::default())
    }

    #[allow(
        clippy::zombie_processes,
        reason = "the child is meant to outlive this call"
    )]
    fn analyze(&mut self, _request: &Analyze) -> Answer {
        let child = std::process::Command::new("sleep")
            .arg("600")
            .spawn()
            .expect("start the descendant");
        std::fs::write(self.0.join("descendant.pid"), child.id().to_string())
            .expect("record the descendant");
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }
}

/// The helper half: does nothing unless the client half started it.
#[test]
fn helper_entry() {
    let marker = marker_directory(getppid().as_raw());
    if marker.is_dir() {
        let _ = serve_stdio(&mut Stuck(marker));
    }
}

fn alive(pid: i32) -> bool {
    kill(Pid::from_raw(pid), None).is_ok()
}

#[test]
fn a_client_that_vanishes_mid_request_does_not_leave_the_helpers_descendants_running() {
    let marker = marker_directory(i32::try_from(std::process::id()).unwrap());
    std::fs::create_dir_all(&marker).unwrap();
    let mut helper = spawn(
        &std::env::current_exe().unwrap(),
        &["helper_entry", "--exact", "--nocapture", "--test-threads=1"],
        SandboxRequest::unrestricted(),
    )
    .expect("start the helper half");
    let mut stdin = helper.take_stdin().expect("the helper's stdin");
    write_frame(
        &mut stdin,
        &Request {
            protocol_version: PROTOCOL_VERSION,
            id: 1,
            body: RequestBody::Analyze(Analyze {
                unit: UnitRef {
                    unit: "u".to_string(),
                    file: "u.c".to_string(),
                    variant: "host".to_string(),
                },
                compile_command: None,
                read_boundary: None,
                want: vec![Capability::Types],
                permitted: Vec::new(),
            }),
        },
    )
    .unwrap();
    stdin.flush().unwrap();

    let deadline = Instant::now() + Duration::from_secs(30);
    let descendant = loop {
        if let Ok(text) = std::fs::read_to_string(marker.join("descendant.pid"))
            && let Ok(pid) = text.trim().parse::<i32>()
        {
            break pid;
        }
        assert!(Instant::now() < deadline, "the helper never started work");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(alive(descendant));

    // The client dies: its end of every pipe closes and nothing else happens.
    drop(stdin);

    let deadline = Instant::now() + Duration::from_secs(30);
    while alive(descendant) {
        assert!(
            Instant::now() < deadline,
            "the descendant outlived its client"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    helper.wait();
    let _ = std::fs::remove_dir_all(&marker);
}
