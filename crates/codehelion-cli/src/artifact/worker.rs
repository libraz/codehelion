//! Process isolation for artifact parsing.
//!
//! The parent process owns deadlines, resource limits, and diagnostic relay.
//! Format-specific parsing remains in the artifact command module and runs
//! only after the private worker has installed the requested limits.

use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use super::{compare_direct, run_direct};
use crate::Outcome;
use crate::cli::{
    ArtifactArgs, ArtifactCompareArgs, ArtifactIsolatedArgs, UNTRUSTED_ARTIFACT_MAX_BYTES,
    UNTRUSTED_ARTIFACT_MAX_MEMORY_BYTES, UNTRUSTED_ARTIFACT_TIMEOUT_SECONDS,
};

/// Maximum worker diagnostic text retained after draining its stderr pipe.
const MAX_ARTIFACT_WORKER_DIAGNOSTIC_BYTES: usize = 64 * 1024;
const ARTIFACT_WORKER_STAGE_ENV: &str = "CODEHELION_ARTIFACT_WORKER_STAGE";

/// Record the current isolated-worker phase for a timeout diagnostic.
pub(super) fn set_stage(stage: &str) {
    if let Some(path) = std::env::var_os(ARTIFACT_WORKER_STAGE_ENV) {
        let _ = fs::write(path, stage);
    }
}

pub(super) fn current_stage(path: &Path) -> String {
    fs::read_to_string(path)
        .ok()
        .filter(|stage| !stage.trim().is_empty())
        .unwrap_or_else(|| "startup".to_owned())
}

/// The exact request one parent sends to its private worker.
#[derive(Debug, Serialize, Deserialize)]
pub(super) enum IsolatedArtifactRequest {
    Analyze(ArtifactArgs),
    Compare(ArtifactCompareArgs),
}

impl IsolatedArtifactRequest {
    fn set_output(&mut self, path: std::path::PathBuf) {
        match self {
            Self::Analyze(args) => {
                args.output = Some(path);
                args.force = true;
            }
            Self::Compare(args) => {
                args.output = Some(path);
                args.force = true;
            }
        }
    }
}

/// Execute one artifact analysis in a private worker process.
pub(super) fn run_isolated(args: &ArtifactArgs, out: &mut impl Write) -> Result<Outcome> {
    let mut args = args.clone();
    if args.untrusted {
        clamp_untrusted_artifact_limits(
            &mut args.max_bytes,
            &mut args.timeout_seconds,
            &mut args.max_memory_bytes,
        )?;
    }
    let output = args.output.clone();
    let force = args.force;
    run_isolated_request(
        IsolatedArtifactRequest::Analyze(args.clone()),
        args.timeout_seconds,
        output.as_deref(),
        force,
        out,
    )
}

pub(super) fn clamp_untrusted_artifact_limits(
    max_bytes: &mut u64,
    timeout_seconds: &mut u64,
    max_memory_bytes: &mut Option<u64>,
) -> Result<()> {
    *max_bytes = (*max_bytes).min(UNTRUSTED_ARTIFACT_MAX_BYTES);
    *timeout_seconds = (*timeout_seconds).min(UNTRUSTED_ARTIFACT_TIMEOUT_SECONDS);
    if !codehelion_helper::availability().memory_limit {
        bail!(
            "the untrusted artifact profile requires an enforceable worker memory limit on this platform"
        );
    }
    *max_memory_bytes = Some(
        max_memory_bytes
            .unwrap_or(UNTRUSTED_ARTIFACT_MAX_MEMORY_BYTES)
            .min(UNTRUSTED_ARTIFACT_MAX_MEMORY_BYTES),
    );
    Ok(())
}

/// Run either public artifact operation under one worker deadline.
#[allow(clippy::disallowed_types)] // Artifact parsing is intentionally isolated in a worker.
pub(super) fn run_isolated_request(
    mut request: IsolatedArtifactRequest,
    timeout_seconds: u64,
    output: Option<&Path>,
    force: bool,
    out: &mut impl Write,
) -> Result<Outcome> {
    validate_worker_timeout(timeout_seconds)?;
    let request_path = tempfile::NamedTempFile::new()
        .context("creating artifact worker request")?
        .into_temp_path();
    let report_path = tempfile::NamedTempFile::new()
        .context("creating artifact worker report")?
        .into_temp_path();
    let stage_path = tempfile::NamedTempFile::new()
        .context("creating artifact worker stage marker")?
        .into_temp_path();
    fs::write(&stage_path, "startup").context("initializing artifact worker stage marker")?;
    request.set_output(report_path.to_path_buf());
    fs::write(&request_path, serde_json::to_vec(&request)?)
        .context("writing artifact worker request")?;

    let executable = std::env::current_exe().context("locating artifact worker executable")?;
    let mut child = std::process::Command::new(executable)
        .args([
            "artifact",
            "isolated",
            "--request",
            request_path
                .to_str()
                .context("encoding artifact worker request path")?,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .env(ARTIFACT_WORKER_STAGE_ENV, &stage_path)
        .spawn()
        .context("starting isolated artifact worker")?;
    let stderr_reader = child.stderr.take().map(|stream| {
        thread::spawn(move || read_worker_stderr(stream, MAX_ARTIFACT_WORKER_DIAGNOSTIC_BYTES))
    });
    let wait_result = wait_for_worker(&mut child, Duration::from_secs(timeout_seconds));
    let stderr = stderr_reader.map_or_else(
        || Ok(String::new()),
        |reader| {
            reader
                .join()
                .map_err(|_| anyhow::anyhow!("artifact worker diagnostic reader panicked"))?
                .context("reading isolated artifact worker diagnostics")
        },
    )?;
    let status = match wait_result {
        Ok(status) => status,
        Err(error) => {
            return Err(error.context(format!(
                "artifact worker phase when its deadline expired: {}",
                current_stage(&stage_path).trim()
            )));
        }
    };
    if !status.success() {
        let detail = stderr
            .trim()
            .strip_prefix("error: ")
            .unwrap_or_else(|| stderr.trim());
        if detail.is_empty() {
            bail!("artifact worker exited with {status}");
        }
        bail!("artifact worker failed: {detail}");
    }
    if !stderr.trim().is_empty() {
        std::io::stderr()
            .lock()
            .write_all(stderr.as_bytes())
            .context("relaying isolated artifact worker diagnostics")?;
    }
    let rendered = fs::read(&report_path).context("reading isolated artifact worker report")?;
    if let Some(path) = output {
        super::write_output(path, &rendered, force)?;
    } else {
        out.write_all(&rendered)?;
    }
    Ok(Outcome::Success)
}

/// Drain a worker pipe completely while retaining only a bounded prefix.
pub(super) fn read_worker_stderr(
    mut stream: impl Read,
    maximum_bytes: usize,
) -> std::io::Result<String> {
    let mut retained = Vec::with_capacity(maximum_bytes.min(8 * 1024));
    let mut chunk = [0_u8; 8 * 1024];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        let keep = maximum_bytes.saturating_sub(retained.len()).min(read);
        retained.extend_from_slice(&chunk[..keep]);
    }
    Ok(String::from_utf8_lossy(&retained).into_owned())
}

/// Run the request an isolated artifact run sends, without starting another
/// worker.
///
/// # Errors
///
/// Returns an error for a malformed private request or any error the normal
/// local-only artifact analysis reports.
pub fn run_isolated_worker(args: &ArtifactIsolatedArgs) -> Result<Outcome> {
    let request: IsolatedArtifactRequest =
        serde_json::from_slice(&fs::read(&args.request).with_context(|| {
            format!("reading artifact worker request {}", args.request.display())
        })?)
        .context("parsing artifact worker request")?;
    let output = match &request {
        IsolatedArtifactRequest::Analyze(args) => args.output.as_ref(),
        IsolatedArtifactRequest::Compare(args) => args.output.as_ref(),
    };
    if output.is_none() {
        bail!("artifact worker request must name a private output file");
    }
    enforce_memory_limit(match &request {
        IsolatedArtifactRequest::Analyze(args) => args.max_memory_bytes,
        IsolatedArtifactRequest::Compare(args) => args.max_memory_bytes,
    })?;
    match request {
        IsolatedArtifactRequest::Analyze(args) => run_direct(&args, &mut std::io::sink()),
        IsolatedArtifactRequest::Compare(args) => compare_direct(&args, &mut std::io::sink()),
    }
}

/// Install the caller's required OS memory ceiling before an artifact parser
/// reads untrusted bytes.
fn enforce_memory_limit(max_memory_bytes: Option<u64>) -> Result<()> {
    let Some(max_memory_bytes) = max_memory_bytes else {
        return Ok(());
    };
    codehelion_helper::enforce_current_process_memory_limit(max_memory_bytes).map_err(|error| {
        anyhow::anyhow!(
            "cannot enforce the requested artifact worker memory limit of {max_memory_bytes} bytes: {error}"
        )
    })
}

/// Wait for an isolated worker, forcefully terminating it after `timeout`.
pub(super) fn wait_for_worker(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Result<std::process::ExitStatus> {
    let deadline = deadline_after(timeout)?;
    loop {
        if let Some(status) = child
            .try_wait()
            .context("waiting for isolated artifact worker")?
        {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let kill_result = child.kill();
            let reap_result = child.wait();
            kill_result.context("terminating timed-out artifact worker")?;
            let _ = reap_result.context("reaping timed-out artifact worker")?;
            bail!(
                "artifact analysis exceeded the configured timeout of {}s",
                timeout.as_secs()
            );
        }
        thread::sleep(Duration::from_millis(5));
    }
}

/// Reject a deadline that the host's monotonic clock cannot represent.
fn validate_worker_timeout(timeout_seconds: u64) -> Result<()> {
    deadline_after(Duration::from_secs(timeout_seconds)).map(|_| ())
}

/// Compute a deadline without allowing oversized private requests to panic.
pub(super) fn deadline_after(timeout: Duration) -> Result<Instant> {
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| anyhow::anyhow!("artifact worker timeout is too large for this platform"))
}
