use super::correlation::mapping::*;
use super::correlation::matching::*;
use super::correlation::*;
use super::model::*;
use super::*;
use crate::cli::{DEFAULT_ARTIFACT_MAX_BYTES, DEFAULT_ARTIFACT_TIMEOUT_SECONDS};
use boon::{Compiler, Schemas};

#[cfg(unix)]
#[test]
#[allow(clippy::disallowed_types)] // Exercises the actual worker-kill path.
fn worker_deadline_terminates_a_nonresponsive_parser_process() {
    let mut child = std::process::Command::new("sh")
        .args(["-c", "sleep 1"])
        .spawn()
        .expect("start deliberately nonresponsive worker");
    let error = wait_for_worker(&mut child, Duration::from_millis(1))
        .expect_err("deadline must terminate the worker");
    assert!(
        error
            .to_string()
            .contains("exceeded the configured timeout"),
        "unexpected error: {error}"
    );
    assert!(child.try_wait().expect("query terminated worker").is_some());
}

#[test]
fn worker_deadline_rejects_an_unrepresentable_timeout_without_panicking() {
    let error = deadline_after(Duration::from_secs(u64::MAX))
        .expect_err("an unrepresentable deadline must be an error");
    assert!(error.to_string().contains("timeout is too large"));
}

#[test]
fn worker_stage_marker_reports_the_last_written_phase() {
    let marker = tempfile::NamedTempFile::new().expect("stage marker");
    fs::write(marker.path(), "persistence and source correlation").expect("write stage");
    assert_eq!(
        worker::current_stage(marker.path()),
        "persistence and source correlation"
    );
}

#[test]
fn worker_diagnostics_are_fully_drained_but_only_a_bounded_prefix_is_retained() {
    use std::cell::Cell;
    use std::rc::Rc;

    struct CountedReader {
        inner: std::io::Cursor<Vec<u8>>,
        consumed: Rc<Cell<usize>>,
    }

    impl Read for CountedReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let read = self.inner.read(buffer)?;
            self.consumed.set(self.consumed.get() + read);
            Ok(read)
        }
    }

    let payload = vec![b'x'; 1024 * 1024];
    let consumed = Rc::new(Cell::new(0));
    let reader = CountedReader {
        inner: std::io::Cursor::new(payload.clone()),
        consumed: Rc::clone(&consumed),
    };
    let retained = read_worker_stderr(reader, 1024).unwrap();
    assert_eq!(consumed.get(), payload.len());
    assert_eq!(retained.len(), 1024);
    assert!(retained.bytes().all(|byte| byte == b'x'));
}

#[test]
fn untrusted_artifact_limits_clamp_every_enforceable_resource() {
    let mut max_bytes = u64::MAX;
    let mut timeout_seconds = u64::MAX;
    let mut max_memory_bytes = None;
    let result = clamp_untrusted_artifact_limits(
        &mut max_bytes,
        &mut timeout_seconds,
        &mut max_memory_bytes,
    );
    assert_eq!(max_bytes, UNTRUSTED_ARTIFACT_MAX_BYTES);
    assert_eq!(timeout_seconds, UNTRUSTED_ARTIFACT_TIMEOUT_SECONDS);
    if !codehelion_helper::availability().memory_limit {
        assert!(result.is_err());
        return;
    }
    result.expect("supported platform applies the memory ceiling");
    assert_eq!(max_memory_bytes, Some(UNTRUSTED_ARTIFACT_MAX_MEMORY_BYTES));

    let mut lower_bytes = 1024;
    let mut lower_timeout = 1;
    let mut lower_memory = Some(2048);
    clamp_untrusted_artifact_limits(&mut lower_bytes, &mut lower_timeout, &mut lower_memory)
        .expect("supported platform applies the lower explicit ceiling");
    assert_eq!(lower_bytes, 1024);
    assert_eq!(lower_timeout, 1);
    assert_eq!(lower_memory, Some(2048));
}

fn assert_valid_schema(schema_uri: &str, schema: &str, value: &serde_json::Value) {
    let mut schemas = Schemas::new();
    let mut compiler = Compiler::new();
    let schema = serde_json::from_str(schema).unwrap();
    compiler.add_resource(schema_uri, schema).unwrap();
    let index = compiler.compile(schema_uri, &mut schemas).unwrap();
    schemas.validate(value, index).unwrap();
}

fn assert_clone_group_savings_are_in_json_and_csv(report: &ArtifactReport) {
    let json = serde_json::to_value(report).unwrap();
    assert!(json["sizes"]["estimated_refactor_savings_bytes"].is_null());
    assert_eq!(
        json["correlation"]["estimated_refactor_savings"][0]["estimated_refactor_savings_bytes"],
        9
    );
    let mut csv = Vec::new();
    render_csv(report, &mut csv).unwrap();
    let csv = String::from_utf8(csv).unwrap();
    let mut csv_rows = csv.lines();
    let header: Vec<_> = csv_rows.next().unwrap().split(',').collect();
    let savings = csv_rows
        .map(|row| row.split(',').collect::<Vec<_>>())
        .find(|row| row[0] == "clone-group-savings")
        .unwrap();
    for (field, expected) in [
        ("duplicated_bytes", "9"),
        ("estimated_refactor_savings_bytes", "9"),
    ] {
        let index = header
            .iter()
            .position(|candidate| *candidate == field)
            .unwrap();
        assert_eq!(savings[index], expected, "unexpected {field}");
    }
}

fn assert_comparison_csv_has_fixed_records(report: &ArtifactComparisonReport) {
    let mut csv = Vec::new();
    render_compare_csv(report, &mut csv).unwrap();
    let csv = String::from_utf8(csv).unwrap();
    let mut rows = csv.lines();
    let header: Vec<_> = rows.next().unwrap().split(',').collect();
    assert_eq!(
        header,
        [
            "record_type",
            "before_path",
            "after_path",
            "before_format",
            "after_format",
            "before_fingerprint",
            "after_fingerprint",
            "observed_size_reduction_bytes",
            "duplicated_code_delta_bytes",
            "duplicated_data_delta_bytes",
            "estimated_refactor_savings_bytes",
            "verified_savings_bytes",
            "source_run",
            "clone_group_fingerprint",
            "change_kind",
            "name",
            "fingerprint",
            "symbol_size_delta_bytes",
            "duplicated_bytes_delta",
            "members_delta",
            "warning",
            "absolute_error_bytes",
            "relative_error",
        ]
    );
    let rows: Vec<Vec<_>> = rows.map(|row| row.split(',').collect()).collect();
    assert!(rows.iter().all(|row| row.len() == header.len()));
    assert_eq!(rows[0][0], "summary");
    assert_eq!(rows[0][7], "1");
    let calibration = rows.iter().find(|row| row[0] == "calibration").unwrap();
    assert_eq!(calibration[10], "-2");
    assert_eq!(calibration[11], "1");
    assert_eq!(calibration[12], "7");
}

mod correlation;
mod locations;
mod reports;
