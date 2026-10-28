//! `artifact analyze|compare|report --compressed`: the compressed size of a
//! whole artifact, in every command and every format.

use super::*;
use codehelion_artifact::compression::{CompressionAlgorithm, compressed_sizes};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// The text, JSON and CSV spellings one algorithm is reported under.
struct Spelling {
    algorithm: &'static str,
    parameters: &'static str,
    encoder: &'static str,
}

const GZIP: Spelling = Spelling {
    algorithm: "gzip",
    parameters: "level 9",
    encoder: "flate2 (miniz_oxide)",
};
const BROTLI: Spelling = Spelling {
    algorithm: "brotli",
    parameters: "quality 11, window 22",
    encoder: "brotli (rust)",
};

const NOTE: &str = "  note: the compressed size covers the whole artifact; it is not divided among symbols, and an external compressor at the same level can differ by a fraction of a percent";

#[derive(Clone, Copy, Debug)]
enum Command {
    Analyze,
    Compare,
    Report,
}

#[derive(Clone, Copy, Debug)]
enum Names {
    Parameterized,
    Plain,
    Unnamed,
}

struct Row {
    command: Command,
    compressed: &'static [&'static str],
    format: &'static str,
    names: Names,
}

const fn row(
    command: Command,
    compressed: &'static [&'static str],
    format: &'static str,
    names: Names,
) -> Row {
    Row {
        command,
        compressed,
        format,
        names,
    }
}

/// A pairwise cover of command, algorithms, format and symbol names.
const ROWS: [Row; 16] = [
    row(Command::Report, &["gzip", "brotli"], "text", Names::Unnamed),
    row(Command::Analyze, &["brotli"], "text", Names::Parameterized),
    row(Command::Compare, &[], "csv", Names::Unnamed),
    row(Command::Report, &[], "json", Names::Parameterized),
    row(Command::Compare, &["gzip", "brotli"], "json", Names::Plain),
    row(Command::Analyze, &["brotli"], "csv", Names::Plain),
    row(Command::Report, &["gzip"], "text", Names::Plain),
    row(Command::Compare, &["brotli"], "text", Names::Unnamed),
    row(Command::Report, &["gzip"], "csv", Names::Parameterized),
    row(Command::Report, &[], "text", Names::Plain),
    row(Command::Analyze, &["gzip"], "json", Names::Unnamed),
    row(Command::Compare, &[], "text", Names::Parameterized),
    row(Command::Compare, &["gzip"], "json", Names::Unnamed),
    row(Command::Compare, &["brotli"], "json", Names::Plain),
    row(
        Command::Analyze,
        &["gzip", "brotli"],
        "csv",
        Names::Parameterized,
    ),
    row(Command::Analyze, &[], "json", Names::Unnamed),
];

fn spelling(algorithm: &str) -> &'static Spelling {
    match algorithm {
        "gzip" => &GZIP,
        "brotli" => &BROTLI,
        other => panic!("no spelling for {other}"),
    }
}

/// The module's section list as `(id, start, end)` byte ranges.
fn section_ranges(module: &[u8]) -> Vec<(u8, usize, usize)> {
    let mut at = 8;
    let mut ranges = Vec::new();
    while at < module.len() {
        let start = at;
        let id = module[at];
        at += 1;
        let (mut length, mut shift) = (0_usize, 0);
        loop {
            let byte = module[at];
            at += 1;
            length |= usize::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
        }
        at += length;
        ranges.push((id, start, at));
    }
    ranges
}

/// A module declaring the functions `names` selects; `variant` 1 grows the
/// first body by one instruction, so the two variants differ in bytes.
fn module(names: Names, variant: u8) -> Vec<u8> {
    let labels: &[&str] = match names {
        Names::Parameterized => &[
            "int probe<f::$_0>(char const*, f::$_0)",
            "int probe<f::$_1>(char const*, f::$_1)",
            "int probe<f::$_2>(char const*, f::$_2)",
            "std::__2::deque<int>::push_back(int&&)",
            "std::__2::deque<int>::pop_front()",
            "solo()",
        ],
        Names::Plain => &["solo()", "helper(int)", "render()"],
        Names::Unnamed => &["", "", ""],
    };
    let bodies: Vec<Vec<u8>> = (0..labels.len())
        .map(|index| {
            let mut body = vec![0x00, 0x41, u8::try_from(index).expect("small index"), 0x1a];
            if index == 0 && variant == 1 {
                body.push(0x01);
            }
            body.push(0x0b);
            body
        })
        .collect();
    let functions: Vec<(&str, &[u8])> = labels
        .iter()
        .zip(&bodies)
        .map(|(label, body)| (*label, body.as_slice()))
        .collect();
    let mut bytes = codehelion_fixtures::wasm_module(&functions);
    if matches!(names, Names::Unnamed) {
        let (_, start, end) = *section_ranges(&bytes)
            .last()
            .expect("the module has a name section");
        assert_eq!(end, bytes.len());
        bytes.truncate(start);
    }
    bytes
}

fn run(directory: &Path, args: &[&str]) -> std::process::Output {
    cmd()
        .current_dir(directory)
        .args(args)
        .output()
        .expect("run codehelion")
}

fn stdout_of(output: &std::process::Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).expect("utf-8 output")
}

fn compressed_flags(algorithms: &[&str]) -> Vec<String> {
    algorithms
        .iter()
        .flat_map(|name| ["--compressed".to_owned(), (*name).to_owned()])
        .collect()
}

fn analyze_args<'a>(file: &'a str, database: &'a str, extra: &'a [String]) -> Vec<&'a str> {
    let mut args = vec!["artifact", "analyze", file, "--db", database];
    args.extend(extra.iter().map(String::as_str));
    args
}

/// The compressed length of each requested algorithm, measured by the library
/// on the bytes of `file` rather than read back from the command under test.
fn measured(file: &Path, algorithms: &[&str]) -> Vec<u64> {
    let bytes = std::fs::read(file).expect("read the module");
    let algorithms: Vec<CompressionAlgorithm> = algorithms
        .iter()
        .map(|algorithm| match *algorithm {
            "gzip" => CompressionAlgorithm::Gzip,
            "brotli" => CompressionAlgorithm::Brotli,
            other => panic!("unknown algorithm {other}"),
        })
        .collect();
    compressed_sizes(&bytes, &algorithms)
        .expect("measure the module")
        .iter()
        .map(|size| size.bytes)
        .collect()
}

/// Split one CSV record, honouring double-quoted fields.
fn csv_fields(line: &str) -> Vec<String> {
    let (mut fields, mut field, mut quoted) = (Vec::new(), String::new(), false);
    let mut chars = line.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '"' if quoted && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(std::mem::take(&mut field)),
            other => field.push(other),
        }
    }
    fields.push(field);
    fields
}

/// The records of one type, each as a column-name to value map.
fn csv_records(csv: &str, record_type: &str) -> Vec<std::collections::BTreeMap<String, String>> {
    let mut lines = csv.lines();
    let header = csv_fields(lines.next().expect("csv header"));
    lines
        .map(csv_fields)
        .filter(|fields| fields[0] == record_type)
        .map(|fields| header.iter().cloned().zip(fields).collect())
        .collect()
}

/// What an analysis of `file` says about compressed size, in any format.
fn check_analysis(output: &str, format: &str, algorithms: &[&str], expected: &[u64]) {
    match format {
        "json" => {
            let report: Value = serde_json::from_str(output).expect("json report");
            let entries = report["compressed_sizes"].as_array().expect("array");
            assert_eq!(entries.len(), algorithms.len(), "{output}");
            for ((entry, name), bytes) in entries.iter().zip(algorithms).zip(expected) {
                let spelling = spelling(name);
                assert_eq!(entry["algorithm"], spelling.algorithm);
                assert_eq!(entry["parameters"], spelling.parameters);
                assert_eq!(entry["encoder"], spelling.encoder);
                assert_eq!(entry["bytes"], *bytes);
                assert!(*bytes > 0);
            }
        }
        "text" => {
            let lines: Vec<&str> = output
                .lines()
                .filter(|line| line.starts_with("compressed bytes ("))
                .collect();
            assert_eq!(lines.len(), algorithms.len(), "{output}");
            for ((line, name), bytes) in lines.iter().zip(algorithms).zip(expected) {
                let spelling = spelling(name);
                assert_eq!(
                    *line,
                    format!(
                        "compressed bytes ({}, {}, {}): {bytes}",
                        spelling.algorithm, spelling.parameters, spelling.encoder
                    )
                );
            }
            let notes = output.lines().filter(|line| *line == NOTE).count();
            assert_eq!(notes, usize::from(!algorithms.is_empty()), "{output}");
            if !algorithms.is_empty() {
                let data = output.find("data segment bytes:").expect("data line");
                let first = output.find("compressed bytes (").expect("compressed line");
                let note = output.find(NOTE).expect("note");
                assert!(data < first && first < note, "{output}");
                if let Some(sections) = output.find("section sizes:") {
                    assert!(note < sections, "{output}");
                }
            }
        }
        "csv" => {
            let records = csv_records(output, "compressed-size");
            assert_eq!(records.len(), algorithms.len(), "{output}");
            for ((record, name), bytes) in records.iter().zip(algorithms).zip(expected) {
                let spelling = spelling(name);
                assert_eq!(record["compression_algorithm"], spelling.algorithm);
                assert_eq!(record["compression_parameters"], spelling.parameters);
                assert_eq!(record["compression_encoder"], spelling.encoder);
                assert_eq!(record["compressed_bytes"], bytes.to_string());
            }
            if !algorithms.is_empty() {
                let types: Vec<&str> = output
                    .lines()
                    .skip(1)
                    .map(|line| line.split(',').next().expect("record type"))
                    .collect();
                assert_eq!(types[0], "summary");
                assert_eq!(types[1], "compressed-size", "directly after the summary");
            }
        }
        other => panic!("unknown format {other}"),
    }
}

const fn direction(delta: i128) -> &'static str {
    match delta.signum() {
        1 => "larger",
        -1 => "smaller",
        _ => "no change",
    }
}

fn check_comparison(
    output: &str,
    format: &str,
    algorithms: &[&str],
    before: &[u64],
    after: &[u64],
) {
    let deltas: Vec<i128> = before
        .iter()
        .zip(after)
        .map(|(before, after)| i128::from(*after) - i128::from(*before))
        .collect();
    match format {
        "json" => {
            let report: Value = serde_json::from_str(output).expect("json report");
            let entries = report["compressed_deltas"].as_array().expect("array");
            assert_eq!(entries.len(), algorithms.len(), "{output}");
            for (index, name) in algorithms.iter().enumerate() {
                let spelling = spelling(name);
                let entry = &entries[index];
                assert_eq!(entry["algorithm"], spelling.algorithm);
                assert_eq!(entry["parameters"], spelling.parameters);
                assert_eq!(entry["encoder"], spelling.encoder);
                assert_eq!(entry["before_bytes"], before[index]);
                assert_eq!(entry["after_bytes"], after[index]);
                assert_eq!(entry["delta_bytes"], i64::try_from(deltas[index]).unwrap());
            }
        }
        "text" => {
            let lines: Vec<&str> = output
                .lines()
                .filter(|line| line.starts_with("compressed bytes ("))
                .collect();
            assert_eq!(lines.len(), algorithms.len(), "{output}");
            for (index, name) in algorithms.iter().enumerate() {
                let spelling = spelling(name);
                assert_eq!(
                    lines[index],
                    format!(
                        "compressed bytes ({}, {}, {}): {} before, {} after, {:+} bytes ({})",
                        spelling.algorithm,
                        spelling.parameters,
                        spelling.encoder,
                        before[index],
                        after[index],
                        deltas[index],
                        direction(deltas[index]),
                    )
                );
            }
            if !algorithms.is_empty() {
                let data = output.find("data segment bytes:").expect("data line");
                let first = output.find("compressed bytes (").expect("compressed line");
                assert!(data < first, "{output}");
                if let Some(changes) = output.find("symbol changes:") {
                    assert!(first < changes, "{output}");
                }
            }
        }
        "csv" => {
            let records = csv_records(output, "compressed-delta");
            assert_eq!(records.len(), algorithms.len(), "{output}");
            for (index, name) in algorithms.iter().enumerate() {
                let spelling = spelling(name);
                let record = &records[index];
                assert_eq!(record["compression_algorithm"], spelling.algorithm);
                assert_eq!(record["compression_parameters"], spelling.parameters);
                assert_eq!(record["compression_encoder"], spelling.encoder);
                assert_eq!(record["before_compressed_bytes"], before[index].to_string());
                assert_eq!(record["after_compressed_bytes"], after[index].to_string());
                assert_eq!(record["compressed_delta_bytes"], deltas[index].to_string());
            }
            if !algorithms.is_empty() {
                let types: Vec<&str> = output
                    .lines()
                    .skip(1)
                    .map(|line| line.split(',').next().expect("record type"))
                    .collect();
                assert_eq!(types[0], "summary");
                assert_eq!(types[1], "compressed-delta", "directly after the summary");
            }
        }
        other => panic!("unknown format {other}"),
    }
}

fn write_module(directory: &Path, file: &str, bytes: &[u8]) -> PathBuf {
    let path = directory.join(file);
    std::fs::write(&path, bytes).expect("write module");
    path
}

#[test]
fn compressed_size_is_reported_by_every_command_in_every_format() {
    for (number, row) in ROWS.iter().enumerate() {
        let directory = tempfile::tempdir().expect("fixture directory");
        let root = directory.path();
        let context = format!(
            "row {}: {:?}",
            number + 1,
            (row.command, row.compressed, row.format, row.names)
        );
        let first = write_module(root, "first.wasm", &module(row.names, 0));
        let flags = compressed_flags(row.compressed);
        let database = root.join("audit.db");
        let (first_arg, database_arg) = (
            first.to_str().expect("path"),
            database.to_str().expect("path"),
        );
        match row.command {
            Command::Analyze | Command::Report => {
                let mut extra = flags.clone();
                extra.extend(["--format".to_owned(), row.format.to_owned()]);
                let analyzed =
                    stdout_of(&run(root, &analyze_args(first_arg, database_arg, &extra)));
                let expected = measured(&first, row.compressed);
                check_analysis(&analyzed, row.format, row.compressed, &expected);
                if matches!(row.command, Command::Report) {
                    std::fs::remove_file(&first).expect("remove the input");
                    let replayed = stdout_of(&run(
                        root,
                        &[
                            "artifact",
                            "report",
                            "--db",
                            database_arg,
                            "--format",
                            row.format,
                        ],
                    ));
                    assert_eq!(replayed, analyzed, "{context}");
                }
            }
            Command::Compare => {
                let second = write_module(root, "second.wasm", &module(row.names, 1));
                let mut args = vec![
                    "artifact",
                    "compare",
                    first_arg,
                    second.to_str().expect("path"),
                    "--format",
                    row.format,
                ];
                args.extend(flags.iter().map(String::as_str));
                let compared = stdout_of(&run(root, &args));
                let before = measured(&first, row.compressed);
                let after = measured(&second, row.compressed);
                check_comparison(&compared, row.format, row.compressed, &before, &after);
            }
        }
    }
}

#[test]
fn a_repeated_algorithm_is_measured_once_in_a_fixed_order() {
    let directory = tempfile::tempdir().expect("fixture directory");
    let root = directory.path();
    let file = write_module(root, "m.wasm", &module(Names::Plain, 0));
    let database = root.join("audit.db");
    let extra = compressed_flags(&["brotli", "gzip", "gzip"]);
    let mut args = analyze_args(
        file.to_str().expect("path"),
        database.to_str().expect("path"),
        &extra,
    );
    args.extend(["--format", "json"]);
    let report: Value = serde_json::from_str(&stdout_of(&run(root, &args))).expect("json");
    let algorithms: Vec<&str> = report["compressed_sizes"]
        .as_array()
        .expect("array")
        .iter()
        .map(|entry| entry["algorithm"].as_str().expect("algorithm"))
        .collect();
    assert_eq!(algorithms, ["gzip", "brotli"]);
}

#[test]
fn an_unknown_algorithm_is_a_usage_error() {
    let directory = tempfile::tempdir().expect("fixture directory");
    let file = write_module(directory.path(), "m.wasm", &module(Names::Plain, 0));
    let output = run(
        directory.path(),
        &[
            "artifact",
            "analyze",
            file.to_str().expect("path"),
            "--compressed",
            "zstd",
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("possible values: gzip, brotli"));
}

/// Append a custom section named `pad` holding `payload`.
fn with_padding(mut module: Vec<u8>, payload: &[u8]) -> Vec<u8> {
    let mut length = 4 + payload.len();
    module.push(0x00);
    loop {
        let low = u8::try_from(length & 0x7f).expect("seven bits");
        length >>= 7;
        if length == 0 {
            module.push(low);
            break;
        }
        module.push(low | 0x80);
    }
    module.extend_from_slice(b"\x03pad");
    module.extend_from_slice(payload);
    module
}

/// Incompressible padding for the deadline test: in the debug build the tests
/// run against, 1 MiB takes about 4 s to brotli, four times the deadline.
const TIMEOUT_PADDING_BYTES: usize = 1024 * 1024;

/// Deterministic incompressible bytes, so the encoder has real work to do.
fn pseudo_random(length: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_be_bytes()[0]
        })
        .collect()
}

#[test]
fn a_deadline_that_expires_while_compressing_names_the_compression_stage() {
    let directory = tempfile::tempdir().expect("fixture directory");
    let root = directory.path();
    let padding = pseudo_random(TIMEOUT_PADDING_BYTES);
    let file = write_module(
        root,
        "large.wasm",
        &with_padding(module(Names::Plain, 0), &padding),
    );
    let database = root.join("audit.db");
    let (file_arg, database_arg) = (
        file.to_str().expect("path"),
        database.to_str().expect("path"),
    );

    let brotli = run(
        root,
        &[
            "artifact",
            "analyze",
            file_arg,
            "--db",
            database_arg,
            "--compressed",
            "brotli",
            "--timeout-seconds",
            "1",
        ],
    );
    assert!(!brotli.status.success());
    let stderr = String::from_utf8_lossy(&brotli.stderr);
    assert!(
        stderr.contains("artifact worker phase when its deadline expired: compression"),
        "{stderr}"
    );
}
