//! The threads that carry frames to and from a helper process.
//!
//! A pipe read blocks until the peer writes and a pipe write blocks until the
//! peer reads, so neither may happen on the caller's thread: a helper that has
//! stopped answering, or stopped reading, would otherwise hold the run inside a
//! call that cannot be given a deadline.

use std::io::{BufRead, BufReader, Write};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use super::diagnostics::Diagnostics;
use crate::protocol::{FrameError, Request, Response, read_frame, write_frame};

/// Read frames off the helper's output on a thread.
///
/// The channel is bounded: a helper writing faster than the run reads is made
/// to wait rather than allowed to fill memory with answers nobody has asked
/// for yet.
pub(super) fn read_responses(
    stdout: Option<std::process::ChildStdout>,
) -> Receiver<Result<Response, FrameError>> {
    let (sender, receiver) = sync_channel(16);
    let Some(mut stdout) = stdout else {
        return receiver;
    };
    std::thread::spawn(move || {
        loop {
            match read_frame(&mut stdout) {
                Ok(Some(response)) => {
                    if sender.send(Ok(response)).is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    let _ = sender.send(Err(error));
                    break;
                }
            }
        }
    });
    receiver
}

/// One request on its way to the helper, with where its outcome goes.
#[derive(Debug)]
pub(super) struct Outgoing {
    /// The frame to write.
    request: Request,
    /// Where the writer reports whether the frame reached the helper.
    outcome: SyncSender<Result<(), FrameError>>,
}

/// How handing a request to the writer can fail.
#[derive(Debug)]
pub(super) enum Delivery {
    /// The deadline passed with the request still unwritten.
    Timeout,
    /// The stream refused it.
    Failed(FrameError),
}

/// Write requests to the helper on a thread.
///
/// The writer is a thread for the same reason the reader is: a pipe write
/// blocks until the peer reads, and a helper that has stopped reading would
/// otherwise hold the run inside a call that cannot be given a deadline.
pub(super) fn write_requests<W: Write + Send + 'static>(mut stdin: W) -> SyncSender<Outgoing> {
    let (sender, receiver) = sync_channel::<Outgoing>(1);
    std::thread::spawn(move || {
        while let Ok(outgoing) = receiver.recv() {
            let result = write_frame(&mut stdin, &outgoing.request);
            let failed = result.is_err();
            let _ = outgoing.outcome.send(result);
            if failed {
                // The stream is no longer one whole frames can be written to,
                // so the pipe closes here rather than carrying half a message.
                break;
            }
        }
    });
    sender
}

/// Hand `request` to the writer and wait, no longer than `timeout`, for it to
/// reach the helper.
pub(super) fn deliver(
    requests: &SyncSender<Outgoing>,
    request: Request,
    timeout: Duration,
) -> Result<(), Delivery> {
    let started = Instant::now();
    let (outcome, written) = sync_channel(1);
    match requests.try_send(Outgoing { request, outcome }) {
        Ok(()) => {}
        // One request is outstanding at a time, so a full queue means the
        // writer is still on a frame whose deadline has already passed.
        Err(TrySendError::Full(_)) => return Err(Delivery::Timeout),
        Err(TrySendError::Disconnected(_)) => return Err(Delivery::Failed(broken_pipe())),
    }
    match written.recv_timeout(timeout.saturating_sub(started.elapsed())) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(Delivery::Failed(error)),
        Err(RecvTimeoutError::Timeout) => Err(Delivery::Timeout),
        Err(RecvTimeoutError::Disconnected) => Err(Delivery::Failed(broken_pipe())),
    }
}

/// The stream failure a writer that has gone leaves behind.
fn broken_pipe() -> FrameError {
    FrameError::Io(std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "the helper's standard input was closed",
    ))
}

/// Keep the helper's standard error, bounded, on a thread.
pub(super) fn drain_stderr(stream: std::process::ChildStderr, sink: Arc<Mutex<Diagnostics>>) {
    std::thread::spawn(move || {
        collect_stderr(BufReader::new(stream), &sink);
    });
}

/// Read all of one helper stderr stream while retaining the bounded prefix of
/// each span between two reads.
fn collect_stderr(reader: impl BufRead, sink: &Arc<Mutex<Diagnostics>>) {
    for line in reader.lines().map_while(Result::ok) {
        // Take the lock for one line and let it go: the helper writing to
        // its standard error must never be what stops a caller from
        // reading what it has written so far.
        sink.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(line);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::client::MAX_DIAGNOSTIC_LINES;
    use crate::protocol::{PROTOCOL_VERSION, RequestBody};

    #[test]
    fn stderr_drain_keeps_its_prefix_and_consumes_the_remaining_lines() {
        use std::fmt::Write as _;

        let mut input = String::new();
        for line in 0..=MAX_DIAGNOSTIC_LINES {
            writeln!(input, "line-{line}").unwrap();
        }
        let sink = Arc::new(Mutex::new(Diagnostics::default()));
        collect_stderr(std::io::Cursor::new(input), &sink);
        let kept = sink.lock().unwrap().peek();
        assert_eq!(kept.len(), MAX_DIAGNOSTIC_LINES);
        assert_eq!(kept.first().map(String::as_str), Some("line-0"));
        let expected_last = format!("line-{}", MAX_DIAGNOSTIC_LINES - 2);
        assert_eq!(
            kept.get(MAX_DIAGNOSTIC_LINES - 2).map(String::as_str),
            Some(expected_last.as_str())
        );
    }

    #[test]
    fn lines_a_ceiling_left_out_are_counted_where_the_kept_ones_are_reported() {
        use std::fmt::Write as _;

        let overshoot = 7;
        let mut input = String::new();
        for line in 0..MAX_DIAGNOSTIC_LINES + overshoot {
            writeln!(input, "line-{line}").unwrap();
        }
        let sink = Arc::new(Mutex::new(Diagnostics::default()));
        collect_stderr(std::io::Cursor::new(input), &sink);

        let reported = sink.lock().unwrap().take();
        assert_eq!(reported.len(), MAX_DIAGNOSTIC_LINES);
        // One kept line gives up its place to the note that accounts for the
        // rest, so the count names every line that was not kept.
        let expected = format!("{} further line(s)", overshoot + 1);
        let note = reported.last().cloned().unwrap_or_default();
        assert!(note.contains(&expected), "{note}");
    }

    /// A stream that accepts nothing, the way a pipe behaves once the peer at
    /// the other end has stopped reading it.
    struct NeverAccepts;

    impl Write for NeverAccepts {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            std::thread::sleep(Duration::from_secs(30));
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn shutdown_request() -> Request {
        Request {
            protocol_version: PROTOCOL_VERSION,
            id: 0,
            body: RequestBody::Shutdown,
        }
    }

    #[test]
    fn a_request_a_helper_will_not_read_gives_up_on_its_deadline() {
        let deadline = Duration::from_millis(200);
        let requests = write_requests(NeverAccepts);

        let started = Instant::now();
        let outcome = deliver(&requests, shutdown_request(), deadline);
        let waited = started.elapsed();

        assert!(matches!(outcome, Err(Delivery::Timeout)), "{outcome:?}");
        assert!(
            waited < Duration::from_secs(5),
            "the write waited {waited:?} on a {deadline:?} deadline"
        );
    }

    #[test]
    fn a_request_a_helper_reads_completes_rather_than_waiting_out_its_deadline() {
        let requests = write_requests(std::io::sink());

        let started = Instant::now();
        let outcome = deliver(&requests, shutdown_request(), Duration::from_secs(30));

        assert!(outcome.is_ok(), "{outcome:?}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
