//! What a helper printed on its standard error, kept under a ceiling.

use super::MAX_DIAGNOSTIC_LINES;

/// Helper standard error that has not been reported yet, and what did not fit.
///
/// The count is kept rather than the lines: a run that drops an explanation has
/// to say so, because diagnostics that end silently read exactly like a helper
/// that had nothing more to say.
#[derive(Debug, Default)]
pub(super) struct Diagnostics {
    /// Lines collected since the last time they were handed out.
    kept: Vec<String>,
    /// Lines the ceiling left out over the same span.
    dropped: usize,
}

impl Diagnostics {
    /// Keep `line` if there is room, and count it if there is not.
    pub(super) fn push(&mut self, line: String) {
        if self.kept.len() < MAX_DIAGNOSTIC_LINES {
            self.kept.push(line);
        } else {
            self.dropped = self.dropped.saturating_add(1);
        }
    }

    /// What has been collected, without consuming it.
    pub(super) fn peek(&self) -> Vec<String> {
        bounded(self.kept.clone(), self.dropped)
    }

    /// What has been collected, leaving the next span empty.
    pub(super) fn take(&mut self) -> Vec<String> {
        let dropped = std::mem::take(&mut self.dropped);
        bounded(std::mem::take(&mut self.kept), dropped)
    }
}

/// Cut `lines` to the ceiling, ending with a note for what a limit left out.
///
/// `already_dropped` lines were discarded before this point. The note is part
/// of the ceiling rather than an extra line past it, so what a caller receives
/// is bounded whether or not anything was left out.
pub(super) fn bounded(mut lines: Vec<String>, already_dropped: usize) -> Vec<String> {
    let mut dropped = already_dropped;
    if lines.len().saturating_add(usize::from(dropped > 0)) > MAX_DIAGNOSTIC_LINES {
        let room = MAX_DIAGNOSTIC_LINES.saturating_sub(1);
        dropped = dropped.saturating_add(lines.len().saturating_sub(room));
        lines.truncate(room);
    }
    if dropped > 0 {
        lines.push(format!(
            "{dropped} further line(s) the helper printed were not kept"
        ));
    }
    lines
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[test]
    fn what_one_unit_was_refused_for_is_not_spent_by_the_units_before_it() {
        // A helper explaining every unit it refuses prints far more lines over
        // its life than any one report may carry. Each unit's reasons must
        // still be its own, however many units came first.
        let sink = Arc::new(Mutex::new(Diagnostics::default()));
        let units = MAX_DIAGNOSTIC_LINES * 2;
        for unit in 0..units {
            sink.lock().unwrap().push(format!("refused unit-{unit}"));
            let reported = sink.lock().unwrap().take();
            assert_eq!(reported, vec![format!("refused unit-{unit}")]);
        }
    }

    #[test]
    fn a_span_that_was_read_starts_the_next_one_empty() {
        let sink = Arc::new(Mutex::new(Diagnostics::default()));
        sink.lock().unwrap().push("first".to_string());
        assert_eq!(sink.lock().unwrap().take(), vec!["first".to_string()]);
        assert!(sink.lock().unwrap().take().is_empty());
        assert!(sink.lock().unwrap().peek().is_empty());
    }
}
