// Seed for the divergence corpus. One function carrying a loop, nested
// branches, early exits and method calls, so that a variant can disturb the
// control-flow profile or the call surface independently of the statement
// sequence. Authored in the controlled one-statement-per-line style the
// mutation generator assumes.

fn tally_entries(entries: &[i32], limit: i32) -> i32 {
    let mut total = 0;
    let mut kept = 0;
    let mut skipped = 0;
    for entry in entries {
        let value = entry.abs();
        if value > limit {
            skipped += 1;
            continue;
        }
        if value > 0 {
            total += value;
            kept += 1;
        } else {
            total -= 1;
        }
    }
    if kept == 0 {
        return 0;
    }
    total = total.min(limit);
    total = total.max(0);
    total - skipped
}
