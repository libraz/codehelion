// Seed source for the partial-clone synthetic corpus.
// Hand-authored; the variant files derive from this one. The donor functions
// hold the fragments that the variants transplant into the host functions.

fn measure_lines(lines: &[String]) -> (u32, u32) {
    let mut blanks = 0;
    let mut longest = 0;
    for raw in lines {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            blanks += 1;
            continue;
        }
        let mut width = 0;
        for ch in trimmed.chars() {
            if ch == '\t' {
                width += 4;
            } else {
                width += 1;
            }
        }
        longest = longest.max(width);
    }
    (blanks, longest)
}

fn checksum_records(records: &[u64], digest: &mut u64) -> u32 {
    let mut touched = 0;
    for record in records {
        if *record > 0 {
            touched += 1;
        }
    }
    let mut acc = 1;
    for record in records {
        acc = acc.rotate_left(7) ^ *record;
        if acc == 0 {
            acc = 11;
        }
    }
    *digest ^= acc;
    touched
}

fn tally_input(rows: &[String]) -> i64 {
    let mut errors = 0;
    let mut sum = 0;
    for line in rows {
        let value = match line.parse::<i64>() {
            Ok(parsed) => parsed,
            Err(_) => {
                errors += 1;
                continue;
            }
        };
        sum += value;
    }
    sum + errors
}

fn scan_report(report: &[String]) -> u32 {
    let mut blanks = 0;
    let mut longest = 0;
    let mut seen = 0;
    for raw in report {
        seen += raw.len() as u32;
    }
    longest + blanks + seen
}

fn merge_batches(entries: &[u64], state: &mut u64) -> u64 {
    let mut merged = 0;
    for entry in entries {
        merged += *entry;
    }
    merged ^= *state;
    merged
}

fn count_valid(rows: &[String]) -> i64 {
    let mut errors = 0;
    let mut valid = 0;
    for line in rows {
        let value = i64::from(!line.is_empty());
        if value > 0 {
            valid += 1;
        }
    }
    valid - errors
}

fn sum_marked(rows: &[String]) -> i64 {
    let mut errors = 0;
    let mut sum = 0;
    for line in rows {
        let value = line.len() as i64;
        sum += value;
    }
    sum - errors
}
