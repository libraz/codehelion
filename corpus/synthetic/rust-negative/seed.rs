// Seed for the negative corpus. Four functions that share the same skeleton —
// accumulate over a slice under a branch, return the accumulator — while
// computing genuinely different things. They are what a detector tempted by
// shape alone would group together, and none of the pairings among them is a
// clone. Authored in the controlled one-statement-per-line style the mutation
// generator assumes.

fn sum_positive(values: &[i32]) -> i32 {
    let mut total = 0;
    for value in values {
        if *value > 0 {
            total += value;
        }
    }
    total
}

fn longest_run(values: &[i32]) -> i32 {
    let mut best = 0;
    let mut run = 0;
    for value in values {
        if *value > 0 {
            run += 1;
        } else {
            run = 0;
        }
        if run > best {
            best = run;
        }
    }
    best
}

fn count_transitions(values: &[i32]) -> i32 {
    let mut changes = 0;
    let mut previous = 0;
    for value in values {
        if *value != previous {
            changes += 1;
        }
        previous = *value;
    }
    changes
}

fn narrowest_gap(values: &[i32], limit: i32) -> i32 {
    let mut gap = limit;
    let mut previous = 0;
    for value in values {
        let distance = (*value - previous).abs();
        if distance < gap {
            gap = distance;
        }
        previous = *value;
    }
    gap
}
