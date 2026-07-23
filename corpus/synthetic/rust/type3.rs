// Type-3 variant of seed.rs: one extra statement added inside sum_even.

fn sum_even(values: &[i32]) -> i32 {
    let mut total = 0;
    let mut seen = 0;
    for value in values {
        seen += 1;
        if value % 2 == 0 {
            total += value;
        }
    }
    let _ = seen;
    total
}

fn max_run(flags: &[bool]) -> usize {
    let mut best = 0;
    let mut current = 0;
    for flag in flags {
        if *flag {
            current += 1;
            if current > best {
                best = current;
            }
        } else {
            current = 0;
        }
    }
    best
}
