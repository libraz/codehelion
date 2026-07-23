// Seed source for the synthetic evaluation corpus.
// Hand-authored; the variant files derive from this one.

fn sum_even(values: &[i32]) -> i32 {
    let mut total = 0;
    for value in values {
        if value % 2 == 0 {
            total += value;
        }
    }
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

struct Counter {
    count: u32,
}

impl Counter {
    fn value(&self) -> u32 {
        self.count
    }
}
