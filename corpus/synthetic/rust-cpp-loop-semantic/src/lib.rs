pub fn collect_direct(values: &[u64]) -> Vec<&u64> {
    let mut output = Vec::new();
    for value in values {
        output.push(value);
    }
    output
}

pub fn sum_direct(values: &[u64]) -> u64 {
    let mut total = 0;
    for value in values {
        total += *value;
    }
    total
}

pub fn collect_transformed(values: &[u64]) -> Vec<u64> {
    let mut output = Vec::new();
    for value in values {
        output.push(value.saturating_add(1));
    }
    output
}

pub fn sum_transformed(values: &[u64]) -> u64 {
    let mut total = 0;
    for value in values {
        total += value.saturating_add(1);
    }
    total
}
