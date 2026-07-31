pub fn copied() -> Vec<u64> {
    let values = vec![1];
    values.iter().copied().collect()
}

pub fn defaulted(value: Option<u64>) -> u64 {
    match value {
        Some(value) => value,
        None => 0,
    }
}
