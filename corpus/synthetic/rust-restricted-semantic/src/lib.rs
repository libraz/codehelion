pub fn odd_values(values: &[u64]) -> Vec<u64> {
    values.iter().filter(|value| **value % 2 == 1).map(|value| *value).collect()
}

pub fn even_values(values: &[u64]) -> Vec<u64> {
    values.iter().filter(|value| **value % 2 == 0).map(|value| *value).collect()
}

pub fn different_sequence(values: &[u64]) -> Vec<u64> {
    values.iter().map(|value| value.saturating_add(1)).collect()
}

pub fn propagate_first(value: Result<u64, ()>) -> Result<u64, ()> {
    Ok(value?)
}

pub fn propagate_second(value: Result<u64, ()>) -> Result<u64, ()> {
    Ok(value?)
}

pub fn propagate_transformed(value: Result<u64, ()>) -> Result<u64, ()> {
    Ok(value?.saturating_add(1))
}

pub fn optional_first(value: Option<u64>) -> Option<u64> {
    Some(value?)
}

pub fn optional_second(value: Option<u64>) -> Option<u64> {
    Some(value?)
}

pub fn optional_transformed(value: Option<u64>) -> Option<u64> {
    Some(value?.saturating_add(1))
}

pub fn validate_optional_first(value: Option<u64>) -> bool {
    if value.is_some() { true } else { false }
}

pub fn validate_optional_second(value: Option<u64>) -> bool {
    if value.is_some() { false } else { true }
}

pub fn validate_optional_compound(value: Option<u64>, keep: bool) -> bool {
    if value.is_some() && keep { true } else { false }
}

pub fn validate_result_first(value: Result<u64, ()>) -> bool {
    if value.is_ok() { true } else { false }
}

pub fn validate_result_second(value: Result<u64, ()>) -> bool {
    if value.is_ok() { false } else { true }
}

pub fn validate_result_compound(value: Result<u64, ()>, keep: bool) -> bool {
    if value.is_ok() && keep { true } else { false }
}

pub fn inspect_first(path: &std::path::Path) {
    let _file = std::fs::File::open(path).unwrap();
}

pub fn inspect_second(path: &std::path::Path) {
    let _file = std::fs::File::open(path).unwrap();
}

pub fn inspect_third(path: &std::path::Path) {
    let _file = std::fs::File::open(path).unwrap();
}

pub fn round_trip_first(value: u64) -> u64 {
    value.to_string().parse::<u64>().unwrap_or_default()
}

pub fn round_trip_second(value: u64) -> u64 {
    value.to_string().parse::<u64>().unwrap_or_default()
}

pub fn formats_twice(value: u64) -> usize {
    value.to_string().to_string().len()
}
