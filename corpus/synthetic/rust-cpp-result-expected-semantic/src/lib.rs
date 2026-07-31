pub fn direct(value: Result<u64, ()>) -> Result<u64, ()> {
    Ok(value?)
}

pub fn transformed(value: Result<u64, ()>) -> Result<u64, ()> {
    Ok(value?.saturating_add(1))
}

pub fn present(value: Result<u64, ()>) -> bool {
    if value.is_ok() { true } else { false }
}

pub fn present_with_flag(value: Result<u64, ()>, keep: bool) -> bool {
    if value.is_ok() && keep { true } else { false }
}
