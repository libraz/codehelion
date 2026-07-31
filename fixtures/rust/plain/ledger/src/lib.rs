//! Entries and the totals drawn from them.

/// One movement of money.
pub struct Entry {
    /// What it was for.
    pub label: String,
    /// How much, in the smallest unit of the currency.
    pub amount: i64,
}

/// Everything that came in.
///
/// Deliberately near-identical to [`credits`]: the two differ only in the
/// comparison, which is the smallest difference a type-2 reading has to
/// survive and the largest one a type-1 reading may not.
pub fn debits(entries: &[Entry]) -> i64 {
    let mut total = 0;
    for entry in entries {
        if entry.amount < 0 {
            total += entry.amount;
        }
    }
    total
}

/// Everything that went out.
pub fn credits(entries: &[Entry]) -> i64 {
    let mut total = 0;
    for entry in entries {
        if entry.amount > 0 {
            total += entry.amount;
        }
    }
    total
}

/// The labels of every entry, in order.
pub fn labels(entries: &[Entry]) -> Vec<String> {
    entries.iter().map(|entry| entry.label.clone()).collect()
}

/// Labels from the entries whose amount is odd.
///
/// The direct receiver chain is a closed def-use fixture: the `filter` output
/// is immediately consumed by `map`.
pub fn odd_labels(entries: &[Entry]) -> Vec<String> {
    entries
        .iter()
        .filter(|entry| entry.amount % 2 != 0)
        .map(|entry| entry.label.clone())
        .collect()
}

/// Labels from the entries whose amount is even.
///
/// The binding deliberately breaks the direct receiver form. It is valid Rust
/// but is outside the helper's limited def-use vocabulary.
pub fn even_labels(entries: &[Entry]) -> Vec<String> {
    let selected = entries.iter().filter(|entry| entry.amount % 2 == 0);
    selected.map(|entry| entry.label.clone()).collect()
}

/// Round-trips an integer through the standard textual representation.
///
/// This is the closed serialization fixture: the helper must resolve both
/// `ToString::to_string` and `str::parse`, rather than infer either API from
/// its spelling.
pub fn round_trip_number(value: u64) -> u64 {
    value.to_string().parse::<u64>().unwrap_or_default()
}

/// Opens one standard file for the duration of this function.
pub fn inspect_file(path: &std::path::Path) -> std::io::Result<()> {
    let _file = std::fs::File::open(path)?;
    Ok(())
}

/// Opens two files, which is deliberately outside the one-resource form.
pub fn inspect_two_files(
    first: &std::path::Path,
    second: &std::path::Path,
) -> std::io::Result<()> {
    let _first = std::fs::File::open(first)?;
    let _second = std::fs::File::open(second)?;
    Ok(())
}
