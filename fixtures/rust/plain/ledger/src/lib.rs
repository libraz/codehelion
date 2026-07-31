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
