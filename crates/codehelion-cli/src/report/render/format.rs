//! Column, count and duration formatting shared by the text sections.

use crate::report::Member;

/// Digits in the largest number a listing of `count` entries writes.
pub(super) const fn decimal_width(count: usize) -> usize {
    let mut digits = 1;
    let mut remaining = count / 10;
    while remaining > 0 {
        digits += 1;
        remaining /= 10;
    }
    digits
}

/// The printed width of a string.
///
/// Character count rather than display width: paths and identifiers in the
/// languages this tool reads are ASCII, and the one column that could hold
/// anything else is the last on its line, where a mismeasured pad shows as
/// nothing.
pub(super) fn width(text: &str) -> usize {
    text.chars().count()
}

/// Pad `text` to `width` columns, measuring what was written rather than what
/// the styling added.
pub(super) fn pad(text: &str, painted: String, width: usize) -> String {
    let mut padded = painted;
    for _ in self::width(text)..width {
        padded.push(' ');
    }
    padded
}

/// A count with thousands separators, because six-digit token counts are read
/// as often as they are compared.
pub(super) fn thousands(value: u64) -> String {
    let digits = value.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped
}

/// How many of `total` a limit left out, as the count a note prints.
pub(super) fn remaining(total: usize, limit: usize) -> u64 {
    u64::try_from(total.saturating_sub(limit)).unwrap_or(u64::MAX)
}

/// `1 group` or `12 groups`, so a summary line does not read as a template.
pub(super) fn plural(count: u64, noun: &str) -> String {
    format!("{} {}", thousands(count), noun_form(count, noun))
}

/// The singular or plural noun for `count`.
pub(super) fn noun_form(count: u64, noun: &str) -> String {
    if count == 1 {
        noun.to_string()
    } else {
        format!("{noun}s")
    }
}

/// Where one occurrence sits, in the form an editor and a grep both accept.
pub(super) fn member_location(member: &Member) -> String {
    format!("{}:{}-{}", member.file, member.start_line, member.end_line)
}

/// The enclosing unit, parenthesised, or nothing when parsing recovered none.
pub(super) fn member_unit(member: &Member) -> String {
    member
        .unit
        .as_deref()
        .map_or_else(String::new, |name| format!(" ({name})"))
}

/// The singular or plural of a noun whose plural is not its singular and an
/// `s`.
pub(super) const fn noun_form_of<'a>(
    count: u64,
    singular: &'a str,
    plural_form: &'a str,
) -> &'a str {
    if count == 1 { singular } else { plural_form }
}

/// How many things are in a list, written the way every other count is.
pub(super) fn count(entries: &[String]) -> String {
    thousands(u64::try_from(entries.len()).unwrap_or(u64::MAX))
}

/// An elapsed time, at the precision a reader can act on.
///
/// Tenths below a minute and whole seconds above it: nobody arranges reuse
/// over a hundredth of a second, and nobody reads four significant figures of
/// a five-minute scan.
pub(super) fn seconds(elapsed: std::time::Duration) -> String {
    let value = elapsed.as_secs_f64();
    if value < 60.0 {
        format!("{value:.1}s")
    } else {
        format!("{}s", thousands(elapsed.as_secs()))
    }
}
