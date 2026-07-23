// Seed for the literal-category corpus. One function carrying a literal of each
// category (integer, float, string, char) so that Type-2 variants can change a
// single category at a time. Controlled one-statement-per-line style.

fn classify(level: i32) -> i32 {
    let threshold = 10;
    let ratio = 1.5;
    let label = "warn";
    let marker = 'x';
    let mut result = level;
    if result > threshold {
        result += 1;
    }
    let _ = ratio;
    let _ = label;
    let _ = marker;
    result
}
