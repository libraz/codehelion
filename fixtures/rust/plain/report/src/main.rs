//! Prints a summary of a fixed ledger.

use ledger::{Entry, credits, debits, labels};

fn main() {
    let entries = vec![
        Entry {
            label: "rent".to_string(),
            amount: -95_000,
        },
        Entry {
            label: "invoice".to_string(),
            amount: 240_000,
        },
    ];
    println!("in  {}", credits(&entries));
    println!("out {}", debits(&entries));
    println!("for {}", labels(&entries).join(", "));
}
