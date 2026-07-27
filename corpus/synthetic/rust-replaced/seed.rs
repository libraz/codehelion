// Seed for the statement-replacement corpus. Every step of the loop and of the
// tail is an independent accumulation, so a step can be swapped for a different
// one without the rest ceasing to make sense — which is what lets a variant
// change statements in place instead of adding or removing them. Authored in
// the controlled one-statement-per-line style the mutation generator assumes.

fn summarise(samples: &[i32]) -> i32 {
    let mut total = 0;
    let mut spread = 0;
    let mut peak = 0;
    let mut dips = 0;
    for sample in samples {
        let value = *sample;
        total += value;
        if value > peak {
            peak = value;
        }
        if value < 0 {
            dips += 1;
        }
        spread += value * value;
    }
    let width = samples.len() as i32;
    total -= dips;
    total += spread / 4;
    total += peak;
    total -= width;
    total
}
