# Calibration

Calibration is the answer to "how close was the estimate?". A source scan can
estimate what a clone group costs; only two real builds can say what removing it
actually took out of the artifact. Calibration records one against the other.

## Which figure is which

Savings are reported as separate quantities and never collapsed into one number:

| Figure | What it is |
|---|---|
| observed | what the artifact contains today, measured |
| duplicated | of that, what is a repeat of something else |
| retained | what would remain reachable if a duplicate went |
| upper bound | the most that could come out under the most favourable assumption |
| estimated | what a model predicts for one clone group |
| verified | what two real builds actually differed by |

`upper_bound_savings` is not a reduction guarantee, and is never displayed as
one. Only the verified figure comes from a measurement of the thing itself, and
even that means what it says only under the conditions below.

## Recording a measurement

A measurement is recorded by `artifact compare` when it is given `--source-run`
and `--clone-group` together with `--before-build-variant` and
`--after-build-variant`. The group's saved estimate is then set beside the size
difference the two artifacts actually show. The estimate it needs comes from an
earlier `artifact analyze` run with `--source-run` and `--build-variant`.

```sh
codehelion artifact analyze before/app.wasm --source-run 1 --build-variant build-variant.json
# ... remove the duplication and rebuild ...
codehelion artifact compare before/app.wasm after/app.wasm \
  --source-run 1 --clone-group 0f5065d5 \
  --before-build-variant build-variant.json \
  --after-build-variant build-variant.json
```

## What a verified figure means, and does not

The `verified_savings_bytes` that comes out of a calibrated comparison is the
whole observed size difference between the two artifacts, assigned to the one
clone group named by `--clone-group`. What the comparison establishes is that
both artifacts are the same format and were built under the same declared build
variant, and nothing beyond that: a pair of builds that also picked up a
dependency update or a toolchain change reports that difference too, as the
measured saving of the refactoring. The number means what it says only for a pair
that differs in nothing else.

## Summarizing what has been recorded

```sh
codehelion artifact calibration                 # summarize the recorded measurements
codehelion artifact calibration --source-run 1  # summarize a particular source scan
```

`artifact calibration` reads measurements rather than taking them, so it
summarizes nothing until some exist.

## Comparing two summaries

```sh
codehelion artifact calibration --format json --output calibration.json
# ... later ...
codehelion artifact calibration --baseline calibration.json
```

`--baseline <file>` takes a calibration report written earlier and prints the
change in each error statistic, overall and per stratum, beside the current
value. It compares and reports only: no threshold is enforced and nothing fails
on a difference. A report written under a different calibration report schema is
refused rather than compared against.
