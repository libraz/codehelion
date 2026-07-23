# Test fixtures

Small, self-contained inputs for unit and integration tests. Everything here is
committed and should stay tiny (tens of lines per file) so tests remain fast and
readable.

Fixtures are grouped by the behaviour they exercise, e.g. a snippet that a
frontend must tokenize, or a pair of near-identical functions a detector must
flag. Larger, accuracy-oriented inputs belong in the top-level `corpus/`
instead — see `corpus/README.md`.
