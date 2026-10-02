.DEFAULT_GOAL := help

CARGO ?= cargo

# Incremental compilation is off for every cargo invocation in this tree; the
# reasoning is in `.cargo/config.toml`, next to the setting.
#
# Superseded artifacts are the other half. Cargo never removes the ones a later
# build replaces, so weeks of rebuilds leave tens of gigabytes nothing can link
# against again, and `cargo clean` is the only thing that collects them. The
# cap below sweeps the oldest of those before a build instead: what the current
# tree still needs was written most recently and survives, so this costs a
# relink at worst, where `clean` costs the whole workspace.
TARGET_MAXSIZE ?= 20GB
NESTED_TARGET_AGE ?= 7

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

## --- auto-fix -------------------------------------------------------------

.PHONY: format
format: sweep ## Auto-fix everything: apply clippy fixes, then format
	$(CARGO) clippy --fix --allow-dirty --allow-staged --workspace --all-targets --all-features
	$(CARGO) fmt --all

.PHONY: fix
fix: format ## Alias for `format`

## --- checks (CI parity) ---------------------------------------------------

.PHONY: format-check
format-check: ## Check formatting without modifying files
	$(CARGO) fmt --all --check

.PHONY: lint
lint: sweep ## Static analysis only: clippy with warnings as errors
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings

.PHONY: verify-helper-boundaries
verify-helper-boundaries: ## Verify core and CLI do not link compiler adapter dependencies
	sh scripts/verify-helper-boundaries.sh

.PHONY: verify-artifact-boundaries
verify-artifact-boundaries: ## Verify the source engine does not link artifact crates
	sh scripts/verify-artifact-boundaries.sh

# A crate is packaged as a directory of its own, so anything it reads from
# outside that directory is there in the working tree and gone in the tarball.
# Nothing else builds a crate that way, which is why the failure otherwise
# waits until a release is already tagged.
.PHONY: verify-packaging
verify-packaging: ## Verify every publishable crate builds from its own package
	sh scripts/verify-packaging.sh

.PHONY: verify-artifact-fixtures
verify-artifact-fixtures: ## Build and verify real WASM and ELF artifact fixtures (Linux)
	sh scripts/verify-artifact-fixtures.sh

.PHONY: verify-macho-artifact-fixtures
verify-macho-artifact-fixtures: ## Build and verify a real Mach-O and dSYM fixture (macOS)
	sh scripts/verify-macho-artifact-fixtures.sh

.PHONY: verify-pe-artifact-fixtures
verify-pe-artifact-fixtures: ## Build and verify real PE/PDB fixtures (Windows)
	pwsh -NoProfile -File scripts/verify-pe-artifact-fixtures.ps1

.PHONY: test
test: sweep ## Run the full test suite
	$(CARGO) test --workspace --all-targets --all-features --no-fail-fast
	# `--all-targets` excludes doc examples, so a second run is what actually
	# compiles them. An example that no longer builds is documentation that is
	# wrong, and nothing else here would say so.
	$(CARGO) test --workspace --doc --all-features --no-fail-fast

.PHONY: doc
doc: sweep ## Build docs, failing on warnings
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --workspace --no-deps --all-features

.PHONY: eval
eval: sweep ## Show detection accuracy over the generated and materialized corpora
	$(CARGO) test -p codehelion --test corpus_accuracy -- --nocapture
	$(CARGO) test -p codehelion --test labeled_precision -- --nocapture
	$(CARGO) test -p codehelion --test candidate_stages -- --nocapture

.PHONY: readme-sample
readme-sample: ## Print the sample scan report the READMEs show
	# Scans this tree the way the READMEs say the sample was produced. Reuse is
	# off so the summary reads the same whether or not a previous run is on
	# hand: a cache hit words that line differently, and a sample whose shape
	# depends on the operator's database is not a sample anyone can reproduce.
	#
	# The block is printed, not substituted: the READMEs wrap it in prose, and
	# the leading path is shortened by hand so the sample does not publish
	# whoever ran it. Paste it into both READMEs; `docs_wording` then checks
	# that the occurrences it names still resolve.
	$(CARGO) run --release -p codehelion -- scan . --mode structural --limit 2 --no-reuse

.PHONY: check
check: sweep format-check lint verify-helper-boundaries verify-artifact-boundaries verify-packaging test doc ## Run every CI check locally

## --- convenience ----------------------------------------------------------

.PHONY: build
build: sweep ## Build the release binary
	$(CARGO) build --release -p codehelion

.PHONY: run
run: ## Run the binary (pass args via ARGS="...")
	# The edit-run loop is what incremental compilation pays off in, so this is
	# the one target that opts back in to it.
	CARGO_INCREMENTAL=1 $(CARGO) run -p codehelion -- $(ARGS)

.PHONY: audit
audit: ## Check dependencies for advisories, bans and license issues
	$(CARGO) deny check

.PHONY: coverage
coverage: sweep ## Generate an HTML coverage report (needs cargo-llvm-cov)
	$(CARGO) llvm-cov --workspace --all-features --html

.PHONY: hooks
hooks: ## Install the repo's git hooks
	git config core.hooksPath .githooks
	@echo "git hooks installed (core.hooksPath -> .githooks)"

# A target directory nested inside this one -- the scratch tree
# verify-packaging builds each package in, or whatever a one-off
# CARGO_TARGET_DIR left behind -- does not count against the size cap, which
# only accounts for artifacts of the workspace cargo was pointed at. Each one
# caches a run that rebuilds from scratch anyway, so age is the only thing worth
# keeping one by, and the CACHEDIR.TAG cargo writes into every target directory
# it creates is what tells them apart from `debug` and `release`.
#
# None of this runs on CI, where the runner is thrown away after the job.
.PHONY: sweep
sweep: ## Drop superseded build artifacts, keeping target under TARGET_MAXSIZE
	@test -d target || exit 0; \
	test -z "$$CI" || exit 0; \
	find target -mindepth 1 -maxdepth 1 -type d -mtime +$(NESTED_TARGET_AGE) \
		| while read -r dir; do \
			test -e "$$dir/CACHEDIR.TAG" || continue; \
			echo "sweep: removing stale nested target directory $$dir"; \
			rm -rf "$$dir"; \
		done; \
	command -v cargo-sweep >/dev/null 2>&1 || { \
		echo "sweep: cargo-sweep is not installed, so target/ grows unbounded."; \
		echo "sweep:   cargo install cargo-sweep"; \
		exit 0; \
	}; \
	$(CARGO) sweep --maxsize $(TARGET_MAXSIZE)

.PHONY: clean
clean: ## Remove build artifacts
	$(CARGO) clean
