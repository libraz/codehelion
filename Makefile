.DEFAULT_GOAL := help

CARGO ?= cargo

# Whole-workspace runs compile every target once and exit, which is the case
# incremental compilation cannot pay off in: it splits each crate into far more
# codegen units and leaves a per-crate cache behind, and the caches grow to
# gigabytes over a few days of these runs. `build` and `run` are the interactive
# ones and keep it.
ONESHOT := CARGO_INCREMENTAL=0

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

## --- auto-fix -------------------------------------------------------------

.PHONY: format
format: ## Auto-fix everything: apply clippy fixes, then format
	$(ONESHOT) $(CARGO) clippy --fix --allow-dirty --allow-staged --workspace --all-targets --all-features
	$(CARGO) fmt --all

.PHONY: fix
fix: format ## Alias for `format`

## --- checks (CI parity) ---------------------------------------------------

.PHONY: format-check
format-check: ## Check formatting without modifying files
	$(CARGO) fmt --all --check

.PHONY: lint
lint: ## Static analysis only: clippy with warnings as errors
	$(ONESHOT) $(CARGO) clippy --workspace --all-targets --all-features -- -D warnings

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
	$(ONESHOT) sh scripts/verify-packaging.sh

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
test: ## Run the full test suite
	$(ONESHOT) $(CARGO) test --workspace --all-targets --all-features --no-fail-fast
	# `--all-targets` excludes doc examples, so a second run is what actually
	# compiles them. An example that no longer builds is documentation that is
	# wrong, and nothing else here would say so.
	$(ONESHOT) $(CARGO) test --workspace --doc --all-features --no-fail-fast

.PHONY: doc
doc: ## Build docs, failing on warnings
	RUSTDOCFLAGS="-D warnings" $(ONESHOT) $(CARGO) doc --workspace --no-deps --all-features

.PHONY: eval
eval: ## Show detection accuracy over the generated and materialized corpora
	$(CARGO) test -p codehelion --test corpus_accuracy -- --nocapture
	$(CARGO) test -p codehelion --test labeled_precision -- --nocapture
	$(CARGO) test -p codehelion --test candidate_stages -- --nocapture

.PHONY: check
check: format-check lint verify-helper-boundaries verify-artifact-boundaries verify-packaging test doc ## Run every CI check locally

## --- convenience ----------------------------------------------------------

.PHONY: build
build: ## Build the release binary
	$(CARGO) build --release -p codehelion

.PHONY: run
run: ## Run the binary (pass args via ARGS="...")
	$(CARGO) run -p codehelion -- $(ARGS)

.PHONY: audit
audit: ## Check dependencies for advisories, bans and license issues
	$(CARGO) deny check

.PHONY: coverage
coverage: ## Generate an HTML coverage report (needs cargo-llvm-cov)
	$(ONESHOT) $(CARGO) llvm-cov --workspace --all-features --html

.PHONY: hooks
hooks: ## Install the repo's git hooks
	git config core.hooksPath .githooks
	@echo "git hooks installed (core.hooksPath -> .githooks)"

.PHONY: clean
clean: ## Remove build artifacts
	$(CARGO) clean
