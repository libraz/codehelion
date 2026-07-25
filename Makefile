.DEFAULT_GOAL := help

CARGO ?= cargo

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

## --- auto-fix -------------------------------------------------------------

.PHONY: format
format: ## Auto-fix everything: apply clippy fixes, then format
	$(CARGO) clippy --fix --allow-dirty --allow-staged --workspace --all-targets --all-features
	$(CARGO) fmt --all

.PHONY: fix
fix: format ## Alias for `format`

## --- checks (CI parity) ---------------------------------------------------

.PHONY: format-check
format-check: ## Check formatting without modifying files
	$(CARGO) fmt --all --check

.PHONY: lint
lint: ## Static analysis only: clippy with warnings as errors
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings

.PHONY: test
test: ## Run the full test suite
	$(CARGO) test --workspace --all-targets --all-features

.PHONY: doc
doc: ## Build docs, failing on warnings
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --workspace --no-deps --all-features

.PHONY: eval
eval: ## Show detection accuracy over the committed corpora
	$(CARGO) test -p codehelion-cli --test corpus_accuracy -- --nocapture

.PHONY: check
check: format-check lint test doc ## Run every CI check locally

## --- convenience ----------------------------------------------------------

.PHONY: build
build: ## Build the release binary
	$(CARGO) build --release -p codehelion-cli

.PHONY: run
run: ## Run the binary (pass args via ARGS="...")
	$(CARGO) run -p codehelion-cli -- $(ARGS)

.PHONY: audit
audit: ## Check dependencies for advisories, bans and license issues
	$(CARGO) deny check

.PHONY: coverage
coverage: ## Generate an HTML coverage report (needs cargo-llvm-cov)
	$(CARGO) llvm-cov --workspace --all-features --html

.PHONY: hooks
hooks: ## Install the repo's git hooks
	git config core.hooksPath .githooks
	@echo "git hooks installed (core.hooksPath -> .githooks)"

.PHONY: clean
clean: ## Remove build artifacts
	$(CARGO) clean
