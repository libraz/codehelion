# Security policy

## Reporting a vulnerability

Report privately, not through the public issue tracker:

- **Preferred:** GitHub's private vulnerability reporting, from the repository's
  Security tab.
- **Alternative:** email `libraz@libraz.net`.

Please include the codehelion version, the platform, the command you ran, and an
input that reproduces the problem — or a description of its shape, if the input
is a tree you cannot share.

An acknowledgement should arrive within about a week. There is no committed
remediation deadline, and no bounty.

## Supported versions

Pre-1.0. Fixes land on the latest release only; older versions are not patched.

## What is in scope

codehelion reads code that it does not trust — that is the whole job — so the
parsing and analysis path is the interesting attack surface. In scope:

- A crafted source file, binary artifact, debug companion, archive, baseline or
  configuration file that causes a crash, a hang, unbounded memory growth, or
  reads outside the tree being scanned.
- Any path by which scanning a tree executes code from that tree without the
  corresponding `--allow-execution` flag. Nothing in a scanned tree is supposed
  to run by default, and `--untrusted` is supposed to permit no execution at
  all.
- Any network access. codehelion is meant to have none: `cargo-deny` refuses the
  common HTTP stacks and `clippy.toml` disallows sockets in the scan path. A
  reachable network call is a vulnerability even if it is benign.
- Any path by which source code or analysis results leave the machine.
- Escapes from the compiler-helper process boundary, or a helper response that
  compromises the CLI that invoked it.

## What is not in scope

- Resource ceilings behaving as documented. File-size, parse-timeout, candidate
  and memory limits exist so that a hostile tree cannot run the scan out of
  resources; a large input that is rejected or truncated with a report entry is
  working as intended. A ceiling that can be bypassed is in scope.
- Vulnerabilities in the code being analysed. codehelion reports duplication; it
  is not a vulnerability scanner and does not claim to be.
- Findings that require an attacker to already control the machine the scan runs
  on, or to have write access to codehelion's own configuration and database.
- Semantic mode running a build script after `--allow-execution=build-script`
  was passed. That flag exists to grant exactly that.

## Notes on the implementation

First-party code forbids `unsafe`. Memory-unsafety in a dependency is still in
scope for a report — bundled SQLite and the binary-format parsers are C or
contain unsafe Rust — and dependency advisories are checked by `cargo-deny` in
CI.

codehelion has not been independently audited.
