#!/bin/sh
# Build every publishable crate from its own package, the way a dependent will.
#
# `cargo package` verifies a crate against the packaged copies of its workspace
# siblings rather than against the working tree, which is the whole point: it
# is the only build that reads a crate as a package.
#
# Those copies are addressed by name and version, and every version here stays
# 0.1.0 until the first release. Cargo caches the extracted sources under that
# name in the shared cargo home and the objects built from them under it in a
# target directory — and since the timestamps inside a `.crate` are
# normalised, repacking the same version with different contents leaves both
# looking untouched. A second run then reports on the first run's code, in
# whichever direction is wrong: a removal that should fail passes, an addition
# that should pass fails.
#
# So this crate's own entries are dropped before every run. Third-party
# dependencies are left alone — they are addressed by a version that does move
# when their contents do, and rebuilding them each time would cost minutes for
# nothing. The build is kept out of the workspace's own target directory for
# the same reason in reverse: these objects are built from packaged sources
# and are not the ones a test run should pick up.
set -eu

cargo_cmd=${CARGO:-cargo}
cargo_home=${CARGO_HOME:-$HOME/.cargo}
verify_dir="${CARGO_TARGET_DIR:-target}/packaging"

if [ -d "$cargo_home/registry/src" ]; then
    find "$cargo_home/registry/src" -maxdepth 2 -type d -name 'codehelion*' \
        -exec rm -rf {} +
fi
rm -rf "$verify_dir/package"
if [ -d "$verify_dir" ]; then
    find "$verify_dir" -maxdepth 3 -name '*codehelion*' -exec rm -rf {} +
fi

# Uncommitted work is packaged as it stands: the question is whether the tree
# in front of you can be published, and refusing to answer until the change is
# committed asks it too late.
CARGO_TARGET_DIR="$verify_dir" exec "$cargo_cmd" \
    package --workspace --locked --allow-dirty "$@"
