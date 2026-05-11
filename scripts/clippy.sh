#!/bin/sh
# Run clippy for all Rust code in the project.
#
# To check, run
#   scripts/clippy.sh 
#
# To automatically fix warnings, run
#   scripts/clippy.sh --fix --allow-dirty
cargo clippy --workspace --all-targets --all-features "$@" -- -D warnings
