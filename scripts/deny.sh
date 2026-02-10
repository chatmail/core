#!/bin/sh

# Update package cache without changing the lockfile.
cargo update --dry-run

cargo deny --workspace --all-features --locked check -D warnings
