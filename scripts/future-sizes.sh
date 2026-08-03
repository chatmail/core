#!/usr/bin/env bash
set -euo pipefail

# Report the largest async-fn futures using rustc's unstable -Zprint-type-sizes.
#
# Usage: scripts/future-sizes.sh [TOP_N]     (default: 30)
#
# Uses a dedicated target dir so the normal build cache is untouched
# and repeated runs only recompile the core crate itself.

TOP_N="${1:-30}"

export CARGO_TARGET_DIR="target/type-sizes"
export RUSTFLAGS="-Zprint-type-sizes"
export RUSTC_BOOTSTRAP=1

# Warm the dependency cache so their output doesn't pollute the report later.
cargo check --locked --release -p deltachat >/dev/null

# Recompile only the core crate (release) capture its type-size report.
cargo clean --locked --release -p deltachat
report="$CARGO_TARGET_DIR/type-sizes.txt"
if ! cargo check --locked --release -p deltachat >"$report"; then
    tail -20 "$report"
    exit 1
fi

sizes=$(rg '^print-type-size type: `\{async fn body of (.*)\(\)\}`: ([0-9]+) bytes' \
    -or '$2 $1' "$report" | sort -rn | uniq)
if [ -z "$sizes" ]; then
    echo "error: no type-size output found, see $report" >&2
    exit 1
fi

echo "Largest async fn futures in deltachat (top $TOP_N, bytes):"
head -"$TOP_N" <<<"$sizes"

echo
echo "Full report (all types, with per-field breakdown): $report"
