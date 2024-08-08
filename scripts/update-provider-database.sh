#!/usr/bin/env bash
# Updates provider database.
# Returns 1 if the database is changed, 0 otherwise.
set -euo pipefail

export TZ=UTC

# Provider database revision.
REV=956475aff51caf577067de1f747a788899fd63fc

CORE_ROOT="$PWD"
TMP="$(mktemp -d)"
git clone --filter=blob:none https://github.com/deltachat/provider-db.git "$TMP"
cd "$TMP"
git checkout "$REV"
DATE=$(git show -s --format=%cs)
"$CORE_ROOT"/scripts/create-provider-data-rs.py "$TMP/_providers" "$DATE" >"$CORE_ROOT/src/provider/data.rs"
rustfmt "$CORE_ROOT/src/provider/data.rs"
rm -fr "$TMP"

cd "$CORE_ROOT"
test -z "$(git status --porcelain src/provider/data.rs)"
