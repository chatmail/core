#!/usr/bin/env bash
set -euo pipefail

set -x
if ! test -v SSHTARGET; then
	echo >&2 SSHTARGET is not set
	exit 1
fi
BUILDDIR=ci_builds/chatmailcore

echo "--- Copying files to $SSHTARGET:$BUILDDIR"

rsync -az --delete --mkpath --files-from=<(git ls-files) ./ "$SSHTARGET:$BUILDDIR"

echo "--- Running Python tests remotely"

ssh -oBatchMode=yes -- "$SSHTARGET" <<_HERE
    set +x -e

    # make sure all processes exit when ssh dies
    shopt -s huponexit

    export RUSTC_WRAPPER=\`command -v sccache\`
    cd $BUILDDIR
    export CHATMAIL_DOMAIN=$CHATMAIL_DOMAIN

    scripts/make-rpc-testenv.sh
    . venv/bin/activate

    cd deltachat-rpc-client
    pytest -n6 $@
_HERE
