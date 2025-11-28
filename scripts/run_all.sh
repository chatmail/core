#!/bin/sh
#
# Build the Delta Chat Core Rust library and Python wheels

set -e -x

# Perform clean build of core and install.

# compile core lib

cargo build --release -p deltachat_ffi

# Statically link against libdeltachat.a.
export DCC_RS_DEV="$PWD"
export DCC_RS_TARGET=release

export PYTHONDONTWRITEBYTECODE=1
cd python

TOXWORKDIR=.docker-tox
# prepare a clean tox run
rm -rf tests/__pycache__
rm -rf src/deltachat/__pycache__
mkdir -p $TOXWORKDIR

# disable live-account testing to speed up test runs and wheel building
# XXX we may switch on some live-tests on for better ensurances 
# Note that the independent remote_tests_python step does all kinds of
# live-testing already. 
unset CHATMAIL_DOMAIN

# Try to build wheels for a range of interpreters, but don't fail if they are not available.
# E.g. musllinux_1_1 does not have PyPy interpreters as of 2022-07-10
tox --workdir "$TOXWORKDIR" -e py310,py311,py312,py313,pypy310 --skip-missing-interpreters true

auditwheel repair "$TOXWORKDIR"/wheelhouse/deltachat* -w "$TOXWORKDIR/wheelhouse"
