#!/usr/bin/env bash
set -euo pipefail

# Install Rust
#
# Path from https://forge.rust-lang.org/infra/other-installation-methods.html
#
# Avoid using rustup here as it depends on reading /proc/self/exe and
# has problems running under QEMU.
RUST_VERSION=1.93.0

ARCH="$(uname -m)"
test -f "/lib/libc.musl-$ARCH.so.1" && LIBC=musl || LIBC=gnu

curl "https://static.rust-lang.org/dist/rust-${RUST_VERSION}-$ARCH-unknown-linux-$LIBC.tar.gz" | tar xz
cd "rust-${RUST_VERSION}-$ARCH-unknown-linux-$LIBC"
./install.sh --prefix=/usr --components=rustc,cargo,"rust-std-$ARCH-unknown-linux-$LIBC"
rustc --version
cd ..
rm -fr "rust-${RUST_VERSION}-$ARCH-unknown-linux-$LIBC"
