# Delta Chat RPC server

This program provides a [JSON-RPC 2.0](https://www.jsonrpc.org/specification) interface to DeltaChat
over standard I/O.

## Install

To download binary pre-builds check the [releases page](https://github.com/chatmail/core/releases).
Rename the downloaded binary to `deltachat-rpc-server` and add it to your `PATH`.

To install from source run:

```sh
cargo install --locked --git https://github.com/chatmail/core/ deltachat-rpc-server
```

The `deltachat-rpc-server` executable will be installed into `$HOME/.cargo/bin` that should be available
in your `PATH`.

## Usage

To use just run `deltachat-rpc-server` command. The accounts folder will be created in the current
working directory unless `DC_ACCOUNTS_PATH` is set:

```sh
export DC_ACCOUNTS_PATH=$HOME/delta/
deltachat-rpc-server
```

The common use case for this program is to create bindings to use Delta Chat core from programming
languages other than Rust, for example:

1. Python: https://pypi.org/project/deltachat-rpc-client/
2. Go: https://github.com/deltachat/deltachat-rpc-client-go/

Run `deltachat-rpc-server --version` to check the version of the server.
Run `deltachat-rpc-server --openrpc` to get [OpenRPC](https://open-rpc.org/) specification of the provided JSON-RPC API.

## Windows ARM64 builds

Windows ARM64 release binaries are cross-compiled on Linux with Nix, using
`aarch64-pc-windows-gnullvm` and the LLVM/MinGW UCRT toolchain from the pinned
Nixpkgs revision. OpenSSL is built by Nix and linked statically, alongside bundled
SQLCipher. No Visual Studio tools or Windows runner are needed to produce the
release binary, Python wheel, or npm prebuild.

```sh
nix build .#deltachat-rpc-server-win-arm64
nix build .#deltachat-rpc-server-win-arm64-wheel --out-link wheel
```

The `Windows ARM64 RPC server` workflow runs on pull requests, pushes to `main`,
and manual dispatch. It cross-compiles the binary and wheel on Linux, then tests
those same artifacts on `windows-11-arm`: executable architecture, JSON-RPC
account creation, and the installed wheel entry point. This runtime test is
separate from the release workflow, which builds all Windows targets on Linux.

Releases include `deltachat-rpc-server-win-arm64.exe`, a `py3-none-win_arm64`
Python wheel, and a `@deltachat/stdio-rpc-server-win32-arm64` npm prebuild.
Publishing to PyPI and npm is restricted to `chatmail/core`; fork releases still
receive the binaries and packages as GitHub assets.

For a Parla Windows ARM64 bundle, rename the release executable to
`deltachat-rpc-server.exe` and put it in the same `bin` directory as `parla.exe`.
