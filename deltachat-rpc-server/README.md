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

The `Windows ARM64 RPC server` workflow builds and tests a native
`aarch64-pc-windows-msvc` release executable on `windows-11-arm`. It runs on pull
requests and pushes to `main`, and can also be started with **Run workflow**.
Download the `deltachat-rpc-server-win-arm64` artifact and extract
`deltachat-rpc-server.exe`. The executable includes vendored OpenSSL/SQLCipher
and a statically linked Visual C++ runtime.

The binary release workflow also includes this build and publishes
`deltachat-rpc-server-win-arm64.exe`, a `py3-none-win_arm64` Python wheel, and a
`@deltachat/stdio-rpc-server-win32-arm64` npm prebuild. In the `trufae/core` fork,
GitHub release assets are available from <https://github.com/trufae/core/releases>.

For a Parla Windows ARM64 bundle, place the artifact's `deltachat-rpc-server.exe`
in the same `bin` directory as `parla.exe`. Parla discovers this bundled server
automatically. When using the release asset, rename it to
`deltachat-rpc-server.exe` first. Parla's Windows auto-downloader currently
selects the upstream x64 asset; bundle this ARM64 server for the native port.

To build locally, install Rust and the Visual Studio ARM64 C++ tools, open an
ARM64 developer shell, and run:

```powershell
$env:RUSTFLAGS = '-C target-feature=+crt-static'
rustup target add aarch64-pc-windows-msvc
cargo build --release --locked -p deltachat-rpc-server --target aarch64-pc-windows-msvc --features vendored
```

Vendored OpenSSL also requires Perl and `nmake`, as supplied by the CI runner.
