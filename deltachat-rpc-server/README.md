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
