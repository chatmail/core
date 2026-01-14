## npm package for deltachat-rpc-server

This is the successor of `deltachat-node`,
it does not use NAPI bindings but instead uses stdio executables
to let you talk to core over jsonrpc over stdio.
This simplifies cross-compilation and even reduces binary size (no CFFI layer and no NAPI layer).

## Usage

> The **minimum** nodejs version for this package is `16`

```
npm i @deltachat/stdio-rpc-server @deltachat/jsonrpc-client
```

```js
import { startDeltaChat } from "@deltachat/stdio-rpc-server";
import { C } from "@deltachat/jsonrpc-client";

async function main() {
  const dc = await startDeltaChat("deltachat-data");
  console.log(await dc.rpc.getSystemInfo());
  dc.close();
}
main();
```

For a more complete example refer to https://github.com/deltachat-bot/echo/tree/master/nodejs_stdio_jsonrpc.

## How to use on an unsupported platform

You need to have rust installed to compile deltachat core for your platform and cpu architecture.
<https://rustup.rs/> is the recommended way to install rust.
Also your system probably needs more than 4GB RAM to compile core, alternatively your could try to build the debug build, which might take less RAM to build.

1. clone the core repo, right next to your project folder: `git clone git@github.com:deltachat/deltachat-core-rust.git`
2. go into your core checkout and run `git pull` and `git checkout <version>` to point it to the correct version (needs to be the same version the `@deltachat/jsonrpc-client` package has)
3. run `cargo build --release --package deltachat-rpc-server --bin deltachat-rpc-server`

Then you have 2 options:

### point to deltachat-rpc-server via direct path:

```sh
# start your app with the DELTA_CHAT_RPC_SERVER env var
DELTA_CHAT_RPC_SERVER="../deltachat-core-rust/target/release/deltachat-rpc-server" node myapp.js
```

### install deltachat-rpc-server in your $PATH:

```sh
# use this to install to ~/.cargo/bin
cargo install --release --package deltachat-rpc-server --bin deltachat-rpc-server
# or manually move deltachat-core-rust/target/release/deltachat-rpc-server
# to a location that is included in your $PATH Environment variable.
```

And make sure to enable the `takeVersionFromPATH` option:
```js
startDeltaChat("data-dir", { takeVersionFromPATH: true });
```

## How does it work when you install it

NPM automatically installs platform dependent optional dependencies when `os` and `cpu` fields are set correctly.

references:

- https://napi.rs/docs/deep-dive/release#3-the-native-addon-for-different-platforms-is-distributed-through-different-npm-packages, [webarchive version](https://web.archive.org/web/20240309234250/https://napi.rs/docs/deep-dive/release#3-the-native-addon-for-different-platforms-is-distributed-through-different-npm-packages)
- https://docs.npmjs.com/cli/v6/configuring-npm/package-json#cpu
- https://docs.npmjs.com/cli/v6/configuring-npm/package-json#os

When you import this package it searches for the rpc server in the following locations and order:

1. `DELTA_CHAT_RPC_SERVER` environment variable
2. use the PATH when `{takeVersionFromPATH: true}` is supplied in the options.
3. prebuilds in npm packages

so by default it uses the prebuilds.

## How do you built this package in CI

- To build platform packages, run the `build_platform_package.py` script:
  ```
  python3 build_platform_package.py <cargo-target>
  # example
  python3 build_platform_package.py x86_64-apple-darwin
  ```
- Then pass it as an artifact to the last CI action that publishes the main package.
- upload all packages from `deltachat-rpc-server/npm-package/platform_package`.
- then publish `deltachat-rpc-server/npm-package`,
  - this will run `update_optional_dependencies_and_version.js` (in the `prepack` script),
    which puts all platform packages into `optionalDependencies` and updates the `version` in `package.json`

## How to build a version you can use locally on your host machine for development

You can not install the npm packet from the previous section locally, unless you have a local npm registry set up where you upload it too. This is why we have separate scripts for making it work for local installation.

- If you just need your host platform run `python scripts/make_local_dev_version.py`
- note: this clears the `platform_package` folder
- (advanced) If you need more than one platform for local install you can just run `node scripts/update_optional_dependencies_and_version.js` after building multiple platforms with `build_platform_package.py`

## Thanks to nlnet

The initial work on this package was funded by nlnet as part of the [Delta Tauri](https://nlnet.nl/project/DeltaTauri/) Project.
