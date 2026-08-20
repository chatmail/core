//@ts-check
import { ENV_VAR_NAME } from "./const.js";

const cargoInstallCommand =
  "cargo install --locked --git https://github.com/chatmail/core deltachat-rpc-server";

export function NPM_NOT_FOUND_SUPPORTED_PLATFORM_ERROR(package_name) {
  return `deltachat-rpc-server not found:

- Install it with "npm i ${package_name}"
- or download/compile deltachat-rpc-server for your platform and
 - either put it into your PATH (for example with "${cargoInstallCommand}")
 - or set the "${ENV_VAR_NAME}" env var to the path to deltachat-rpc-server"`;
}

export function NPM_NOT_FOUND_UNSUPPORTED_PLATFORM_ERROR() {
  return `deltachat-rpc-server not found:

Unfortunately no prebuild is available for your system, so you need to provide deltachat-rpc-server yourself.

- Download or Compile deltachat-rpc-server for your platform and
 - either put it into your PATH (for example with "${cargoInstallCommand}")
 - or set the "${ENV_VAR_NAME}" env var to the path to deltachat-rpc-server"`;
}

export function ENV_VAR_LOCATION_NOT_FOUND(error) {
  return `deltachat-rpc-server not found in ${ENV_VAR_NAME}:

    Error: ${error}

    Content of ${ENV_VAR_NAME}: "${process.env[ENV_VAR_NAME]}"`;
}

export function FAILED_TO_START_SERVER_EXECUTABLE(pathToServerBinary, error) {
  return `Failed to start server executable at '${pathToServerBinary}',

  Error: ${error}

Make sure the deltachat-rpc-server binary exists at this location 
and you can start it with \`${pathToServerBinary} --version\``;
}
