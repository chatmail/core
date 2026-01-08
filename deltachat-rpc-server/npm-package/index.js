//@ts-check
import { spawn } from "node:child_process";
import { statSync } from "node:fs";
import os from "node:os";
import process from "node:process";
import { ENV_VAR_NAME, PATH_EXECUTABLE_NAME } from "./src/const.js";
import {
  ENV_VAR_LOCATION_NOT_FOUND,
  FAILED_TO_START_SERVER_EXECUTABLE,
  NPM_NOT_FOUND_SUPPORTED_PLATFORM_ERROR,
  NPM_NOT_FOUND_UNSUPPORTED_PLATFORM_ERROR,
} from "./src/errors.js";

import { createRequire } from "node:module";

function findRPCServerInNodeModules() {
  const arch = os.arch();
  const operating_system = process.platform;
  const package_name = `@deltachat/stdio-rpc-server-${operating_system}-${arch}`;
  try {
    const { resolve } = createRequire(import.meta.url);
    return resolve(package_name);
  } catch (error) {
    console.debug("findRpcServerInNodeModules", error);
    const require = createRequire(import.meta.url);
    if (
      Object.keys(require("./package.json").optionalDependencies).includes(
        package_name
      )
    ) {
      throw new Error(NPM_NOT_FOUND_SUPPORTED_PLATFORM_ERROR(package_name));
    } else {
      throw new Error(NPM_NOT_FOUND_UNSUPPORTED_PLATFORM_ERROR());
    }
  }
}

/** @type {import("./index").FnTypes.getRPCServerPath} */
export function getRPCServerPath(options = {}) {
  const { takeVersionFromPATH, disableEnvPath } = {
    takeVersionFromPATH: false,
    disableEnvPath: false,
    ...options,
  };
  // 1. check if it is set as env var
  if (process.env[ENV_VAR_NAME] && !disableEnvPath) {
    try {
      if (!statSync(process.env[ENV_VAR_NAME]).isFile()) {
        throw new Error(
          `expected ${ENV_VAR_NAME} to point to the deltachat-rpc-server executable`
        );
      }
    } catch (error) {
      throw new Error(ENV_VAR_LOCATION_NOT_FOUND());
    }
    return process.env[ENV_VAR_NAME];
  }

  // 2. check if PATH should be used
  if (takeVersionFromPATH) {
    return PATH_EXECUTABLE_NAME;
  }
  // 3. check for prebuilds

  return findRPCServerInNodeModules();
}

import { StdioDeltaChat } from "@deltachat/jsonrpc-client";

/** @type {import("./index").FnTypes.startDeltaChat} */
export function startDeltaChat(directory, options = {}) {
  return new DeltaChatOverJsonRpc(directory, options);
}

export class DeltaChatOverJsonRpc extends StdioDeltaChat {
  /**
   *
   * @param {string} directory
   * @param {Partial<import("./index").SearchOptions & import("./index").StartOptions>} options
   */
  constructor(directory, options = {}) {
    const pathToServerBinary = getRPCServerPath(options);
    const server = spawn(pathToServerBinary, {
      env: {
        RUST_LOG: process.env.RUST_LOG,
        DC_ACCOUNTS_PATH: directory,
      },
      stdio: ["pipe", "pipe", options.muteStdErr ? "ignore" : "inherit"],
    });

    server.on("error", (err) => {
      throw new Error(
        FAILED_TO_START_SERVER_EXECUTABLE(pathToServerBinary, err)
      );
    });
    let shouldClose = false;

    server.on("exit", () => {
      if (shouldClose) {
        return;
      }
      throw new Error("Server quit");
    });

    super(server.stdin, server.stdout, true);

    this.close = () => {
      shouldClose = true;
      if (!server.kill()) {
        console.log("server termination failed");
      }
    };

    this.pathToServerBinary = pathToServerBinary;
  }
}
