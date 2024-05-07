//@ts-check
import { execFile, spawn } from "child_process";
import { stat, readdir } from "fs/promises";
import os from "os";
import { join } from "path";
import { basename } from "path/posix";
import process from "process";
import { promisify } from "node:util";
import {
  ENV_VAR_NAME,
  PATH_EXECUTABLE_NAME,
  SKIP_SEARCH_IN_PATH,
} from "./src/const.js";
import {
  ENV_VAR_LOCATION_NOT_FOUND,
  FAILED_TO_START_SERVER_EXECUTABLE,
  NPM_NOT_FOUND_SUPPORTED_PLATFORM_ERROR,
  NPM_NOT_FOUND_UNSUPPORTED_PLATFORM_ERROR,
} from "./src/errors.js";

// Because this is not compiled by typescript, nodejs needs this stuff (` assert { type: "json" };`)
import package_json from "./package.json" assert { type: "json" };
import { createRequire } from "node:module";

const { resolve } = createRequire(import.meta.url);


// exports
// - [ ] expose from where the rpc server was loaded (env_var, prebuild or npm package)
// - [ ] a raw starter that has a stdin/out handle thingie like desktop uses
// - [X] a function that already wraps the stdio handle from above into the deltachat jsonrpc bindings

function findRPCServerInNodeModules() {
  const arch = os.arch();
  const operating_system = process.platform;
  const package_name = `@deltachat/stdio-rpc-server-${operating_system}-${arch}`;
  try {
    return resolve(package_name);
  } catch (error) {
    console.debug("findRpcServerInNodeModules", error);
    if (Object.keys(package_json.optionalDependencies).includes(package_name)) {
      throw new Error(NPM_NOT_FOUND_SUPPORTED_PLATFORM_ERROR(package_name));
    } else {
      throw new Error(NPM_NOT_FOUND_UNSUPPORTED_PLATFORM_ERROR());
    }
  }
}

/** @type {import("./index").FnTypes.getRPCServerPath} */
export async function getRPCServerPath(
  options = { skipSearchInPath: false, disableEnvPath: false }
) {
  // @TODO: improve confusing naming of these options
  const { skipSearchInPath, disableEnvPath } = options;
  // 1. check if it is set as env var
  if (process.env[ENV_VAR_NAME] && !disableEnvPath) {
    try {
      if (!(await stat(process.env[ENV_VAR_NAME])).isFile()) {
        throw new Error(
          `expected ${ENV_VAR_NAME} to point to the deltachat-rpc-server executable`
        );
      }
    } catch (error) {
      throw new Error(ENV_VAR_LOCATION_NOT_FOUND());
    }
    return process.env[ENV_VAR_NAME];
  }

  // 2. check if it can be found in PATH
  if (!process.env[SKIP_SEARCH_IN_PATH] && !skipSearchInPath) {
    const path_dirs = process.env["PATH"].split(/:|;/);
    // check cargo dir first
    const cargo_dirs = path_dirs.filter((p) => p.endsWith(".cargo/bin"));
    const findExecutable = async (directory) => {
      const files = await readdir(directory);
      const file = files.find((p) =>
        basename(p).includes(PATH_EXECUTABLE_NAME)
      );
      if (file) {
        return join(directory, file);
      } else {
        throw null;
      }
    };
    const executable_search = // TODO make code simpler to read
      (await Promise.allSettled(cargo_dirs.map(findExecutable))).find(
        ({ status }) => status === "fulfilled"
      ) ||
      (await Promise.allSettled(path_dirs.map(findExecutable))).find(
        ({ status }) => status === "fulfilled"
      );
    // TODO maybe we could the system do this stuff automatically
    // by just trying to execute it and then use "which" (unix) or "where" (windows) to get the path to the executable
    if (executable_search.status === "fulfilled") {
      const executable = executable_search.value;
      // test if it is the right version
      try {
        // for some unknown reason it is in stderr and not in stdout
        const { stderr } = await promisify(execFile)(executable, ["--version"]);
        const version = stderr.slice(0, stderr.indexOf("\n"));
        if (package_json.version !== version) {
          throw new Error(
            `version mismatch: (npm package: ${package_json.version})  (installed ${PATH_EXECUTABLE_NAME} version: ${version})`
          );
        } else {
          return executable;
        }
      } catch (error) {
        console.error(
          "Found executable in PATH, but there was an error: " + error
        );
        console.error("So falling back to using prebuild...");
      }
    }
  }
  // 3. check for prebuilds

  return findRPCServerInNodeModules();
}

import { StdioDeltaChat } from "@deltachat/jsonrpc-client";

/** @type {import("./index").FnTypes.startDeltaChat} */
export async function startDeltaChat(directory, options) {
  const pathToServerBinary = await getRPCServerPath(options);
  const server = spawn(pathToServerBinary, {
    env: {
      RUST_LOG: process.env.RUST_LOG || "info",
      DC_ACCOUNTS_PATH: directory
    },
  });

  server.on("error", (err) => {
    throw new Error(FAILED_TO_START_SERVER_EXECUTABLE(pathToServerBinary, err));
  });
  let shouldClose = false;

  server.on("exit", () => {
    if (shouldClose) {
      return;
    }
    throw new Error("Server quit");
  });

  server.stderr.pipe(process.stderr);

  /** @type {import('./index').DeltaChatOverJsonRpcServer} */
  //@ts-expect-error
  const dc = new StdioDeltaChat(server.stdin, server.stdout, true);

  dc.shutdown = async () => {
    shouldClose = true;
    if (!server.kill()) {
      console.log("server termination failed");
    }
  };

  return dc;
}
