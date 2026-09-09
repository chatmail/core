import { tmpdir } from "os";
import { join, resolve } from "path";
import { mkdtemp, rm } from "fs/promises";
import { spawn, exec } from "child_process";
import { Readable, Writable } from "node:stream";

export type RpcServerHandle = {
  stdin: Writable;
  stdout: Readable;
  close: () => Promise<void>;
};

export async function startServer(): Promise<RpcServerHandle> {
  const tmpDir = await mkdtemp(join(tmpdir(), "deltachat-jsonrpc-test"));

  const pathToServerBinary = resolve(
    join(await getTargetDir(), "debug/deltachat-rpc-server"),
  );

  const server = spawn(pathToServerBinary, {
    cwd: tmpDir,
    env: {
      RUST_LOG: process.env.RUST_LOG || "info",
      RUST_MIN_STACK: "8388608",
    },
  });

  server.on("error", (err) => {
    throw new Error(
      "Failed to start server executable " +
        pathToServerBinary +
        ", make sure you built it first.",
    );
  });
  let shouldClose = false;

  server.on("exit", () => {
    if (shouldClose) {
      return;
    }
    throw new Error("Server quit");
  });

  server.stderr.pipe(process.stderr);

  return {
    stdin: server.stdin,
    stdout: server.stdout,
    close: async () => {
      shouldClose = true;
      if (!server.kill()) {
        console.log("server termination failed");
      }
      await rm(tmpDir, { recursive: true });
    },
  };
}

export function createTempUser(chatmailDomain: String) {
  const charset = "2345789acdefghjkmnpqrstuvwxyz";
  let user = "ci-";
  for (let i = 0; i < 6; i++) {
    user += charset[Math.floor(Math.random() * charset.length)];
  }
  const email = user + "@" + chatmailDomain;
  return { email: email, password: user + "$" + user };
}

function getTargetDir(): Promise<string> {
  return new Promise((resolve, reject) => {
    exec(
      "cargo metadata --no-deps --format-version 1",
      (error, stdout, _stderr) => {
        if (error) {
          console.log("error", error);
          reject(error);
        } else {
          try {
            const json = JSON.parse(stdout);
            resolve(json.target_directory);
          } catch (error) {
            console.log("json error", error);
            reject(error);
          }
        }
      },
    );
  });
}
