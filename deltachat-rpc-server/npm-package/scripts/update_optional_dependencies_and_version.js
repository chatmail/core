import fs from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const expected_cwd = join(dirname(fileURLToPath(import.meta.url)), "..");

if (process.cwd() !== expected_cwd) {
  console.error(
    "CWD mismatch: this script needs to be run from " + expected_cwd,
    { actual: process.cwd(), expected: expected_cwd }
  );
  process.exit(1);
}

// whether to use local paths instead of npm registry version number for the prebuilds in optionalDependencies
// useful for local development
const is_local = process.argv.includes("--local");

const package_json = JSON.parse(await fs.readFile("./package.json", "utf8"));

const cargo_toml = await fs.readFile("../Cargo.toml", "utf8");
const version = cargo_toml
  .split("\n")
  .find((line) => line.includes("version"))
  .split('"')[1];

const platform_packages_dir = "./platform_package";

const platform_package_names = await Promise.all(
  (await fs.readdir(platform_packages_dir)).map(async (name) => {
    const p = JSON.parse(
      await fs.readFile(
        join(platform_packages_dir, name, "package.json"),
        "utf8"
      )
    );
    if (p.version !== version) {
      console.error(
        name,
        "has a different version than the version of the rpc server.",
        { rpc_server: version, platform_package: p.version }
      );
      throw new Error("version mismatch");
    }
    return { folder_name: name, package_name: p.name };
  })
);

package_json.version = version;
package_json.optionalDependencies = {};
for (const { folder_name, package_name } of platform_package_names) {
  package_json.optionalDependencies[package_name] = is_local
    ? `file:${expected_cwd}/platform_package/${folder_name}` // npm seems to work better with an absolute path here
    : version;
}

if (is_local) {
  package_json.peerDependencies["@deltachat/jsonrpc-client"] =
    `file:${join(expected_cwd, "/../../deltachat-jsonrpc-bindings/typescript")}`;
} else {
  package_json.peerDependencies["@deltachat/jsonrpc-client"] = "*";
}

await fs.writeFile("./package.json", JSON.stringify(package_json, null, 4));
