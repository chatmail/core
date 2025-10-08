#!/usr/bin/env node
import { readFileSync, writeFileSync } from "fs";
import { resolve } from "path";
import { fileURLToPath } from "url";
import { dirname } from "path";
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const data = [];
const header = resolve(__dirname, "../../../deltachat-ffi/deltachat.h");

console.log("Generating constants...");

const header_data = readFileSync(header, "UTF-8");
const regex = /^#define\s+(\w+)\s+(\w+)/gm;
let match;
while (null != (match = regex.exec(header_data))) {
  const key = match[1];
  const value = parseInt(match[2]);
  if (!isNaN(value)) {
    data.push({ key, value });
  }
}

const constants = data
  .filter(
    ({ key }) => key.toUpperCase()[0] === key[0], // check if define name is uppercase
  )
  .sort((lhs, rhs) => {
    if (lhs.key < rhs.key) return -1;
    else if (lhs.key > rhs.key) return 1;
    return 0;
  })
  .filter(({ key }) => {
    // filter out what we don't need it
    return !(
      key.startsWith("DC_EVENT_") ||
      key.startsWith("DC_IMEX_") ||
      key.startsWith("DC_CHAT_VISIBILITY") ||
      key.startsWith("DC_DOWNLOAD") ||
      key.startsWith("DC_INFO_") ||
      (key.startsWith("DC_MSG") && !key.startsWith("DC_MSG_ID")) ||
      key.startsWith("DC_QR_") ||
      key.startsWith("DC_CERTCK_") ||
      key.startsWith("DC_SOCKET_") ||
      key.startsWith("DC_LP_AUTH_") ||
      key.startsWith("DC_PUSH_") ||
      key.startsWith("DC_TEXT1_") ||
      key.startsWith("DC_CHAT_TYPE")
    );
  })
  .map((row) => {
    return `  export const ${row.key} = ${row.value};`;
  })
  .join("\n");

writeFileSync(
  resolve(__dirname, "../generated/constants.ts"),
  `// Generated!

export namespace C {
${constants}
  /** @deprecated 10-8-2025 compare string directly with \`== "Group"\` */
  export const DC_CHAT_TYPE_GROUP = "Group";
  /** @deprecated 10-8-2025 compare string directly with \`== "InBroadcast"\`*/
  export const DC_CHAT_TYPE_IN_BROADCAST = "InBroadcast";
  /** @deprecated 10-8-2025 compare string directly with \`== "Mailinglist"\` */
  export const DC_CHAT_TYPE_MAILINGLIST = "Mailinglist";
  /** @deprecated 10-8-2025 compare string directly with \`== "OutBroadcast"\` */
  export const DC_CHAT_TYPE_OUT_BROADCAST = "OutBroadcast";
  /** @deprecated 10-8-2025 compare string directly with \`== "Single"\` */
  export const DC_CHAT_TYPE_SINGLE = "Single";
}\n`,
);
