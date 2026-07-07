import { readFileSync } from "fs";
// only checks for the coverage of the api functions in bindings.ts for now
const generatedFile = "typescript/generated/client.ts";
const json = JSON.parse(readFileSync("./coverage/coverage-final.json"));
const jsonCoverage =
  json[Object.keys(json).find((k) => k.includes(generatedFile))];
const fnMap = Object.keys(jsonCoverage.fnMap).map(
  (key) => jsonCoverage.fnMap[key],
);
const htmlCoverage = readFileSync(
  "./coverage/" + generatedFile + ".html",
  "utf8",
);
const uncoveredLines = htmlCoverage
  .split("\n")
  .filter((line) => line.includes(`"function not covered"`));
const uncoveredFunctions = uncoveredLines.map(
  (line) => />([\w_]+)\(/.exec(line)[1],
);
console.log(
  "\nUncovered api functions:\n" +
    uncoveredFunctions
      .map((uF) => fnMap.find(({ name }) => name === uF))
      .map(
        ({ name, line }) => `.${name.padEnd(40)}  (${generatedFile}:${line})`,
      )
      .join("\n"),
);
