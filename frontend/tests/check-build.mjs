import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

const [directory, expectedBase] = process.argv.slice(2);
assert.ok(directory && expectedBase, "pass build directory and expected API base");
const files = await readdir(path.join(directory, "assets"));
const scripts = await Promise.all(files.filter((name) => name.endsWith(".js"))
  .map((name) => readFile(path.join(directory, "assets", name), "utf8")));
const bundle = scripts.join("\n");
assert.ok(bundle.includes(expectedBase), "compiled bundle must honor the API base");
assert.ok(!bundle.includes("http://192.168.65.199:8088"), "deployment host must not be hardcoded");
console.log(`Build configuration verified for ${expectedBase}`);
