import { access } from "node:fs/promises";

const required = [
  "lib/analyze.js",
  "lib/check.js",
  "lib/cli.js",
  "lib/decision.js",
  "lib/env.js",
  "lib/policy.js",
  "lib/run.js",
  "lib/sandbox.js",
  "lib/shim.js",
  "lib/scan.js",
  "lib/secrets.js",
  "lib/networkProxy.js"
];

for (const file of required) {
  await access(file);
}

console.log(`verified ${required.length} runtime files`);
