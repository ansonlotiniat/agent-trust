import path from "node:path";
import { walkFiles } from "./filewalk.js";
import { scanFile } from "./secrets.js";

export async function scanPaths(paths, config, cwd = process.cwd()) {
  const findings = [];
  let filesScanned = 0;
  for (const input of paths.length ? paths : ["."]) {
    const full = path.resolve(cwd, input);
    for await (const file of walkOrSingle(full)) {
      filesScanned++;
      findings.push(...await scanFile(file, config));
    }
  }
  return { filesScanned, findings };
}

async function* walkOrSingle(full) {
  const { stat } = await import("node:fs/promises");
  const info = await stat(full);
  if (info.isDirectory()) yield* walkFiles(full);
  else if (info.isFile()) yield full;
}
