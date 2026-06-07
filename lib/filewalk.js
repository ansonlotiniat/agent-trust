import { readdir } from "node:fs/promises";
import path from "node:path";

const ignoredDirs = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  ".next",
  ".turbo",
  ".venv",
  "venv",
  "__pycache__",
  ".agent-trust/audit"
]);

export async function* walkFiles(root) {
  const entries = await readdir(root, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(root, entry.name);
    if (entry.isDirectory()) {
      if (ignoredDirs.has(entry.name)) continue;
      if (ignoredDirs.has(path.relative(process.cwd(), full))) continue;
      yield* walkFiles(full);
    } else if (entry.isFile()) {
      yield full;
    }
  }
}

//# sourceMappingURL=filewalk.js.map
