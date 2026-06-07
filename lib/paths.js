import os from "node:os";
import path from "node:path";
import { access, constants } from "node:fs/promises";

export const CONFIG_DIR = ".agent-trust";
export const CONFIG_FILE = "policy.json";
export const DEFAULT_AUDIT_DIR = ".agent-trust/audit";

export function expandHome(value) {
  if (value === "~") return os.homedir();
  if (value.startsWith("~/")) return path.join(os.homedir(), value.slice(2));
  return value;
}

export function resolveFrom(base, value) {
  const expanded = expandHome(value);
  return path.isAbsolute(expanded) ? path.normalize(expanded) : path.normalize(path.join(base, expanded));
}

export async function pathExists(filePath) {
  try {
    await access(filePath, constants.F_OK);
    return true;
  } catch (e) {
    return false;
  }
}

export function normalizeForDisplay(filePath, cwd = process.cwd()) {
  const rel = path.relative(cwd, filePath);
  if (!rel.startsWith("..") && !path.isAbsolute(rel)) return rel || ".";
  return filePath;
}

//# sourceMappingURL=paths.js.map
