import { spawnSync } from "node:child_process";
import os from "node:os";

import { pathExists } from "./paths.js";








export async function runDoctor(config) {
  const checks = [];
  checks.push({
    id: "node",
    ok: Number(process.versions.node.split(".")[0]) >= 20,
    severity: "error",
    message: `Node.js ${process.versions.node}`
  });

  if (!config.sandbox.enabled || config.sandbox.mode === "none") {
    checks.push({
      id: "sandbox",
      ok: true,
      severity: "info",
      message: "OS sandbox disabled; semantic command fuse is active"
    });
  } else {
    const platform = os.platform();
    if (platform === "darwin") {
      checks.push({
        id: "sandbox-exec",
        ok: hasCommand("sandbox-exec"),
        severity: "error",
        message: hasCommand("sandbox-exec") ? "macOS sandbox-exec available" : "macOS sandbox-exec not found"
      });
    } else if (platform === "linux") {
      const hasSandbox = hasCommand("bwrap") || hasCommand("firejail");
      checks.push({
        id: "linux-sandbox",
        ok: hasSandbox,
        severity: hasSandbox ? "info" : "warn",
        message: hasSandbox ? "Linux sandbox helper available" : "Install bubblewrap or firejail for OS sandboxing"
      });
    } else {
      checks.push({
        id: "platform-sandbox",
        ok: false,
        severity: "warn",
        message: `No built-in OS sandbox for ${platform}; policy, env scrub, scan and audit still work`
      });
    }
  }

  checks.push({
    id: "policy",
    ok: config.rules.length > 0,
    severity: "error",
    message: `${config.rules.length} policy rules loaded`
  });

  checks.push({
    id: "audit-dir",
    ok: await pathExists(config.auditDir),
    severity: "warn",
    message: `audit dir: ${config.auditDir}`
  });

  return checks;
}

function hasCommand(command) {
  const result = spawnSync("which", [command], { stdio: "ignore" });
  return result.status === 0;
}

//# sourceMappingURL=doctor.js.map
