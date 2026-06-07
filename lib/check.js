import { spawn } from "node:child_process";
import path from "node:path";
import { access } from "node:fs/promises";
import { constants } from "node:fs";
import pc from "./colors.js";
import { AuditLog } from "./audit.js";
import { decideCommand } from "./decision.js";
import { resolveAsk } from "./prompt.js";

export async function runShimCheck(command, args, config, options) {
  const cwd = path.resolve(options.cwd || process.cwd());
  const audit = new AuditLog(config, options.auditFile ? path.basename(options.auditFile, ".jsonl") : undefined);
  const result = decideCommand(config, command, args, cwd, process.env);
  const decision = await resolveAsk(result.policy, config.interactive, options.assume);

  await audit.append({
    type: "shim.preflight",
    decision,
    ruleId: result.policy.ruleId,
    reason: result.policy.reason,
    cwd,
    command,
    args,
    findings: result.findings,
    subject: { subjects: result.subjects, analysis: result.analysis }
  });

  if (decision === "deny") {
    console.error(`${pc.red("agent-trust denied")} ${command}: ${result.policy.reason}`);
    return 126;
  }

  const original = await findOriginalCommand(command, process.env.AGENT_TRUST_ORIGINAL_PATH || process.env.PATH || "");
  const child = spawn(original, args, {
    cwd,
    stdio: "inherit",
    env: process.env
  });
  const exit = await new Promise((resolve) => {
    child.on("close", (code, signal) => resolve({ code, signal }));
  });
  return exit.code ?? (exit.signal ? 128 : 1);
}

async function findOriginalCommand(command, pathValue) {
  if (command.includes("/")) return command;
  for (const dir of pathValue.split(path.delimiter)) {
    if (!dir) continue;
    const candidate = path.join(dir, command);
    try {
      await access(candidate, constants.X_OK);
      if (candidate !== process.argv[1]) return candidate;
    } catch {
      // continue
    }
  }
  return command;
}
