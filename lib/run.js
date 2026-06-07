import { spawn } from "node:child_process";
import path from "node:path";
import pc from "./colors.js";
import { AuditLog } from "./audit.js";
import { buildChildEnv } from "./env.js";
import { decideCommand } from "./decision.js";
import { resolveAsk } from "./prompt.js";
import { buildSandboxCommand } from "./sandbox.js";
import { installCommandShims } from "./shim.js";

export async function runGuarded(command, args, config, options) {
  const audit = new AuditLog(config);
  const cwd = path.resolve(options.cwd);
  const preflight = decideCommand(config, command, args, cwd, process.env);
  const policy = preflight.policy;
  const decision = await resolveAsk(policy, config.interactive, options.assume);
  await audit.append({
    type: "process.preflight",
    decision,
    ruleId: policy.ruleId,
    reason: policy.reason,
    cwd,
    command,
    args,
    findings: preflight.findings,
    subject: { subjects: preflight.subjects, analysis: preflight.analysis }
  });

  if (decision === "deny") {
    console.error(`${pc.red("denied")} ${policy.reason}`);
    console.error(`audit: ${audit.path}`);
    return 126;
  }

  const { startNetworkProxy } = await import("./networkProxy.js");
  const networkProxy = await startNetworkProxy(config, audit, options.assume);
  const shim = await installCommandShims(config, audit.path, cwd, options.assume);
  const envResult = buildChildEnv(config, options.passEnv ?? [], networkProxy?.url, {
    shimDir: shim.dir,
    auditFile: audit.path,
    assume: options.assume
  });
  const sandboxConfig = {
    ...config,
    sandbox: {
      ...config.sandbox,
      enabled: options.noSandbox ? false : config.sandbox.enabled,
      macosProfile: options.strictSandbox ? "strict" : config.sandbox.macosProfile
    }
  };
  const sandboxed = await buildSandboxCommand(sandboxConfig, command, args);
  for (const warning of sandboxed.warnings) console.error(`${pc.yellow("warning")} ${warning}`);

  await audit.append({
    type: "process.start",
    decision: "allow",
    cwd,
    command,
    args,
    metadata: {
      sandboxMode: sandboxed.mode,
      macosProfile: sandboxConfig.sandbox.macosProfile,
      sandboxProfile: sandboxed.profilePath,
      scrubbedEnv: envResult.scrubbed,
      networkProxy: networkProxy?.url,
      commandShim: shim.dir
    }
  });

  const child = spawn(sandboxed.command, sandboxed.args, { cwd, stdio: "inherit", env: envResult.env });
  const result = await new Promise((resolve) => {
    child.on("close", (code, signal) => resolve({ code, signal }));
  });
  if (networkProxy) await networkProxy.close();

  const exitCode = result.code ?? (result.signal ? 128 : 1);
  await audit.append({
    type: "process.exit",
    decision: "allow",
    cwd,
    command,
    args,
    exitCode,
    signal: result.signal,
    metadata: { audit: audit.path }
  });

  return exitCode;
}
