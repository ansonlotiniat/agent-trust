import { spawn } from "node:child_process";
import readline from "node:readline";
import path from "node:path";
import pc from "./colors.js";
import { AuditLog } from "./audit.js";
import { buildChildEnv } from "./env.js";
import { evaluatePolicy } from "./policy.js";
import { resolveAsk } from "./prompt.js";
import { highestFindingRisk, scanText } from "./secrets.js";

export async function runMcpProxy(command, args, config, options) {
  const audit = new AuditLog(config);
  const envResult = buildChildEnv(config, options.passEnv ?? []);
  const child = spawn(command, args, {
    cwd: path.resolve(options.cwd),
    stdio: ["pipe", "pipe", "inherit"],
    env: envResult.env
  });

  await audit.append({
    type: "mcp.proxy.start",
    decision: "allow",
    cwd: options.cwd,
    command,
    args,
    metadata: { scrubbedEnv: envResult.scrubbed }
  });

  const childOut = readline.createInterface({ input: child.stdout });
  childOut.on("line", (line) => {
    process.stdout.write(line + "\n");
  });

  const stdinLines = readline.createInterface({ input: process.stdin });
  stdinLines.on("line", (line) => {
    void handleClientLine(line, child, config, audit, options);
  });

  return await new Promise((resolve) => {
    child.on("close", async (code, signal) => {
      await audit.append({ type: "mcp.proxy.exit", decision: "allow", cwd: options.cwd, command, args, exitCode: code, signal });
      resolve(code ?? (signal ? 128 : 1));
    });
  });
}

async function handleClientLine(line, child, config, audit, options) {
  let message;
  try {
    message = JSON.parse(line);
  } catch {
    child.stdin.write(line + "\n");
    return;
  }

  if (message.method !== "tools/call") {
    child.stdin.write(line + "\n");
    return;
  }

  const toolName = extractToolName(message.params);
  const serialized = JSON.stringify(message.params ?? {});
  const findings = scanText(serialized, config);
  const subject = { kind: "mcp-tool", mcpTool: toolName, content: serialized, detectedRisk: highestFindingRisk(findings) };
  const policy = evaluatePolicy(config, subject);
  const decision = await resolveAsk(policy, config.interactive, options.assume);

  await audit.append({
    type: "mcp.tool.preflight",
    decision,
    ruleId: policy.ruleId,
    reason: policy.reason,
    subject: { id: message.id, toolName, params: message.params },
    findings
  });

  if (decision === "deny") {
    const response = {
      jsonrpc: message.jsonrpc ?? "2.0",
      id: message.id,
      error: { code: -32001, message: `Agent Trust denied MCP tool call: ${policy.reason}` }
    };
    process.stdout.write(JSON.stringify(response) + "\n");
    console.error(`${pc.red("denied MCP")} ${toolName}: ${policy.reason}`);
    return;
  }

  child.stdin.write(line + "\n");
}

function extractToolName(params) {
  if (!params || typeof params !== "object") return undefined;
  return typeof params.name === "string" ? params.name : undefined;
}
