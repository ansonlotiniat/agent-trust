import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";
import os from "node:os";
import { AuditLog, verifyAuditFile } from "../lib/audit.js";
import { defaultConfig, validateConfig } from "../lib/config.js";
import { evaluatePolicy, globMatches, hostMatches } from "../lib/policy.js";
import { highestFindingRisk, redactSecrets, scanText } from "../lib/secrets.js";
import { startNetworkProxy } from "../lib/networkProxy.js";
import { decideCommand } from "../lib/decision.js";

const tests = [];

function test(name, fn) {
  tests.push({ name, fn });
}

test("host wildcard matches subdomains only", () => {
  assert.equal(hostMatches("*.example.com", "api.example.com"), true);
  assert.equal(hostMatches("*.example.com", "example.com"), false);
  assert.equal(hostMatches("api.example.com", "api.example.com"), true);
});

test("glob path matching supports double-star", () => {
  assert.equal(globMatches("/Users/me/.ssh/**", "/Users/me/.ssh/id_rsa"), true);
  assert.equal(globMatches("/Users/me/.ssh/**", "/Users/me/project/id_rsa"), false);
});

test("semantic fuse allows project-local destructive commands", () => {
  const result = decideCommand(defaultConfig, "rm", ["-rf", "dist"], process.cwd());
  assert.equal(result.policy.decision, "allow");
  assert.equal(result.analysis.tags.includes("project-local-destructive"), true);
});

test("semantic fuse denies catastrophic filesystem deletes", () => {
  const result = decideCommand(defaultConfig, "rm", ["-rf", "/"], process.cwd());
  assert.equal(result.policy.decision, "deny");
  assert.equal(result.policy.ruleId, "deny-catastrophic-actions");
  assert.equal(result.analysis.tags.includes("catastrophic"), true);
});

test("semantic fuse brakes credential access and shell config mutation", () => {
  const credential = decideCommand(defaultConfig, "cat", [path.join(os.homedir(), ".ssh/id_rsa")], process.cwd());
  assert.equal(credential.policy.decision, "ask");
  assert.equal(credential.analysis.tags.includes("credential-access"), true);

  const shellConfig = decideCommand(defaultConfig, "bash", ["-c", "echo x > ~/.zshrc"], process.cwd());
  assert.equal(shellConfig.policy.decision, "ask");
  assert.equal(shellConfig.analysis.tags.includes("shell-config-mutation"), true);
});

test("network allowlist is allowed without prompting", () => {
  const result = evaluatePolicy(defaultConfig, {
    kind: "network",
    networkHost: "api.openai.com"
  });
  assert.equal(result.decision, "allow");
});

test("policy validation catches invalid policy values", () => {
  const errors = validateConfig({ ...defaultConfig, defaultAction: "maybe" });
  assert.equal(errors.some((error) => error.includes("defaultAction")), true);
});

test("detects OpenAI-like keys and redacts them", () => {
  const text = "OPENAI_API_KEY=" + ["sk", "proj", "abcdefghijklmnopqrstuvwxyzABCDE12345"].join("-");
  const findings = scanText(text, defaultConfig, "fixture.env");
  assert.equal(findings.some((finding) => finding.id === "openai-api-key"), true);
  assert.equal(highestFindingRisk(findings), "critical");
  assert.match(redactSecrets(text, defaultConfig), /REDACTED:openai-api-key/);
});

test("audit log verifies and detects tampering", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "agent-trust-test-"));
  const config = {
    ...defaultConfig,
    projectRoot: dir,
    auditDir: dir
  };
  const audit = new AuditLog(config, "session");
  await audit.append({ type: "test", decision: "allow", command: "echo", args: ["ok"] });
  await audit.append({ type: "test.exit", decision: "allow", exitCode: 0 });
  assert.deepEqual(await verifyAuditFile(audit.path), { ok: true, events: 2 });

  const raw = await readFile(audit.path, "utf8");
  await writeFile(audit.path, raw.replace("echo", "cat"), "utf8");
  const verification = await verifyAuditFile(audit.path);
  assert.equal(verification.ok, false);
});

test("network proxy starts and closes cleanly", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "agent-trust-net-"));
  const config = { ...defaultConfig, projectRoot: dir, auditDir: dir, network: { ...defaultConfig.network, proxyEnv: true } };
  const audit = new AuditLog(config, "network");
  const proxy = await startNetworkProxy(config, audit, "deny");
  assert.match(proxy.url, /^http:\/\/127\.0\.0\.1:\d+$/);
  await proxy.close();
});

test("CLI help and wrap commands work without runtime dependencies", () => {
  const help = spawnSync(process.execPath, ["lib/cli.js", "--help"], { encoding: "utf8" });
  assert.equal(help.status, 0);
  assert.match(help.stdout, /Usage: agent-trust/);

  const wrap = spawnSync(process.execPath, ["lib/cli.js", "wrap", "codex", "--dangerous"], { encoding: "utf8" });
  assert.equal(wrap.status, 0);
  assert.match(wrap.stdout, /codex_safe/);
  assert.match(wrap.stdout, /dangerously-bypass-approvals-and-sandbox/);
});

test("CLI validate and decide commands work", () => {
  const validate = spawnSync(process.execPath, ["lib/cli.js", "validate"], { encoding: "utf8" });
  assert.equal(validate.status, 0);
  assert.match(validate.stdout, /valid/);

  const safeDelete = spawnSync(process.execPath, ["lib/cli.js", "decide", "--", "rm", "-rf", "dist"], { encoding: "utf8" });
  assert.equal(safeDelete.status, 0);
  assert.match(safeDelete.stdout, /decision: .*allow/);

  const catastrophicDelete = spawnSync(process.execPath, ["lib/cli.js", "decide", "--", "rm", "-rf", "/"], { encoding: "utf8" });
  assert.equal(catastrophicDelete.status, 0);
  assert.match(catastrophicDelete.stdout, /decision: .*deny/);
  assert.match(catastrophicDelete.stdout, /deny-catastrophic-actions/);

  const hostDecision = spawnSync(process.execPath, ["lib/cli.js", "decide", "--json", "--host", "api.openai.com"], { encoding: "utf8" });
  assert.equal(hostDecision.status, 0);
  assert.equal(JSON.parse(hostDecision.stdout).decision, "allow");
});

let failures = 0;
for (const item of tests) {
  try {
    await item.fn();
    console.log(`ok ${item.name}`);
  } catch (error) {
    failures++;
    console.error(`fail ${item.name}`);
    console.error(error);
  }
}

if (failures) process.exit(1);
console.log(`${tests.length} tests passed`);
