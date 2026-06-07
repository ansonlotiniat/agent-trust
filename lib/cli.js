#!/usr/bin/env node
import path from "node:path";
import { readdir } from "node:fs/promises";
import pc from "./colors.js";
import { initConfig, loadConfig, validateConfig } from "./config.js";
import { runDoctor } from "./doctor.js";
import { runGuarded } from "./run.js";
import { runMcpProxy } from "./mcp.js";
import { runShimCheck } from "./check.js";
import { scanPaths } from "./scan.js";
import { printFindings } from "./format.js";
import { compareRisk, maxRisk } from "./risk.js";
import { AuditLog, verifyAuditFile, writeEvidenceBundle } from "./audit.js";
import { defaultConfig } from "./config.js";
import { evaluatePolicy, globMatches, hostMatches, mergeDecisions } from "./policy.js";
import { highestFindingRisk, redactSecrets, scanText } from "./secrets.js";
import { analyzePath } from "./analyze.js";
import { decideCommand } from "./decision.js";

const VERSION = "0.1.0";

if (isDirectExecution()) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(pc.red(error instanceof Error ? error.message : String(error)));
    process.exit(1);
  });
}

async function main(argv) {
  const [cmd, ...rest] = argv;
  if (!cmd || cmd === "--help" || cmd === "-h" || cmd === "help") return printHelp();
  if (cmd === "--version" || cmd === "-V") return console.log(VERSION);

  if (cmd === "init") {
    const opts = parseOptions(rest);
    const file = await initConfig(process.cwd(), Boolean(opts.flags.force || opts.flags.f));
    console.log(`${pc.green("created")} ${file}`);
    return;
  }

  if (cmd === "doctor") {
    const opts = parseOptions(rest);
    const { config, path: configPath } = await loadConfig(opts.flags.config || opts.flags.c);
    console.log(`policy: ${configPath ?? pc.yellow("default in-memory; run agent-trust init")}`);
    const checks = await runDoctor(config);
    let failed = false;
    for (const check of checks) {
      const marker = check.ok ? pc.green("ok") : check.severity === "error" ? pc.red("fail") : pc.yellow("warn");
      console.log(`${marker} ${check.id}: ${check.message}`);
      if (!check.ok && check.severity === "error") failed = true;
    }
    process.exitCode = failed ? 1 : 0;
    return;
  }

  if (cmd === "validate") {
    const opts = parseOptions(rest);
    const cwd = opts.flags.cwd || process.cwd();
    const { config, path: configPath } = await loadConfig(opts.flags.config || opts.flags.c, cwd);
    const errors = validateConfig(config);
    if (errors.length) {
      console.error(`${pc.red("invalid")} ${configPath ?? "default policy"}`);
      for (const error of errors) console.error(`  - ${error}`);
      process.exitCode = 1;
      return;
    }
    console.log(`${pc.green("valid")} ${configPath ?? "default policy"}`);
    return;
  }

  if (cmd === "run") {
    const split = splitAtDoubleDash(rest);
    const opts = parseOptions(split.before);
    const commandArgs = split.after.length ? split.after : opts.positionals;
    const command = commandArgs[0];
    if (!command) throw new Error("run requires a command after --");
    const cwd = opts.flags.cwd || process.cwd();
    const { config } = await loadConfig(opts.flags.config || opts.flags.c, cwd);
    const code = await runGuarded(command, commandArgs.slice(1), config, {
      cwd,
      assume: opts.flags.assume,
      passEnv: arrayFlag(opts.flags["pass-env"]),
      noSandbox: Boolean(opts.flags["no-sandbox"]),
      strictSandbox: Boolean(opts.flags["strict-sandbox"])
    });
    process.exit(code);
  }

  if (cmd === "check") {
    const split = splitAtDoubleDash(rest);
    const opts = parseOptions(split.before);
    const command = opts.flags["shim-command"];
    if (!command) throw new Error("check requires --shim-command");
    const cwd = opts.flags.cwd || process.cwd();
    const { config } = await loadConfig(opts.flags.config || opts.flags.c, cwd);
    const code = await runShimCheck(command, split.after, config, {
      cwd,
      auditFile: opts.flags["audit-file"],
      assume: opts.flags.assume || process.env.AGENT_TRUST_ASSUME
    });
    process.exit(code);
  }

  if (cmd === "mcp") {
    const split = splitAtDoubleDash(rest);
    const opts = parseOptions(split.before);
    const commandArgs = split.after.length ? split.after : opts.positionals;
    const command = commandArgs[0];
    if (!command) throw new Error("mcp requires a command after --");
    const cwd = opts.flags.cwd || process.cwd();
    const { config } = await loadConfig(opts.flags.config || opts.flags.c, cwd);
    const code = await runMcpProxy(command, commandArgs.slice(1), config, {
      cwd,
      assume: opts.flags.assume,
      passEnv: arrayFlag(opts.flags["pass-env"])
    });
    process.exit(code);
  }

  if (cmd === "scan") {
    const opts = parseOptions(rest);
    const cwd = opts.flags.cwd || process.cwd();
    const { config } = await loadConfig(opts.flags.config || opts.flags.c, cwd);
    const result = await scanPaths(opts.positionals, config, cwd);
    printFindings(result.findings, cwd);
    console.log(`${result.filesScanned} files scanned, ${result.findings.length} findings`);
    const failOn = opts.flags["fail-on"] || config.secrets.failOn;
    process.exitCode = result.findings.some((finding) => compareRisk(finding.risk, failOn) >= 0) ? 2 : 0;
    return;
  }

  if (cmd === "audit") {
    const opts = parseOptions(rest);
    const cwd = opts.flags.cwd || process.cwd();
    const { config } = await loadConfig(opts.flags.config || opts.flags.c, cwd);
    const files = opts.positionals.length ? opts.positionals.map((f) => path.resolve(cwd, f)) : await listAuditFiles(config.auditDir);
    let failed = false;
    for (const file of files) {
      const result = await verifyAuditFile(file);
      const marker = result.ok ? pc.green("ok") : pc.red("fail");
      console.log(`${marker} ${file}: ${result.events} events${result.error ? ` (${result.error})` : ""}`);
      if (!result.ok) failed = true;
    }
    if (opts.flags.export) {
      const out = path.resolve(cwd, opts.flags.export);
      await writeEvidenceBundle(config, files, out);
      console.log(`${pc.green("exported")} ${out}`);
    }
    process.exitCode = failed ? 1 : 0;
    return;
  }

  if (cmd === "policy") {
    const opts = parseOptions(rest);
    const { config, path: configPath } = await loadConfig(opts.flags.config || opts.flags.c);
    console.log(`policy: ${configPath ?? "default"}`);
    console.log(`defaultAction: ${config.defaultAction}`);
    console.log(`sandbox: ${config.sandbox.enabled ? config.sandbox.mode : "disabled"}`);
    console.log("rules:");
    for (const rule of config.rules) console.log(`  - ${rule.id}: ${rule.action} ${rule.description ? `(${rule.description})` : ""}`);
    return;
  }

  if (cmd === "decide") {
    const split = splitAtDoubleDash(rest);
    const opts = parseOptions(split.before);
    const cwd = opts.flags.cwd || process.cwd();
    const { config } = await loadConfig(opts.flags.config || opts.flags.c, cwd);
    const report = buildDecisionReport(config, opts, split.after, cwd);
    if (opts.flags.json) {
      console.log(JSON.stringify(report, null, 2));
      return;
    }
    printDecisionReport(report);
    return;
  }

  if (cmd === "wrap") {
    const opts = parseOptions(rest);
    const name = opts.positionals[0] || "claude";
    const command = wrapperCommand(name, Boolean(opts.flags.dangerous));
    console.log("# Add this to your shell profile or paste it into the current shell.");
    console.log(`alias ${safeAliasName(name)}=${JSON.stringify(command)}`);
    return;
  }

  throw new Error(`unknown command: ${cmd}`);
}

function parseOptions(args) {
  const flags = {};
  const positionals = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith("--")) {
      const { key: rawKey, value: inline } = parseLongFlag(arg);
      const next = args[i + 1];
      if (inline !== undefined) setFlag(flags, rawKey, inline);
      else if (next && !next.startsWith("-")) setFlag(flags, rawKey, args[++i]);
      else setFlag(flags, rawKey, true);
    } else if (arg.startsWith("-") && arg.length > 1) {
      const { key, value: inline } = parseShortFlag(arg);
      const next = args[i + 1];
      if (inline !== undefined) setFlag(flags, key, inline);
      else if (next && !next.startsWith("-")) setFlag(flags, key, args[++i]);
      else setFlag(flags, key, true);
    } else {
      positionals.push(arg);
    }
  }
  return { flags, positionals };
}

function parseLongFlag(arg) {
  const body = arg.slice(2);
  const eq = body.indexOf("=");
  if (eq === -1) return { key: body, value: undefined };
  return { key: body.slice(0, eq), value: body.slice(eq + 1) };
}

function parseShortFlag(arg) {
  const body = arg.slice(1);
  const eq = body.indexOf("=");
  if (eq === -1) return { key: body, value: undefined };
  return { key: body.slice(0, eq), value: body.slice(eq + 1) };
}

function setFlag(flags, key, value) {
  if (flags[key] === undefined) flags[key] = value;
  else if (Array.isArray(flags[key])) flags[key].push(value);
  else flags[key] = [flags[key], value];
}

function splitAtDoubleDash(args) {
  const index = args.indexOf("--");
  if (index === -1) return { before: args, after: [] };
  return { before: args.slice(0, index), after: args.slice(index + 1) };
}

function arrayFlag(value) {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function buildDecisionReport(config, opts, trailingCommand, cwd) {
  const subjects = [];
  const findings = [];
  const analyses = [];
  const command = opts.flags.command || opts.flags.cmd || trailingCommand[0];
  const commandArgs = trailingCommand.length ? trailingCommand.slice(1) : arrayFlag(opts.flags.arg);
  if (command) {
    const commandDecision = decideCommand(config, command, commandArgs, cwd, process.env);
    findings.push(...commandDecision.findings);
    subjects.push(...commandDecision.subjects.map((subject) => ({
      ...subject,
      detectedRisk: mergeRisk(subject.detectedRisk, opts.flags.risk)
    })));
    analyses.push(commandDecision.analysis);
  }

  for (const item of arrayFlag(opts.flags.path)) {
    const pathAnalysis = analyzePath(item, cwd, config);
    analyses.push({
      kind: "path-analysis",
      input: item,
      path: pathAnalysis.path,
      tags: Array.from(pathAnalysis.tags).sort(),
      reason: pathAnalysis.reasons.join("; ") || "path appears project-local"
    });
    subjects.push({
      kind: "filesystem",
      path: pathAnalysis.path,
      analysisTags: Array.from(pathAnalysis.tags),
      detectedRisk: mergeRisk(pathAnalysis.tags.has("catastrophic") ? "critical" : pathAnalysis.tags.has("credential") || pathAnalysis.tags.has("system") ? "high" : undefined, opts.flags.risk)
    });
  }

  for (const host of arrayFlag(opts.flags.host)) {
    subjects.push({ kind: "network", networkHost: host, detectedRisk: mergeRisk(undefined, opts.flags.risk) });
  }

  const contents = arrayFlag(opts.flags.content);
  const contentText = contents.join("\n");
  const contentFindings = contentText ? scanText(contentText, config, "content") : [];
  const contentRisk = mergeRisk(highestFindingRisk(contentFindings), opts.flags.risk);
  findings.push(...contentFindings);

  for (const tool of arrayFlag(opts.flags.tool)) {
    subjects.push({ kind: "mcp-tool", mcpTool: tool, content: contentText || undefined, detectedRisk: contentRisk });
  }

  if (contentText && !arrayFlag(opts.flags.tool).length) {
    subjects.push({ kind: "content", content: contentText, detectedRisk: contentRisk });
  }

  if (!subjects.length && opts.positionals.length) {
    for (const item of opts.positionals) {
      const pathAnalysis = analyzePath(item, cwd, config);
      subjects.push({ kind: "filesystem", path: pathAnalysis.path, analysisTags: Array.from(pathAnalysis.tags), detectedRisk: mergeRisk(undefined, opts.flags.risk) });
    }
  }

  if (!subjects.length) throw new Error("decide requires --path, --host, --tool, --content, --command or a command after --");

  const checks = subjects.map((subject) => {
    const decision = evaluatePolicy(config, subject);
    return {
      ...decision,
      subject: summarizeSubject(subject)
    };
  });
  const decision = mergeDecisions(checks);
  return {
    decision: decision.decision,
    ruleId: decision.ruleId,
    reason: decision.reason,
    checks,
    analyses,
    findings: findings.map((finding) => ({
      id: finding.id,
      name: finding.name,
      risk: finding.risk,
      file: finding.file,
      line: finding.line,
      column: finding.column
    }))
  };
}

function mergeRisk(detectedRisk, explicitRisk) {
  if (!explicitRisk) return detectedRisk;
  const values = arrayFlag(explicitRisk);
  const invalid = values.find((risk) => !["low", "medium", "high", "critical"].includes(risk));
  if (invalid) throw new Error(`invalid risk level: ${invalid}`);
  return maxRisk([detectedRisk, ...values]);
}

function summarizeSubject(subject) {
  if (subject.kind === "network") return `network ${subject.networkHost}`;
  if (subject.path) return `path ${subject.path}`;
  if (subject.kind === "analysis") return `analysis ${subject.analysisTags?.join(",") || "none"}`;
  if (subject.kind === "mcp-tool") return `mcp tool ${subject.mcpTool ?? "<unknown>"}`;
  if (subject.kind === "process") return `command ${[subject.command, ...(subject.args ?? [])].join(" ")}`;
  if (subject.kind === "content") return `content risk=${subject.detectedRisk ?? "none"}`;
  return subject.kind;
}

function printDecisionReport(report) {
  const color = report.decision === "deny" ? pc.red : report.decision === "ask" ? pc.yellow : pc.green;
  console.log(`decision: ${color(report.decision)}`);
  console.log(`reason: ${report.reason}`);
  if (report.ruleId) console.log(`rule: ${report.ruleId}`);
  console.log("checks:");
  for (const check of report.checks) {
    const marker = check.decision === "deny" ? pc.red(check.decision) : check.decision === "ask" ? pc.yellow(check.decision) : pc.green(check.decision);
    console.log(`  - ${check.subject}: ${marker}${check.ruleId ? ` (${check.ruleId})` : ""}`);
  }
  if (report.analyses.length) {
    console.log("analysis:");
    for (const analysis of report.analyses) console.log(`  - ${analysis.command ?? analysis.input}: ${analysis.tags.join(", ")} (${analysis.reason})`);
  }
  if (report.findings.length) {
    console.log("findings:");
    for (const finding of report.findings) console.log(`  - ${finding.risk} ${finding.id} at ${finding.file}:${finding.line}:${finding.column}`);
  }
}

async function listAuditFiles(auditDir) {
  try {
    const entries = await readdir(auditDir);
    return entries.filter((entry) => entry.endsWith(".jsonl")).map((entry) => path.join(auditDir, entry));
  } catch {
    return [];
  }
}

function wrapperCommand(name, dangerous) {
  const dangerousFlags = {
    claude: "--dangerously-skip-permissions",
    codex: "--dangerously-bypass-approvals-and-sandbox",
    cursor: "--force"
  };
  const flag = dangerous ? dangerousFlags[name] : undefined;
  return ["agent-trust", "run", "--", name, flag].filter(Boolean).join(" ");
}

function safeAliasName(name) {
  return `${name.replace(/[^A-Za-z0-9_]/g, "_")}_safe`;
}

function printHelp() {
  console.log(`Usage: agent-trust <command> [options]

Commands:
  init              Create .agent-trust/policy.json
  validate          Validate policy structure for local use or CI
  doctor            Check local runtime, policy and audit support
  decide            Dry-run policy decisions for commands, paths, hosts or tools
  run -- <cmd>      Run a command behind the semantic circuit breaker
  mcp -- <cmd>      Proxy an MCP stdio server
  scan [paths...]   Scan files for secrets
  audit [files...]  Verify audit logs or export evidence
  policy            Print policy summary
  wrap [name]       Print a shell alias for common agent CLIs
`);
}

function isDirectExecution() {
  return process.argv[1] ? path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname) : false;
}

export { AuditLog, verifyAuditFile, defaultConfig, evaluatePolicy, globMatches, hostMatches, highestFindingRisk, redactSecrets, scanText };
