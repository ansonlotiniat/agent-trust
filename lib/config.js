import path from "node:path";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { CONFIG_DIR, CONFIG_FILE, DEFAULT_AUDIT_DIR, pathExists, resolveFrom, expandHome } from "./paths.js";

const ACTIONS = new Set(["allow", "ask", "deny"]);
const RISKS = new Set(["low", "medium", "high", "critical"]);
const SANDBOX_MODES = new Set(["auto", "macos", "linux", "none"]);
const MACOS_PROFILES = new Set(["compat", "strict"]);
const ARRAY_CONDITIONS = new Set([
  "command",
  "commandRegex",
  "argsContain",
  "path",
  "pathRegex",
  "env",
  "analysisTag",
  "networkHost",
  "networkHostRegex",
  "mcpTool",
  "contentContains"
]);
const REGEX_CONDITIONS = new Set(["commandRegex", "pathRegex", "networkHostRegex"]);
const SCALAR_CONDITIONS = new Set(["riskAtLeast"]);

export const defaultConfig = {
  version: 1,
  defaultAction: "allow",
  interactive: true,
  projectRoot: ".",
  auditDir: DEFAULT_AUDIT_DIR,
  sandbox: {
    enabled: false,
    mode: "none",
    macosProfile: "compat",
    writablePaths: [".", ".agent-trust/tmp"],
    readablePaths: ["."],
    deniedPaths: ["~/.ssh", "~/.aws", "~/.config/gcloud", "~/.kube", "~/.docker", "~/.netrc", "~/.gnupg", "~/.npmrc", "~/.pypirc", "~/.cargo/credentials", "~/.git-credentials"],
    allowNetwork: true,
    allowedHosts: ["api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com", "github.com", "api.github.com", "registry.npmjs.org", "pypi.org", "files.pythonhosted.org"]
  },
  secrets: {
    enabled: true,
    failOn: "high",
    redactAudit: true,
    scrubEnv: false,
    additionalPatterns: []
  },
  network: {
    proxyEnv: false,
    blockByDefault: false,
    allowedHosts: ["api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com", "github.com", "api.github.com", "registry.npmjs.org", "pypi.org", "files.pythonhosted.org"]
  },
  rules: [
    { id: "deny-catastrophic-actions", description: "Stop filesystem-wide destructive operations such as rm -rf / or rm -rf ~.", action: "deny", when: { analysisTag: ["catastrophic"] } },
    { id: "deny-credential-mutation", description: "Stop writes or deletes targeting credential material.", action: "deny", when: { analysisTag: ["credential-mutation"] } },
    { id: "ask-credential-path", description: "Brake before touching local credential paths.", action: "ask", when: { analysisTag: ["credential"] } },
    { id: "ask-credential-access", description: "Brake before reading local credential material.", action: "ask", when: { analysisTag: ["credential-access"] } },
    { id: "ask-system-mutation", description: "Brake before mutating system files or directories.", action: "ask", when: { analysisTag: ["system-mutation"] } },
    { id: "ask-system-path", description: "Brake before touching system paths.", action: "ask", when: { analysisTag: ["system"] } },
    { id: "ask-shell-config-mutation", description: "Brake before changing shell startup files.", action: "ask", when: { analysisTag: ["shell-config-mutation"] } },
    { id: "ask-privilege-escalation", description: "Brake before commands that request elevated privileges.", action: "ask", when: { analysisTag: ["privilege-escalation"] } },
    { id: "ask-disk-operations", description: "Brake before direct disk or filesystem operations.", action: "ask", when: { analysisTag: ["disk-operation"] } },
    { id: "deny-critical-secrets", description: "Block tool calls containing critical secrets.", action: "deny", when: { riskAtLeast: "critical" } },
    { id: "ask-high-risk-secrets", description: "Require approval for high-risk secret exposure.", action: "ask", when: { riskAtLeast: "high" } }
  ]
};

export function defaultPolicyYaml() {
  return JSON.stringify(defaultConfig, null, 2) + "\n";
}

export async function initConfig(cwd = process.cwd(), force = false) {
  const dir = path.join(cwd, CONFIG_DIR);
  const file = path.join(dir, CONFIG_FILE);
  await mkdir(dir, { recursive: true });
  await mkdir(path.join(cwd, ".agent-trust/audit"), { recursive: true });
  await mkdir(path.join(cwd, ".agent-trust/tmp"), { recursive: true });
  if (!force && await pathExists(file)) return file;
  await writeFile(file, defaultPolicyYaml(), "utf8");
  return file;
}

export async function findConfig(startDir = process.cwd()) {
  let current = path.resolve(startDir);
  while (true) {
    const candidate = path.join(current, CONFIG_DIR, CONFIG_FILE);
    if (await pathExists(candidate)) return candidate;
    const parent = path.dirname(current);
    if (parent === current) return null;
    current = parent;
  }
}

export async function loadConfig(configPath, cwd = process.cwd()) {
  const found = configPath ? path.resolve(cwd, configPath) : await findConfig(cwd);
  if (!found) return { config: normalizeConfig(defaultConfig, cwd), path: null };
  const raw = await readFile(found, "utf8");
  const parsed = JSON.parse(raw);
  const merged = mergeConfig(defaultConfig, parsed ?? {});
  assertValidConfig(merged, found);
  return { config: normalizeConfig(merged, path.dirname(path.dirname(found))), path: found };
}

export function assertValidConfig(config, source = "policy") {
  const errors = validateConfig(config);
  if (errors.length) {
    throw new Error(`${source} is invalid:\n${errors.map((error) => `  - ${error}`).join("\n")}`);
  }
}

export function validateConfig(config) {
  const errors = [];
  if (!isPlainObject(config)) return ["policy must be a JSON object"];

  if (config.version !== undefined && typeof config.version !== "number") errors.push("version must be a number");
  requireString(config, "projectRoot", errors);
  requireString(config, "auditDir", errors);
  requireBoolean(config, "interactive", errors);
  requireEnum(config, "defaultAction", ACTIONS, errors);

  validateSandbox(config.sandbox, errors);
  validateSecrets(config.secrets, errors);
  validateNetwork(config.network, errors);
  validateRules(config.rules, errors);

  return errors;
}

function mergeConfig(base, override) {
  return {
    ...base,
    ...override,
    sandbox: { ...base.sandbox, ...(override.sandbox ?? {}) },
    secrets: { ...base.secrets, ...(override.secrets ?? {}) },
    network: { ...base.network, ...(override.network ?? {}) },
    rules: override.rules ?? base.rules
  };
}

function normalizeConfig(config, base) {
  const projectRoot = resolveFrom(base, config.projectRoot);
  const policyPath = (p) => p.startsWith("~") ? expandHome(p) : resolveFrom(projectRoot, p);
  return {
    ...config,
    projectRoot,
    auditDir: resolveFrom(projectRoot, config.auditDir),
    sandbox: {
      ...config.sandbox,
      writablePaths: config.sandbox.writablePaths.map(policyPath),
      readablePaths: config.sandbox.readablePaths.map(policyPath),
      deniedPaths: config.sandbox.deniedPaths.map(policyPath)
    },
    rules: config.rules.map((rule) => {
      const when = { ...rule.when };
      if (when.path) when.path = when.path.map(policyPath);
      return { ...rule, when };
    })
  };
}

function validateSandbox(value, errors) {
  if (!isPlainObject(value)) {
    errors.push("sandbox must be an object");
    return;
  }
  requireBoolean(value, "sandbox.enabled", errors, "enabled");
  requireEnum(value, "sandbox.mode", SANDBOX_MODES, errors, "mode");
  requireEnum(value, "sandbox.macosProfile", MACOS_PROFILES, errors, "macosProfile");
  requireStringArray(value, "sandbox.writablePaths", errors, "writablePaths");
  requireStringArray(value, "sandbox.readablePaths", errors, "readablePaths");
  requireStringArray(value, "sandbox.deniedPaths", errors, "deniedPaths");
  requireBoolean(value, "sandbox.allowNetwork", errors, "allowNetwork");
  requireStringArray(value, "sandbox.allowedHosts", errors, "allowedHosts");
}

function validateSecrets(value, errors) {
  if (!isPlainObject(value)) {
    errors.push("secrets must be an object");
    return;
  }
  requireBoolean(value, "secrets.enabled", errors, "enabled");
  requireEnum(value, "secrets.failOn", RISKS, errors, "failOn");
  requireBoolean(value, "secrets.redactAudit", errors, "redactAudit");
  if (value.scrubEnv !== undefined) requireBoolean(value, "secrets.scrubEnv", errors, "scrubEnv");
  if (!Array.isArray(value.additionalPatterns)) {
    errors.push("secrets.additionalPatterns must be an array");
    return;
  }
  value.additionalPatterns.forEach((pattern, index) => {
    const prefix = `secrets.additionalPatterns[${index}]`;
    if (!isPlainObject(pattern)) {
      errors.push(`${prefix} must be an object`);
      return;
    }
    requireString(pattern, `${prefix}.id`, errors, "id");
    requireString(pattern, `${prefix}.pattern`, errors, "pattern");
    requireEnum(pattern, `${prefix}.risk`, RISKS, errors, "risk");
    if (typeof pattern.pattern === "string") validateRegex(pattern.pattern, `${prefix}.pattern`, errors);
  });
}

function validateNetwork(value, errors) {
  if (!isPlainObject(value)) {
    errors.push("network must be an object");
    return;
  }
  requireBoolean(value, "network.proxyEnv", errors, "proxyEnv");
  requireBoolean(value, "network.blockByDefault", errors, "blockByDefault");
  requireStringArray(value, "network.allowedHosts", errors, "allowedHosts");
}

function validateRules(value, errors) {
  if (!Array.isArray(value)) {
    errors.push("rules must be an array");
    return;
  }
  value.forEach((rule, index) => {
    const prefix = `rules[${index}]`;
    if (!isPlainObject(rule)) {
      errors.push(`${prefix} must be an object`);
      return;
    }
    requireString(rule, `${prefix}.id`, errors, "id");
    requireEnum(rule, `${prefix}.action`, ACTIONS, errors, "action");
    if (rule.description !== undefined && typeof rule.description !== "string") errors.push(`${prefix}.description must be a string`);
    validateRuleCondition(rule.when, `${prefix}.when`, errors);
  });
}

function validateRuleCondition(condition, prefix, errors) {
  if (!isPlainObject(condition)) {
    errors.push(`${prefix} must be an object`);
    return;
  }
  const keys = Object.keys(condition);
  if (!keys.length) errors.push(`${prefix} must contain at least one condition`);
  for (const key of keys) {
    const label = `${prefix}.${key}`;
    if (ARRAY_CONDITIONS.has(key)) {
      requireStringArray(condition, label, errors, key);
      if (REGEX_CONDITIONS.has(key) && Array.isArray(condition[key])) {
        condition[key].forEach((pattern, index) => validateRegex(pattern, `${label}[${index}]`, errors));
      }
      continue;
    }
    if (SCALAR_CONDITIONS.has(key)) {
      requireEnum(condition, label, RISKS, errors, key);
      continue;
    }
    errors.push(`${label} is not a supported condition`);
  }
}

function requireString(object, label, errors, key = label) {
  if (typeof object[key] !== "string" || object[key].length === 0) errors.push(`${label} must be a non-empty string`);
}

function requireBoolean(object, label, errors, key = label) {
  if (typeof object[key] !== "boolean") errors.push(`${label} must be a boolean`);
}

function requireEnum(object, label, values, errors, key = label) {
  if (!values.has(object[key])) errors.push(`${label} must be one of: ${Array.from(values).join(", ")}`);
}

function requireStringArray(object, label, errors, key = label) {
  const value = object[key];
  if (!Array.isArray(value)) {
    errors.push(`${label} must be an array`);
    return;
  }
  value.forEach((item, index) => {
    if (typeof item !== "string" || item.length === 0) errors.push(`${label}[${index}] must be a non-empty string`);
  });
}

function validateRegex(pattern, label, errors) {
  try {
    new RegExp(pattern);
  } catch (error) {
    errors.push(`${label} must be a valid regular expression (${error.message})`);
  }
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
