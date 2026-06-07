import path from "node:path";
import { riskGte } from "./risk.js";
import { expandHome } from "./paths.js";

export function evaluatePolicy(config, subject) {
  for (const rule of config.rules) {
    if (matchesRule(rule, subject)) {
      return {
        decision: rule.action,
        ruleId: rule.id,
        reason: rule.description ?? `matched ${rule.id}`
      };
    }
  }

  if (subject.kind === "network" && subject.networkHost) {
    const allowed = config.network.allowedHosts.some((host) => hostMatches(host, subject.networkHost));
    if (allowed) return { decision: "allow", ruleId: "network-allowed-host", reason: `network host ${subject.networkHost} is in allowedHosts` };
    if (config.network.blockByDefault) return { decision: "ask", ruleId: "network-block-by-default", reason: `network host ${subject.networkHost} is not in allowedHosts` };
    return { decision: "allow", ruleId: "network-observe", reason: `network host ${subject.networkHost} observed` };
  }

  return { decision: config.defaultAction, reason: `no rule matched; defaultAction=${config.defaultAction}` };
}

export function mergeDecisions(results) {
  const rank = { allow: 1, ask: 2, deny: 3 };
  let best = results[0] ?? { decision: "allow", reason: "no checks" };
  for (const result of results) {
    if (rank[result.decision] > rank[best.decision]) best = result;
  }
  return best;
}

export function matchesRule(rule, subject) {
  return matchesCondition(rule.when, subject);
}

function matchesCondition(condition, subject) {
  const checks = [];
  if (condition.command?.length) checks.push(Boolean(subject.command && condition.command.some((cmd) => basenameMatches(cmd, subject.command))));
  if (condition.commandRegex?.length) checks.push(Boolean(subject.command && condition.commandRegex.some((pattern) => new RegExp(pattern).test(subject.command))));
  if (condition.argsContain?.length) checks.push(condition.argsContain.some((needle) => (subject.args ?? []).join(" ").includes(needle)));
  if (condition.path?.length) checks.push(Boolean(subject.path && condition.path.some((pattern) => globMatches(pattern, subject.path))));
  if (condition.pathRegex?.length) checks.push(Boolean(subject.path && condition.pathRegex.some((pattern) => new RegExp(pattern).test(subject.path))));
  if (condition.env?.length) checks.push(condition.env.some((key) => Object.keys(subject.env ?? {}).includes(key)));
  if (condition.analysisTag?.length) checks.push(Boolean(subject.analysisTags?.length && condition.analysisTag.some((tag) => subject.analysisTags.includes(tag))));
  if (condition.networkHost?.length) checks.push(Boolean(subject.networkHost && condition.networkHost.some((host) => hostMatches(host, subject.networkHost))));
  if (condition.networkHostRegex?.length) checks.push(Boolean(subject.networkHost && condition.networkHostRegex.some((pattern) => new RegExp(pattern).test(subject.networkHost))));
  if (condition.mcpTool?.length) checks.push(Boolean(subject.mcpTool && condition.mcpTool.includes(subject.mcpTool)));
  if (condition.contentContains?.length) checks.push(Boolean(subject.content && condition.contentContains.some((needle) => subject.content.includes(needle))));
  if (condition.riskAtLeast) checks.push(riskGte(subject.detectedRisk, condition.riskAtLeast));
  return checks.length > 0 && checks.every(Boolean);
}

function basenameMatches(expected, command) {
  return expected === command || expected === path.basename(command);
}

export function hostMatches(pattern, host) {
  const normalized = host.toLowerCase();
  const p = pattern.toLowerCase();
  if (p === normalized) return true;
  if (p.startsWith("*.")) {
    const suffix = p.slice(1);
    return normalized.endsWith(suffix) && normalized !== p.slice(2);
  }
  return false;
}

export function globMatches(pattern, actual) {
  const normalizedPattern = normalizeGlob(pattern.startsWith("~") ? expandHome(pattern) : pattern);
  const normalizedActual = actual.replaceAll("\\", "/");
  const regex = "^" + globToRegex(normalizedPattern) + "$";
  return new RegExp(regex).test(normalizedActual);
}

function normalizeGlob(value) {
  return value.replaceAll("\\", "/");
}

function escapeRegex(value) {
  return value.replace(/[|\\{}()[\]^$+?.]/g, "\\$&");
}

function globToRegex(pattern) {
  let out = "";
  for (let i = 0; i < pattern.length; i++) {
    const char = pattern[i];
    if (char === "*") {
      if (pattern[i + 1] === "*") {
        out += ".*";
        i++;
      } else {
        out += "[^/]*";
      }
      continue;
    }
    out += escapeRegex(char);
  }
  return out;
}
