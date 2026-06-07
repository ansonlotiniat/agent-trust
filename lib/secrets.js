import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { compareRisk } from "./risk.js";

const builtInPatterns = [
  { id: "openai-api-key", name: "OpenAI API key", pattern: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{24,}\b/g, risk: "critical" },
  { id: "anthropic-api-key", name: "Anthropic API key", pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g, risk: "critical" },
  { id: "github-token", name: "GitHub token", pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\b/g, risk: "critical" },
  { id: "aws-access-key", name: "AWS access key", pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, risk: "critical" },
  { id: "google-api-key", name: "Google API key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g, risk: "high" },
  { id: "private-key", name: "Private key block", pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/g, risk: "critical" },
  { id: "slack-token", name: "Slack token", pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g, risk: "high" },
  { id: "jwt", name: "JWT-like token", pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, risk: "medium" },
  { id: "assignment-secret", name: "Secret assignment", pattern: /\b(?:api[_-]?key|secret|token|password|passwd|private[_-]?key)\s*[:=]\s*["']?[^"'\s]{12,}/gi, risk: "medium" }
];

export function patternsFromConfig(config) {
  const additional = config.secrets.additionalPatterns.map((item) => ({
    id: item.id,
    name: item.id,
    pattern: new RegExp(item.pattern, "g"),
    risk: item.risk
  }));
  return [...builtInPatterns, ...additional];
}

export function scanText(text, config, file) {
  if (!config.secrets.enabled) return [];
  const findings = [];
  const lineStarts = computeLineStarts(text);
  for (const def of patternsFromConfig(config)) {
    def.pattern.lastIndex = 0;
    for (const match of text.matchAll(def.pattern)) {
      const value = match[0];
      const index = match.index ?? 0;
      const location = offsetToLineColumn(lineStarts, index);
      findings.push({ id: def.id, name: def.name, risk: def.risk, file, line: location.line, column: location.column, match: value, context: contextAround(text, index, value.length) });
    }
  }
  return findings;
}

export async function scanFile(filePath, config, maxBytes = 2_000_000) {
  const info = await stat(filePath);
  if (!info.isFile() || info.size > maxBytes) return [];
  const data = await readFile(filePath);
  if (data.includes(0)) return [];
  return scanText(data.toString("utf8"), config, filePath);
}

export function highestFindingRisk(findings) {
  return findings.map((finding) => finding.risk).sort(compareRisk).at(-1);
}

export function redactSecrets(text, config) {
  let redacted = text;
  for (const def of patternsFromConfig(config)) {
    def.pattern.lastIndex = 0;
    redacted = redacted.replace(def.pattern, (value) => `${value.slice(0, Math.min(4, value.length))}[REDACTED:${def.id}]`);
  }
  return redacted;
}

export function redactFinding(finding, config) {
  if (!config.secrets.redactAudit) return finding;
  return {
    ...finding,
    match: `${finding.match.slice(0, Math.min(4, finding.match.length))}[REDACTED:${finding.id}]`,
    context: finding.context ? redactSecrets(finding.context, config) : undefined
  };
}

function computeLineStarts(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === "\n") starts.push(i + 1);
  return starts;
}

function offsetToLineColumn(lineStarts, offset) {
  let low = 0;
  let high = lineStarts.length - 1;
  while (low <= high) {
    const mid = Math.floor((low + high) / 2);
    if (lineStarts[mid] <= offset) low = mid + 1;
    else high = mid - 1;
  }
  const lineIndex = Math.max(0, high);
  return { line: lineIndex + 1, column: offset - lineStarts[lineIndex] + 1 };
}

function contextAround(text, index, length) {
  const start = Math.max(0, index - 40);
  const end = Math.min(text.length, index + length + 40);
  return text.slice(start, end).replace(/\s+/g, " ");
}

export function likelySecretFile(filePath) {
  const base = path.basename(filePath).toLowerCase();
  return [".env", ".npmrc", ".pypirc", ".netrc", "id_rsa", "id_ed25519", "credentials", "credentials.json"].includes(base) || base.endsWith(".pem") || base.endsWith(".key");
}
