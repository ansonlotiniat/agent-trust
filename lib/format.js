import pc from "./colors.js";
import { normalizeForDisplay } from "./paths.js";

export function formatDecision(decision) {
  if (decision === "allow") return pc.green(decision);
  if (decision === "ask") return pc.yellow(decision);
  return pc.red(decision);
}

export function formatRisk(risk) {
  if (risk === "critical") return pc.red(pc.bold(risk));
  if (risk === "high") return pc.red(risk);
  if (risk === "medium") return pc.yellow(risk);
  return pc.gray(risk);
}

export function printFindings(findings, cwd = process.cwd()) {
  for (const finding of findings) {
    const loc = finding.file ? `${normalizeForDisplay(finding.file, cwd)}:${finding.line ?? 1}:${finding.column ?? 1}` : "content";
    console.log(`${formatRisk(finding.risk)} ${finding.id} ${loc}`);
    if (finding.context) console.log(`  ${pc.gray(finding.context)}`);
  }
}
