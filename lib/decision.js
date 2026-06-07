import { analyzeCommand, subjectFromAnalysis } from "./analyze.js";
import { evaluatePolicy, mergeDecisions } from "./policy.js";
import { highestFindingRisk, scanText } from "./secrets.js";
import { maxRisk } from "./risk.js";

export function decideCommand(config, command, args = [], cwd = process.cwd(), env = process.env) {
  const commandText = [command, ...args].join(" ");
  const findings = scanText(commandText, config, "command");
  const analysis = analyzeCommand(command, args, cwd, config);
  const secretRisk = highestFindingRisk(findings);
  const analysisSubject = subjectFromAnalysis(analysis);
  const subjects = [
    { kind: "process", command, args, cwd, env, content: commandText, detectedRisk: secretRisk },
    { ...analysisSubject, detectedRisk: maxRisk([secretRisk, analysisSubject.detectedRisk]) }
  ];
  const checks = subjects.map((subject) => evaluatePolicy(config, subject));
  const policy = mergeDecisions(checks);
  return { policy, subjects, findings, analysis, checks };
}
