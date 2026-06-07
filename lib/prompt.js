import readline from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import pc from "./colors.js";


export async function resolveAsk(policy, interactive, assumed) {
  if (policy.decision !== "ask") return policy.decision;
  if (assumed) return assumed;
  if (!interactive || !input.isTTY) return "deny";

  const rl = readline.createInterface({ input, output });
  try {
    output.write(`${pc.yellow("?")} ${policy.reason}\n`);
    const answer = await rl.question("Allow this action? [y/N/a=allow once] ");
    const normalized = answer.trim().toLowerCase();
    return normalized === "y" || normalized === "yes" || normalized === "a" ? "allow" : "deny";
  } finally {
    rl.close();
  }
}

//# sourceMappingURL=prompt.js.map
