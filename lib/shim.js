import path from "node:path";
import { chmod, mkdir, writeFile } from "node:fs/promises";

export const SHIMMED_COMMANDS = [
  "rm",
  "mv",
  "cp",
  "chmod",
  "chown",
  "chgrp",
  "dd",
  "mkfs",
  "diskutil",
  "sudo",
  "tee",
  "truncate",
  "ln",
  "mkdir",
  "rmdir",
  "touch",
  "cat",
  "head",
  "tail",
  "less",
  "more",
  "sed",
  "sh",
  "bash",
  "zsh"
];

export async function installCommandShims(config, auditFile, cwd, assume) {
  const dir = path.join(config.projectRoot, ".agent-trust", "tmp", "bin");
  await mkdir(dir, { recursive: true });
  const cli = path.resolve(new URL(import.meta.url).pathname, "..", "cli.js");
  for (const command of SHIMMED_COMMANDS) {
    const file = path.join(dir, command);
    const script = [
      "#!/bin/sh",
      "set -eu",
      `export AGENT_TRUST_ORIGINAL_PATH="${escapeShell(process.env.PATH ?? "")}"`,
      `exec "${process.execPath}" "${cli}" check --shim-command "${command}" --cwd "${cwd}" --audit-file "${auditFile}"${assume ? ` --assume "${assume}"` : ""} -- "$@"`
    ].join("\n") + "\n";
    await writeFile(file, script, "utf8");
    await chmod(file, 0o755);
  }
  return { dir, commands: SHIMMED_COMMANDS };
}

function escapeShell(value) {
  return value.replaceAll("\\", "\\\\").replaceAll("\"", "\\\"");
}
