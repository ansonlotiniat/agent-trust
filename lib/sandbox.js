import os from "node:os";
import path from "node:path";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";

export async function buildSandboxCommand(config, command, args) {
  if (!config.sandbox.enabled || config.sandbox.mode === "none") {
    return { command, args, mode: "none", warnings: [] };
  }

  const platform = os.platform();
  if ((config.sandbox.mode === "auto" || config.sandbox.mode === "macos") && platform === "darwin") {
    const profilePath = await writeMacProfile(config);
    return { command: "sandbox-exec", args: ["-f", profilePath, command, ...args], profilePath, mode: "macos", warnings: [] };
  }

  if ((config.sandbox.mode === "auto" || config.sandbox.mode === "linux") && platform === "linux") {
    if (await commandExists("bwrap")) return buildBwrapCommand(config, command, args);
    if (await commandExists("firejail")) return buildFirejailCommand(config, command, args);
  }

  return { command, args, mode: "none", warnings: [`no supported OS sandbox found for ${platform}; running with policy/env/audit only`] };
}

async function writeMacProfile(config) {
  const dir = await mkdtemp(path.join(tmpdir(), "agent-trust-"));
  const profilePath = path.join(dir, "sandbox.sb");
  if (config.sandbox.macosProfile === "compat") {
    const lines = ["(version 1)", "(allow default)"];
    for (const denied of config.sandbox.deniedPaths) lines.push(`(deny file-read* file-write* (subpath ${quoteSb(denied)}))`);
    if (!config.sandbox.allowNetwork) lines.push("(deny network*)");
    await writeFile(profilePath, lines.join("\n") + "\n", "utf8");
    return profilePath;
  }

  const lines = [
    "(version 1)",
    "(deny default)",
    "(allow process*)",
    "(allow sysctl-read)",
    "(allow mach-lookup)",
    "(allow signal)",
    "(allow file-read-metadata)",
    "(allow file-read* (literal \"/dev/null\"))",
    "(allow file-read* file-write* (subpath \"/dev\"))",
    "(allow file-read* (subpath \"/usr\"))",
    "(allow file-read* (subpath \"/bin\"))",
    "(allow file-read* (subpath \"/sbin\"))",
    "(allow file-read* (subpath \"/System\"))",
    "(allow file-read* (subpath \"/Library\"))",
    "(allow file-read* (subpath \"/opt/homebrew\"))",
    "(allow file-read* (subpath \"/private/var/folders\"))",
    `(allow file-write* (subpath ${quoteSb(config.projectRoot)}))`,
    `(allow file-write* (subpath ${quoteSb(path.join(config.projectRoot, ".agent-trust"))}))`
  ];
  for (const readable of config.sandbox.readablePaths) lines.push(`(allow file-read* (subpath ${quoteSb(readable)}))`);
  for (const writable of config.sandbox.writablePaths) lines.push(`(allow file-write* (subpath ${quoteSb(writable)}))`);
  for (const denied of config.sandbox.deniedPaths) lines.push(`(deny file-read* file-write* (subpath ${quoteSb(denied)}))`);
  lines.push(config.sandbox.allowNetwork ? "(allow network*)" : "(deny network*)");
  await writeFile(profilePath, lines.join("\n") + "\n", "utf8");
  return profilePath;
}

function buildBwrapCommand(config, command, args) {
  const bwrapArgs = [
    "--die-with-parent", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
    "--ro-bind", "/usr", "/usr", "--ro-bind", "/bin", "/bin",
    "--ro-bind", "/lib", "/lib", "--ro-bind", "/lib64", "/lib64",
    "--ro-bind", config.projectRoot, config.projectRoot
  ];
  for (const writable of config.sandbox.writablePaths) bwrapArgs.push("--bind", writable, writable);
  if (config.sandbox.allowNetwork) bwrapArgs.push("--share-net");
  bwrapArgs.push("--chdir", config.projectRoot, command, ...args);
  return { command: "bwrap", args: bwrapArgs, mode: "linux-bwrap", warnings: [] };
}

function buildFirejailCommand(config, command, args) {
  const firejailArgs = ["--quiet", "--private-dev", `--whitelist=${config.projectRoot}`, `--private=${config.projectRoot}`];
  if (!config.sandbox.allowNetwork) firejailArgs.push("--net=none");
  firejailArgs.push(command, ...args);
  return { command: "firejail", args: firejailArgs, mode: "linux-firejail", warnings: [] };
}

function quoteSb(value) {
  return JSON.stringify(path.resolve(value));
}

async function commandExists(command) {
  const { spawnSync } = await import("node:child_process");
  return spawnSync("which", [command], { stdio: "ignore" }).status === 0;
}
