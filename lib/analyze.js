import path from "node:path";
import { expandHome, resolveFrom } from "./paths.js";

const WRITE_COMMANDS = new Set(["rm", "mv", "cp", "touch", "mkdir", "rmdir", "ln", "tee", "truncate"]);
const PERMISSION_COMMANDS = new Set(["chmod", "chown", "chgrp"]);
const CATASTROPHIC_ROOT_PATTERNS = new Set(["/", "/*", "/.", "/.."]);
const CREDENTIAL_SEGMENTS = new Set([
  ".env",
  ".ssh",
  ".aws",
  ".kube",
  ".docker",
  ".gnupg",
  ".config/gcloud",
  ".netrc",
  ".npmrc",
  ".pypirc",
  ".git-credentials",
  "credentials",
  "credentials.json",
  "id_rsa",
  "id_ed25519"
]);
const SHELL_CONFIG_BASENAMES = new Set([
  ".bash_profile",
  ".bash_login",
  ".bashrc",
  ".zprofile",
  ".zshenv",
  ".zshrc",
  ".profile",
  "config.fish"
]);
const SHELL_COMMANDS = new Set(["sh", "bash", "zsh"]);

export function analyzeCommand(command, args = [], cwd = process.cwd(), config) {
  const base = path.basename(command);
  const unwrapped = unwrapSudo(base, args);
  if (unwrapped) {
    if (unwrapped.command === "sudo") {
      return {
        kind: "command-analysis",
        command: base,
        args,
        tags: ["privilege-escalation"],
        targets: [],
        reason: "sudo requests elevated privileges"
      };
    }
    const inner = analyzeCommand(unwrapped.command, unwrapped.args, cwd, config);
    return {
      ...inner,
      command: base,
      args,
      tags: unique([...inner.tags, "privilege-escalation"]).sort(),
      reason: unique(["sudo requests elevated privileges", inner.reason]).join("; ")
    };
  }
  if (SHELL_COMMANDS.has(base)) return analyzeShell(base, args, cwd, config);

  const targets = targetArgsFor(base, args).map((arg) => analyzePath(arg, cwd, config));
  const tags = new Set();
  const reasons = [];
  const writes = WRITE_COMMANDS.has(base) || PERMISSION_COMMANDS.has(base);
  const destructive = base === "rm" || base === "rmdir" || base === "truncate";
  const permissionChange = PERMISSION_COMMANDS.has(base);
  const forceful = args.some((arg) => arg === "--force" || /^-[A-Za-z]*f[A-Za-z]*$/.test(arg));
  const recursive = args.some((arg) => arg === "--recursive" || /^-[A-Za-z]*r[A-Za-z]*$/.test(arg) || /^-[A-Za-z]*R[A-Za-z]*$/.test(arg));

  if (writes) tags.add("write");
  if (destructive) tags.add("destructive");
  if (permissionChange) tags.add("permission-change");
  if (forceful) tags.add("forceful");
  if (recursive) tags.add("recursive");

  for (const target of targets) {
    for (const tag of target.tags) tags.add(tag);
    reasons.push(...target.reasons);
  }

  if (base === "dd") {
    tags.add("disk-operation");
    if (!targets.length || targets.some((target) => target.tags.has("system") || target.tags.has("root"))) {
      tags.add("catastrophic");
      reasons.push("dd can mutate disks or filesystems directly");
    }
  }

  if (base === "mkfs" || (base === "diskutil" && mutatingDiskutil(args))) {
    tags.add("disk-operation");
    tags.add("catastrophic");
    reasons.push(`${base} can mutate disks or filesystems directly`);
  }

  if (base === "sudo") {
    tags.add("privilege-escalation");
    reasons.push("sudo requests elevated privileges");
  }

  if (destructive && recursive && forceful && targets.some((target) => target.tags.has("root"))) {
    tags.add("catastrophic");
    reasons.push("recursive forced delete targets filesystem root");
  }

  if (destructive && recursive && forceful && targets.some((target) => target.tags.has("home"))) {
    tags.add("catastrophic");
    reasons.push("recursive forced delete targets the home directory");
  }

  if (writes && targets.some((target) => target.tags.has("system"))) {
    tags.add("system-mutation");
    reasons.push("write operation targets system paths");
  }

  if (writes && targets.some((target) => target.tags.has("outside-project"))) {
    tags.add("outside-project-mutation");
    reasons.push("write operation targets paths outside the project");
  }

  if (writes && targets.some((target) => target.tags.has("credential"))) {
    tags.add("credential-mutation");
    reasons.push("write operation targets credential paths");
  }

  if (writes && targets.some((target) => target.tags.has("shell-config"))) {
    tags.add("shell-config-mutation");
    reasons.push("write operation targets shell startup configuration");
  }

  if (!writes && targets.some((target) => target.tags.has("credential"))) {
    tags.add("credential-access");
    reasons.push("command references credential paths");
  }

  if (writes && targets.length && targets.every((target) => target.tags.has("project"))) {
    tags.add("project-local");
    if (destructive) tags.add("project-local-destructive");
  }

  if (!targets.length && base === "rm") {
    tags.add("project-local");
    tags.add("project-local-destructive");
  }

  return {
    kind: "command-analysis",
    command: base,
    args,
    tags: Array.from(tags).sort(),
    targets: targets.map((target) => ({
      input: target.input,
      path: target.path,
      tags: Array.from(target.tags).sort(),
      reasons: target.reasons
    })),
    reason: reasons.length ? unique(reasons).join("; ") : "project-local command risk only"
  };
}

export function analyzeShell(command, args = [], cwd = process.cwd(), config) {
  const scriptIndex = args.findIndex((arg) => arg === "-c");
  if (scriptIndex === -1 || !args[scriptIndex + 1]) {
    return {
      kind: "command-analysis",
      command,
      args,
      tags: ["project-local"],
      targets: [],
      reason: "interactive shell without inline command"
    };
  }

  const script = args[scriptIndex + 1];
  const parts = splitShellCommands(tokenizeShell(script));
  const analyses = parts.map((tokens) => analyzeShellTokens(tokens, cwd, config)).filter(Boolean);
  const tags = unique(analyses.flatMap((analysis) => analysis.tags));
  const targets = analyses.flatMap((analysis) => analysis.targets);
  const reasons = unique(analyses.map((analysis) => analysis.reason).filter(Boolean));
  if (!tags.length) tags.push("project-local");
  return {
    kind: "command-analysis",
    command,
    args,
    tags: tags.sort(),
    targets,
    reason: reasons.length ? reasons.join("; ") : "inline shell command appears project-local"
  };
}

export function analyzePath(input, cwd = process.cwd(), config) {
  const resolved = resolvePathLike(input, cwd);
  const projectRoot = config?.projectRoot ? path.resolve(config.projectRoot) : path.resolve(cwd);
  const home = expandHome("~");
  const tags = new Set();
  const reasons = [];

  if (isRootTarget(input, resolved)) {
    tags.add("root");
    tags.add("catastrophic");
    reasons.push("targets filesystem root");
  }

  if (isSameOrInside(resolved, projectRoot)) tags.add("project");
  else tags.add("outside-project");

  if (isSameOrInside(resolved, home)) tags.add("home-child");
  if (samePath(resolved, home)) {
    tags.add("home");
    tags.add("catastrophic");
    reasons.push("targets the home directory");
  }

  if (isSystemPath(resolved)) {
    tags.add("system");
    reasons.push("targets a system path");
  }

  if (isCredentialPath(resolved, config)) {
    tags.add("credential");
    reasons.push("targets credential material");
  }

  if (isShellConfigPath(resolved)) {
    tags.add("shell-config");
    reasons.push("targets shell startup configuration");
  }

  return { input, path: resolved, tags, reasons: unique(reasons) };
}

export function subjectFromAnalysis(analysis) {
  return {
    kind: "analysis",
    analysisTags: analysis.tags,
    detectedRisk: analysis.tags.includes("catastrophic") ? "critical" : analysis.tags.includes("system-mutation") || analysis.tags.includes("credential-access") || analysis.tags.includes("credential-mutation") ? "high" : undefined
  };
}

function unwrapSudo(command, args) {
  if (command !== "sudo") return undefined;
  const rest = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--") {
      rest.push(...args.slice(i + 1));
      break;
    }
    if (arg === "-u" || arg === "-g" || arg === "-h" || arg === "-p") {
      i++;
      continue;
    }
    if (arg.startsWith("-")) continue;
    rest.push(...args.slice(i));
    break;
  }
  if (!rest.length) return { command: "sudo", args };
  return { command: rest[0], args: rest.slice(1) };
}

function mutatingDiskutil(args) {
  const verb = args.find((arg) => !arg.startsWith("-"));
  return !verb || ["eraseDisk", "eraseVolume", "partitionDisk", "apfs", "repairDisk", "mount", "unmount", "rename"].includes(verb);
}

function targetArgsFor(command, args) {
  if (command === "dd") return args.filter((arg) => arg.startsWith("of=")).map((arg) => arg.slice(3));
  if (command === "tee") return args.filter((arg) => !arg.startsWith("-"));
  if (command === "sed") return targetArgsForSed(args);
  if (command === "sudo") return [];
  if (WRITE_COMMANDS.has(command) || PERMISSION_COMMANDS.has(command) || command === "cat" || command === "less" || command === "more" || command === "head" || command === "tail" || command === "sed") {
    return args.filter((arg) => !arg.startsWith("-") && !isAssignment(arg));
  }
  return args.filter(looksLikePath);
}

function targetArgsForSed(args) {
  const targets = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "-e" || arg === "-f") {
      i++;
      continue;
    }
    if (arg === "-i" && args[i + 1] && !looksLikePath(args[i + 1])) {
      i++;
      continue;
    }
    if (arg.startsWith("-")) continue;
    if (looksLikePath(arg)) targets.push(arg);
  }
  return targets;
}

function resolvePathLike(input, cwd) {
  if (input === "~") return expandHome("~");
  if (input.startsWith("~/")) return expandHome(input);
  if (input.includes("*")) return resolveGlobBase(input, cwd);
  return resolveFrom(cwd, input);
}

function resolveGlobBase(input, cwd) {
  const expanded = input.startsWith("~") ? expandHome(input) : input;
  const firstGlob = expanded.search(/[*?[]/);
  const prefix = firstGlob === -1 ? expanded : expanded.slice(0, firstGlob);
  const base = prefix.endsWith("/") ? prefix.slice(0, -1) || "/" : path.dirname(prefix);
  return path.isAbsolute(base) ? path.normalize(base) : path.normalize(path.join(cwd, base));
}

function isRootTarget(input, resolved) {
  const normalizedInput = input.replaceAll("\\", "/");
  return CATASTROPHIC_ROOT_PATTERNS.has(normalizedInput) || samePath(resolved, path.parse(resolved).root);
}

function isSystemPath(resolved) {
  return ["/etc", "/bin", "/sbin", "/usr", "/System", "/Library", "/private/etc", "/var/db", "/var/root"].some((prefix) => isSameOrInside(resolved, prefix));
}

function isCredentialPath(resolved, config) {
  const denied = config?.sandbox?.deniedPaths ?? [];
  if (denied.some((item) => isSameOrInside(resolved, item))) return true;
  const normalized = resolved.replaceAll("\\", "/");
  const base = path.basename(normalized);
  return base === ".env" || base.startsWith(".env.") || Array.from(CREDENTIAL_SEGMENTS).some((segment) => normalized.includes(`/${segment}`) || normalized.endsWith(`/${segment}`));
}

function isShellConfigPath(resolved) {
  const normalized = resolved.replaceAll("\\", "/");
  const base = path.basename(normalized);
  return SHELL_CONFIG_BASENAMES.has(base) || normalized.endsWith("/.config/fish/config.fish");
}

function isSameOrInside(candidate, parent) {
  const a = path.resolve(candidate);
  const b = path.resolve(parent);
  return a === b || a.startsWith(b.endsWith(path.sep) ? b : `${b}${path.sep}`);
}

function samePath(a, b) {
  return path.resolve(a) === path.resolve(b);
}

function looksLikePath(value) {
  if (!value || value.startsWith("-")) return false;
  return value.includes("/") || value.startsWith(".") || value.startsWith("~");
}

function isAssignment(value) {
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(value);
}

function unique(values) {
  return Array.from(new Set(values));
}

function tokenizeShell(script) {
  const tokens = [];
  let current = "";
  let quote;
  for (let i = 0; i < script.length; i++) {
    const char = script[i];
    if (quote) {
      if (char === quote) quote = undefined;
      else if (char === "\\" && quote === "\"" && script[i + 1]) current += script[++i];
      else current += char;
      continue;
    }
    if (char === "'" || char === "\"") {
      quote = char;
      continue;
    }
    if (/\s/.test(char)) {
      if (current) {
        tokens.push(current);
        current = "";
      }
      continue;
    }
    if (char === "\\" && script[i + 1]) {
      current += script[++i];
      continue;
    }
    if ([";", "|", "&", ">", "<"].includes(char)) {
      if (current) {
        tokens.push(current);
        current = "";
      }
      if ((char === ">" || char === "<" || char === "|" || char === "&") && script[i + 1] === char) {
        tokens.push(char + script[++i]);
      } else {
        tokens.push(char);
      }
      continue;
    }
    current += char;
  }
  if (current) tokens.push(current);
  return tokens;
}

function splitShellCommands(tokens) {
  const commands = [];
  let current = [];
  for (const token of tokens) {
    if (token === ";" || token === "&&" || token === "||" || token === "|") {
      if (current.length) commands.push(current);
      current = [];
      continue;
    }
    current.push(token);
  }
  if (current.length) commands.push(current);
  return commands;
}

function analyzeShellTokens(tokens, cwd, config) {
  const redirects = [];
  const commandTokens = [];
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (/^(?:\d*)>{1,2}$/.test(token) || token === "<") {
      if (tokens[i + 1]) redirects.push(tokens[++i]);
      continue;
    }
    commandTokens.push(token);
  }
  if (!commandTokens.length && !redirects.length) return undefined;

  const commandAnalysis = commandTokens.length ? analyzeCommand(commandTokens[0], commandTokens.slice(1), cwd, config) : undefined;
  const redirectTargets = redirects.map((target) => analyzePath(target, cwd, config));
  const tags = new Set(commandAnalysis?.tags ?? []);
  const reasons = commandAnalysis?.reason ? [commandAnalysis.reason] : [];
  for (const target of redirectTargets) {
    for (const tag of target.tags) tags.add(tag);
    if (target.tags.has("system")) tags.add("system-mutation");
    if (target.tags.has("credential")) tags.add("credential-mutation");
    if (target.tags.has("shell-config")) tags.add("shell-config-mutation");
    if (target.tags.has("outside-project")) tags.add("outside-project-mutation");
    reasons.push(...target.reasons.map((reason) => `redirection ${reason}`));
  }
  return {
    tags: Array.from(tags),
    targets: [...(commandAnalysis?.targets ?? []), ...redirectTargets.map((target) => ({
      input: target.input,
      path: target.path,
      tags: Array.from(target.tags).sort(),
      reasons: target.reasons
    }))],
    reason: unique(reasons).join("; ")
  };
}
