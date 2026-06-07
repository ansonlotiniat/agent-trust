import crypto from "node:crypto";
import path from "node:path";
import { mkdir, readFile, writeFile, appendFile } from "node:fs/promises";

import { redactFinding, redactSecrets } from "./secrets.js";

export class AuditLog {
  
   __init() {this.queue = Promise.resolve()}

  constructor(  config, sessionId = currentSessionId()) {;this.config = config;AuditLog.prototype.__init.call(this);
    this.filePath = path.join(config.auditDir, `${sessionId}.jsonl`);
  }

  get path() {
    return this.filePath;
  }

  async append(event) {
    const appendPromise = this.queue.then(() => this.appendNow(event));
    this.queue = appendPromise.catch(() => undefined);
    return appendPromise;
  }

   async appendNow(event) {
    await mkdir(path.dirname(this.filePath), { recursive: true });
    const prevHash = await this.lastHash();
    const withMeta = {
      id: crypto.randomUUID(),
      ts: new Date().toISOString(),
      ...sanitizeEvent(event, this.config),
      ...(prevHash ? { prevHash } : {})
    };
    const hash = hashEvent(withMeta);
    const finalEvent = { ...withMeta, hash };
    await appendFile(this.filePath, JSON.stringify(finalEvent) + "\n", "utf8");
    return finalEvent;
  }

  async verify() {
    try {
      const raw = await readFile(this.filePath, "utf8");
      let previous;
      let count = 0;
      for (const line of raw.split(/\n/)) {
        if (!line.trim()) continue;
        const parsed = JSON.parse(line) ;
        const { hash, ...withoutHash } = parsed;
        if (parsed.prevHash !== previous) {
          return { ok: false, events: count, error: `hash chain break at ${parsed.id}` };
        }
        const actual = hashEvent(withoutHash );
        if (actual !== hash) {
          return { ok: false, events: count, error: `invalid hash at ${parsed.id}` };
        }
        previous = hash;
        count++;
      }
      return { ok: true, events: count };
    } catch (error) {
      return { ok: false, events: 0, error: error instanceof Error ? error.message : String(error) };
    }
  }

   async lastHash() {
    try {
      const raw = await readFile(this.filePath, "utf8");
      const lines = raw.split(/\n/).filter(Boolean);
      if (!lines.length) return undefined;
      const last = JSON.parse(lines[lines.length - 1]) ;
      return last.hash;
    } catch (e) {
      return undefined;
    }
  }
}

export async function verifyAuditFile(filePath) {
  try {
    const raw = await readFile(filePath, "utf8");
    let previous;
    let count = 0;
    for (const line of raw.split(/\n/)) {
      if (!line.trim()) continue;
      const parsed = JSON.parse(line) ;
      const { hash, ...withoutHash } = parsed;
      if (parsed.prevHash !== previous) {
        return { ok: false, events: count, error: `hash chain break at event ${count + 1}` };
      }
      const actual = hashEvent(withoutHash );
      if (actual !== hash) {
        return { ok: false, events: count, error: `invalid hash at event ${count + 1}` };
      }
      previous = hash;
      count++;
    }
    return { ok: true, events: count };
  } catch (error) {
    return { ok: false, events: 0, error: error instanceof Error ? error.message : String(error) };
  }
}

export async function writeEvidenceBundle(config, auditFiles, outFile) {
  const audits = [];
  for (const file of auditFiles) {
    const verification = await verifyAuditFile(file);
    audits.push({ file, verification });
  }
  const bundle = {
    generatedAt: new Date().toISOString(),
    projectRoot: config.projectRoot,
    frameworkMappings: {
      "OWASP LLM Top 10 2025": [
        "Prompt Injection",
        "Sensitive Information Disclosure",
        "Supply Chain",
        "Excessive Agency"
      ],
      "NIST AI RMF": [
        "Govern",
        "Map",
        "Measure",
        "Manage"
      ],
      "EU AI Act": [
        "Transparency evidence",
        "Human oversight evidence",
        "Post-market monitoring evidence",
        "Robustness and cybersecurity evidence"
      ]
    },
    controls: {
      policyAsCode: true,
      localAuditLog: true,
      hashChainedAudit: true,
      secretRedaction: config.secrets.enabled,
      sandbox: config.sandbox.enabled
    },
    audits
  };
  await mkdir(path.dirname(outFile), { recursive: true });
  await writeFile(outFile, JSON.stringify(bundle, null, 2), "utf8");
}

function hashEvent(event) {
  return crypto.createHash("sha256").update(stableStringify(event)).digest("hex");
}

function stableStringify(value) {
  if (value === undefined) return "";
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const obj = value ;
  return `{${Object.keys(obj)
    .filter((key) => obj[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(obj[key])}`)
    .join(",")}}`;
}

function sanitizeEvent(event, config) {
  if (!config.secrets.redactAudit) return event;
  const copy = JSON.parse(JSON.stringify(event)) ;
  if (copy.command) copy.command = redactSecrets(copy.command, config);
  if (copy.args) copy.args = copy.args.map((arg) => redactSecrets(arg, config));
  if (copy.findings) copy.findings = copy.findings.map((finding) => redactFinding(finding, config));
  if (copy.subject) copy.subject = redactObject(copy.subject, config) ;
  if (copy.metadata) copy.metadata = redactObject(copy.metadata, config) ;
  return copy;
}

function redactObject(value, config) {
  if (typeof value === "string") return redactSecrets(value, config);
  if (Array.isArray(value)) return value.map((item) => redactObject(item, config));
  if (value && typeof value === "object") {
    const out = {};
    for (const [key, item] of Object.entries(value)) out[key] = redactObject(item, config);
    return out;
  }
  return value;
}

function currentSessionId() {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  return `${stamp}-${process.pid}`;
}

//# sourceMappingURL=audit.js.map
