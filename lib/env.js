

const sensitiveEnvRegex = /(?:TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE|KEY|CREDENTIAL|COOKIE|SESSION|AUTH|AWS_|GOOGLE_|GITHUB_|OPENAI_|ANTHROPIC_)/i;






export function buildChildEnv(config, passEnv = [], proxyUrl, options = {}) {
  const allow = new Set([
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "TERM",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "PWD",
    "EDITOR",
    "VISUAL",
    ...passEnv
  ]);
  const env = {};
  const scrubbed = [];
  for (const [key, value] of Object.entries(process.env)) {
    if (config.secrets.scrubEnv && !allow.has(key) && sensitiveEnvRegex.test(key)) {
      scrubbed.push(key);
      continue;
    }
    env[key] = value;
  }

  if (config.network.proxyEnv) {
    env.AGENT_TRUST_NETWORK_POLICY = config.network.blockByDefault ? "block-by-default" : "observe";
    env.AGENT_TRUST_ALLOWED_HOSTS = config.network.allowedHosts.join(",");
    if (proxyUrl) {
      env.HTTP_PROXY = proxyUrl;
      env.HTTPS_PROXY = proxyUrl;
      env.ALL_PROXY = proxyUrl;
      env.http_proxy = proxyUrl;
      env.https_proxy = proxyUrl;
      env.all_proxy = proxyUrl;
      env.NO_PROXY = "localhost,127.0.0.1,::1";
      env.no_proxy = "localhost,127.0.0.1,::1";
    }
  }
  env.AGENT_TRUST_ACTIVE = "1";
  env.AGENT_TRUST_AUDIT_DIR = config.auditDir;
  if (options.shimDir) {
    env.AGENT_TRUST_SHIM_DIR = options.shimDir;
    env.AGENT_TRUST_AUDIT_FILE = options.auditFile;
    env.AGENT_TRUST_ASSUME = options.assume ?? "";
    env.AGENT_TRUST_ORIGINAL_PATH = env.PATH ?? process.env.PATH ?? "";
    env.PATH = `${options.shimDir}:${env.AGENT_TRUST_ORIGINAL_PATH}`;
  }
  return { env, scrubbed };
}

//# sourceMappingURL=env.js.map
