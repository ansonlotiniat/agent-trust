# Security Model

Agent Trust protects the boundary between an AI agent and local tools. It is designed as a circuit breaker: developers keep dangerous permission workflows fast, while catastrophic deletes, credential access, system mutation, shell startup edits and secret exfiltration are stopped or paused.

## Protected Assets

- Local credential stores such as `~/.ssh`, `~/.aws`, `~/.kube`, `~/.docker`, `.npmrc`, `.pypirc` and Git credential files.
- Local system files and shell startup files that can persistently change the developer environment.
- Sensitive environment variables containing tokens, passwords, private keys, cookies and cloud credentials when strict env scrubbing is enabled.
- Repository contents that may contain API keys, private keys or other secrets.
- Auditability of agent actions, policy decisions and process exits.

## Controls

- Semantic command analysis for high-impact shell commands and inline shell scripts.
- PATH shims that intercept child-agent calls to commands such as `rm`, `chmod`, `sudo`, `dd`, `bash`, `zsh`, `tee` and `sed`.
- Preflight policy evaluation for process commands, analyzed command tags, paths, MCP tool calls, content risk and network hosts.
- Optional environment scrubbing before launching the child process.
- Secret scanning for common AI/API keys, cloud credentials, private keys, Slack tokens, JWT-like values and generic secret assignments.
- Optional macOS `sandbox-exec` support, with compatibility and strict profiles.
- Optional Linux sandbox support through `bwrap` or `firejail` when installed.
- MCP stdio proxy for `tools/call` policy enforcement.
- HTTP/HTTPS proxy environment injection for network host audit and allowlist decisions.
- Hash-chained JSONL audit logs.

## Non-Goals

- It is not a kernel-level EDR.
- It does not make an untrusted model trustworthy.
- It does not guarantee containment on every operating system.
- It does not intercept direct network calls from tools that ignore proxy environment variables.
- It does not try to approve every project-local destructive action. `rm -rf dist` should remain fast.
- It does not replace cloud IAM, least-privilege API tokens or repository secret scanning.

## Recommended Usage

Use Agent Trust as a local execution boundary:

```bash
agent-trust init
agent-trust run -- claude --dangerously-skip-permissions
agent-trust audit
```

For policy debugging:

```bash
agent-trust decide -- rm -rf dist
agent-trust decide -- rm -rf /
agent-trust decide -- bash -c 'echo x > ~/.zshrc'
```

For stricter macOS runs:

```bash
agent-trust run --strict-sandbox -- claude --dangerously-skip-permissions
```

For team use, commit a reviewed policy template and keep `.agent-trust/audit/*.jsonl` out of source control.
