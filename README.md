# Agent Trust

[![CI](https://github.com/ansonlotiniat/agent-trust/actions/workflows/ci.yml/badge.svg)](https://github.com/ansonlotiniat/agent-trust/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Node.js >=20](https://img.shields.io/badge/node-%3E%3D20-339933.svg)](package.json)

Agent Trust is a circuit breaker for AI coding agents: keep dangerous mode on, but stop catastrophic deletes, credential access, system mutation, and secret exfiltration.

Agent Trust lets you keep the productivity of commands such as:

```bash
claude --dangerously-skip-permissions
codex --dangerously-bypass-approvals-and-sandbox
```

without turning every action into an approval prompt. It keeps normal project-local work fast, then brakes when a command crosses into filesystem-wide destruction, credential paths, shell startup files, system locations, disk operations or secret exfiltration.

## Why this exists

Vibe coding tools are moving from autocomplete to autonomous tool use. The risky part is not only the model response. It is the moment an agent can read local credentials, call arbitrary MCP tools, run shell commands, contact unknown hosts, or mutate a repository without an audit trail.

Agent Trust is designed as a local circuit breaker for that boundary.

## Install

Install from GitHub until the npm package is published:

```bash
npm install -g github:ansonlotiniat/agent-trust
agent-trust --help
```

For local development:

```bash
git clone https://github.com/ansonlotiniat/agent-trust.git
cd agent-trust
npm ci
npm link
npm run check
```

The runtime CLI is plain ESM JavaScript with no production dependencies. `npm run check` verifies the runtime files and runs the test suite.

Then initialize a policy in a project:

```bash
agent-trust init
agent-trust validate
agent-trust doctor
```

## Run a dangerous agent safely

```bash
agent-trust run -- claude --dangerously-skip-permissions
agent-trust run -- codex --dangerously-bypass-approvals-and-sandbox
agent-trust run -- cursor-agent --force
```

Generate a shell alias:

```bash
agent-trust wrap claude --dangerous
# alias claude_safe="agent-trust run -- claude --dangerously-skip-permissions"
```

What happens by default:

- the wrapped agent keeps dangerous-mode speed and normal environment access;
- a PATH shim intercepts high-impact child commands such as `rm`, `chmod`, `sudo`, `dd`, `bash` and `zsh`;
- a semantic analyzer classifies command intent and target scope instead of only matching strings;
- `rm -rf dist` is allowed, while `rm -rf /`, `rm -rf ~`, writes to `~/.ssh`, edits to `~/.zshrc`, and mutations under `/etc` brake;
- every decision and process exit is written to `.agent-trust/audit/*.jsonl`;
- audit logs are hash-chained so tampering is detectable.

Optional strict controls can enable environment scrubbing and OS sandboxing through policy.

## Semantic, not keyword-only

Agent Trust does not treat every `rm` as suspicious. It classifies command intent and target scope:

```bash
agent-trust decide -- rm -rf dist
# allow

agent-trust decide -- rm -rf /
# deny

agent-trust decide -- cat ~/.ssh/id_rsa
# ask
```

The current model and known limitations are documented in [docs/semantic-analysis.md](docs/semantic-analysis.md).

## MCP tool-call proxy

Wrap any stdio MCP server:

```bash
agent-trust mcp -- node ./server.js
```

The proxy passes normal JSON-RPC messages through, but intercepts `tools/call` and applies policy/secret scanning to the tool name and arguments before forwarding.

## Secret scan

```bash
agent-trust scan .
agent-trust scan . --fail-on medium
```

Built-in detectors cover common AI/API keys, GitHub tokens, AWS keys, private keys, Slack tokens, JWT-like tokens and generic secret assignments.

## Dry-run policy decisions

Use `decide` to debug a policy before running an agent:

```bash
agent-trust decide --path ~/.ssh/id_rsa
agent-trust decide --host api.openai.com
agent-trust decide --tool read_file --content 'OPENAI_API_KEY=sk-proj-...'
agent-trust decide -- rm -rf dist
agent-trust decide -- rm -rf /
agent-trust decide --json --host api.openai.com
```

The command evaluates the same policy engine used by guarded process runs and MCP tool-call filtering, then prints the winning `allow`, `ask` or `deny` decision.

### JSON output examples

These examples were generated from the current CLI with the default policy so the fields match what `agent-trust decide --json` prints today.

Command decision with a deny:

```bash
agent-trust decide --json -- rm -rf /
```

```json
{
  "decision": "deny",
  "ruleId": "deny-catastrophic-actions",
  "reason": "Stop filesystem-wide destructive operations such as rm -rf / or rm -rf ~.",
  "checks": [
    {
      "decision": "allow",
      "reason": "no rule matched; defaultAction=allow",
      "subject": "command rm -rf /"
    },
    {
      "decision": "deny",
      "ruleId": "deny-catastrophic-actions",
      "reason": "Stop filesystem-wide destructive operations such as rm -rf / or rm -rf ~.",
      "subject": "analysis catastrophic,destructive,forceful,outside-project,outside-project-mutation,recursive,root,write"
    }
  ],
  "analyses": [
    {
      "kind": "command-analysis",
      "command": "rm",
      "args": [
        "-rf",
        "/"
      ],
      "tags": [
        "catastrophic",
        "destructive",
        "forceful",
        "outside-project",
        "outside-project-mutation",
        "recursive",
        "root",
        "write"
      ],
      "targets": [
        {
          "input": "/",
          "path": "/",
          "tags": [
            "catastrophic",
            "outside-project",
            "root"
          ],
          "reasons": [
            "targets filesystem root"
          ]
        }
      ],
      "reason": "targets filesystem root; recursive forced delete targets filesystem root; write operation targets paths outside the project"
    }
  ],
  "findings": []
}
```

Path decision with an ask:

```bash
agent-trust decide --json --path /etc/hosts
```

```json
{
  "decision": "ask",
  "ruleId": "ask-system-path",
  "reason": "Brake before touching system paths.",
  "checks": [
    {
      "decision": "ask",
      "ruleId": "ask-system-path",
      "reason": "Brake before touching system paths.",
      "subject": "path /etc/hosts"
    }
  ],
  "analyses": [
    {
      "kind": "path-analysis",
      "input": "/etc/hosts",
      "path": "/etc/hosts",
      "tags": [
        "outside-project",
        "system"
      ],
      "reason": "targets a system path"
    }
  ],
  "findings": []
}
```

Host decision with an allow:

```bash
agent-trust decide --json --host api.openai.com
```

```json
{
  "decision": "allow",
  "ruleId": "network-allowed-host",
  "reason": "network host api.openai.com is in allowedHosts",
  "checks": [
    {
      "decision": "allow",
      "ruleId": "network-allowed-host",
      "reason": "network host api.openai.com is in allowedHosts",
      "subject": "network api.openai.com"
    }
  ],
  "analyses": [],
  "findings": []
}
```

Tool decision with an allow:

```bash
agent-trust decide --json --tool read_file
```

```json
{
  "decision": "allow",
  "reason": "no rule matched; defaultAction=allow",
  "checks": [
    {
      "decision": "allow",
      "reason": "no rule matched; defaultAction=allow",
      "subject": "mcp tool read_file"
    }
  ],
  "analyses": [],
  "findings": []
}
```

Content decision with an allow:

```bash
agent-trust decide --json --content 'release notes only; no credentials here'
```

```json
{
  "decision": "allow",
  "reason": "no rule matched; defaultAction=allow",
  "checks": [
    {
      "decision": "allow",
      "reason": "no rule matched; defaultAction=allow",
      "subject": "content risk=none"
    }
  ],
  "analyses": [],
  "findings": []
}
```

## Audit verification and evidence export

```bash
agent-trust audit
agent-trust audit --export .agent-trust/evidence.json
```

The evidence bundle maps local controls to OWASP LLM Top 10 2025, NIST AI RMF and EU AI Act style evidence categories.

## Policy

The generated policy lives at `.agent-trust/policy.json`.

```json
{
  "defaultAction": "allow",
  "sandbox": {
    "enabled": false,
    "mode": "none"
  },
  "rules": [
    {
      "id": "deny-catastrophic-actions",
      "action": "deny",
      "when": {
        "analysisTag": ["catastrophic"]
      }
    },
    {
      "id": "ask-system-mutation",
      "action": "ask",
      "when": {
        "analysisTag": ["system-mutation"]
      }
    }
  ]
}
```

Decisions are `allow`, `ask` or `deny`.

Validate policy files locally or in CI:

```bash
agent-trust validate
agent-trust validate --config examples/policy.strict.json
```

## Current platform behavior

Default mode:

- preserves dangerous-mode workflow speed;
- keeps sensitive environment variables available unless `secrets.scrubEnv` is enabled;
- leaves OS sandboxing disabled unless policy enables it;
- uses semantic command analysis and PATH shims as the primary braking layer.

Strict mode:

- can enable macOS `sandbox-exec`;
- can enable Linux `bwrap` or `firejail`;
- can enable sensitive environment variable scrubbing;
- can block network by default through proxy-aware tooling.

## Example

```bash
agent-trust init
agent-trust decide -- rm -rf dist
agent-trust decide -- rm -rf /
agent-trust audit
```

The first decision is allowed; the second is denied before it can execute.

## Project status

This repository is intended to become a production-grade terminal tool for AI agent trust. The first complete CLI includes:

- project policy initialization;
- guarded process runner;
- semantic command analyzer;
- PATH shim for high-impact child commands;
- MCP stdio proxy;
- secret scanner;
- policy validator and dry-run decision explainer;
- optional OS sandbox backend selection;
- optional environment variable scrubbing;
- hash-chained audit logs;
- evidence bundle export;
- doctor checks;
- tests for semantic fuse decisions, scanning, audit integrity, optional network proxy startup and CLI smoke behavior.

See [ROADMAP.md](ROADMAP.md), [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/launch-kit.md](docs/launch-kit.md).
