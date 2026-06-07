# Security Policy

Agent Trust is a developer-side circuit breaker. It is designed to reduce the blast radius of AI coding agents, not to provide kernel-level containment or a guarantee that untrusted code is safe.

## Supported Versions

Security fixes target the latest release.

## Reporting a Vulnerability

Please use GitHub private vulnerability reporting:

https://github.com/ansonlotiniat/agent-trust/security/advisories/new

Include:

- version or commit;
- OS and shell;
- exact command or MCP payload;
- expected decision and observed decision;
- whether the issue allows catastrophic delete, credential access, system mutation, shell startup mutation, secret exfiltration, audit tampering, or policy bypass.

Please do not include live secrets. Redact tokens and credentials before submitting.

## Security Boundaries

Agent Trust currently focuses on:

- semantic command analysis for high-impact shell operations;
- PATH shims for wrapped agents' child commands;
- policy checks for commands, paths, hosts, MCP tool calls, and content risk;
- secret scanning;
- optional OS sandbox backends;
- hash-chained audit logs.

It does not claim complete containment against hostile local code, kernel escape, all shell language constructs, or tools that bypass the wrapped process environment.
