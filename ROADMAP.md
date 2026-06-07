# Roadmap

Agent Trust should become the default local circuit breaker for AI coding agents that run with broad terminal permission.

## v0.1

- Terminal wrapper for dangerous-mode coding agents.
- Default-allow policy posture with brakes for catastrophic actions.
- Semantic command analyzer and PATH shims.
- MCP stdio proxy.
- Secret scanner.
- Hash-chained audit logs.
- Optional sandbox and environment scrubbing controls.

## v0.2

- Shell parser improvements for pipes, redirection, subshells, command substitution, and nested `sh -c` cases.
- Filesystem-aware scope resolution with symlink and realpath handling.
- More command semantics: `find -delete`, `git clean`, `rsync --delete`, `xargs rm`, package manager lifecycle scripts.
- More structured `decide --json` explanations with factors, target scopes, and confidence.
- Better install path after npm release.

## v0.3

- Policy test fixtures for teams.
- More MCP policy examples.
- Signed or externally anchored audit evidence.
- Better cross-platform sandbox compatibility.
- Integration guides for Claude Code, Codex, Cursor, and common MCP servers.

## Non-Goals

- Become an enterprise governance dashboard.
- Ask approval for every destructive command.
- Replace IAM, secrets management, repository scanning, or endpoint protection.
- Claim perfect safety against arbitrary hostile code.
