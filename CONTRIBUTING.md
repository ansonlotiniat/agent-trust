# Contributing

Agent Trust is a local safety boundary for developers who keep AI coding agents in dangerous mode. Contributions are welcome when they preserve that product shape: fast by default, explicit brakes for high-impact actions, and clear auditability.

## Development

```bash
npm ci
npm run check
```

The runtime is plain ESM JavaScript and currently has no production dependencies.

## Before opening a PR

- Add or update tests in `scripts/test.mjs` for policy, analyzer, scanner, audit, or CLI behavior.
- Run `npm run check`.
- Run `node lib/cli.js scan . --fail-on high`.
- Keep fixtures from looking like real credentials. Build token-shaped strings at runtime when testing detectors.
- Document user-visible behavior changes in `README.md`, `docs/security-model.md`, or `docs/semantic-analysis.md`.

## Analyzer contributions

Command analysis is not a command-name blacklist. A useful analyzer change should identify:

- command intent, such as destructive, recursive, forceful, write, permission change, privilege escalation, or disk operation;
- target scope, such as project-local, outside-project, home, credential path, shell startup file, system path, or root;
- the resulting brake, such as catastrophic action, credential access, credential mutation, system mutation, or shell config mutation.

Good PRs include examples that should remain allowed, examples that should brake, and examples that should be denied.

## Issue quality

For command classification issues, include:

- exact command;
- current `agent-trust decide -- ...` output;
- expected `allow`, `ask`, or `deny`;
- cwd and relevant symlinks if path resolution matters;
- OS and shell.

## Maintainer bias

The project should avoid becoming an approval-heavy sandbox. The default posture is still `allow`; the tool should brake only when intent and target scope indicate high-impact risk.
