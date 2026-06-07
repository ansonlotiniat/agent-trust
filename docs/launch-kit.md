# Launch Kit

Agent Trust's launch message should stay narrow:

> Keep AI coding agents in dangerous mode, but stop catastrophic deletes, credential access, system mutation, and secret exfiltration.

Avoid claiming perfect safety. The credible claim is a practical local circuit breaker for developers who already use dangerous-mode AI coding CLIs.

## Links

- GitHub: https://github.com/ansonlotiniat/agent-trust
- Install before npm publish: `npm install -g github:ansonlotiniat/agent-trust`
- Demo script: `docs/demo-script.md`
- Security model: `docs/security-model.md`
- Analyzer details: `docs/semantic-analysis.md`

## Hacker News

Title:

```text
Show HN: Agent Trust - a circuit breaker for AI coding agents in dangerous mode
```

Post:

```text
I built Agent Trust because I keep AI coding agents in dangerous mode, but I do not want them touching `/`, `~/.ssh`, shell startup files, or `/etc`.

The goal is not to turn every command into an approval prompt. `rm -rf dist` should stay fast. `rm -rf /`, `cat ~/.ssh/id_rsa`, and edits to `~/.zshrc` should brake.

It wraps tools like Claude Code, Codex, and Cursor-style agents, adds PATH shims for high-impact child commands, applies policy to command intent + target scope, scans for secrets, proxies stdio MCP tool calls, and writes hash-chained audit logs.

The command analyzer is heuristic today, not a full shell AST. I documented the current model and limitations because I want feedback from people who actually run these agents daily.

GitHub: https://github.com/ansonlotiniat/agent-trust
```

## X / LinkedIn

```text
I keep AI coding agents in dangerous mode.

But I do not want an agent touching `/`, `~/.ssh`, `/etc`, or my shell startup files.

So I built Agent Trust: a local circuit breaker for AI coding agents.

`rm -rf dist` -> allowed
`rm -rf /` -> denied
`cat ~/.ssh/id_rsa` -> brakes
`echo x > ~/.zshrc` -> brakes

It wraps Claude Code / Codex-style CLIs, intercepts high-impact child commands with PATH shims, applies policy to command intent + target scope, scans for secrets, and writes hash-chained audit logs.

GitHub: https://github.com/ansonlotiniat/agent-trust
```

## Product Hunt

Name:

```text
Agent Trust
```

Tagline:

```text
Keep AI agents fast. Stop catastrophic commands.
```

Description:

```text
Agent Trust is a local circuit breaker for AI coding agents running in dangerous mode. It keeps normal project-local work fast, then brakes before catastrophic deletes, credential access, shell startup edits, system mutation, MCP tool-call risk, and secret exfiltration.
```

First comment:

```text
I built Agent Trust for a specific workflow: developers who already use AI coding agents with broad terminal permission.

I do not want to disable dangerous mode completely. It is often the fastest way to work. But I do want a hard brake before commands cross into `/`, home credential stores, shell startup files, or system locations.

The current version includes a default-allow policy, semantic command analysis, PATH shims for high-impact child commands, an MCP stdio proxy, secret scanning, optional sandboxing, and hash-chained audit logs.

The analyzer is intentionally documented with limitations. I would especially like feedback on real command cases that should be classified better.

GitHub: https://github.com/ansonlotiniat/agent-trust
```

## Reddit

Use only in subreddits where self-promotion or project feedback posts are allowed.

```text
I built a local circuit breaker for AI coding agents running in dangerous mode.

The design goal is default allow, not approval fatigue:

- `rm -rf dist` should be allowed
- `rm -rf /` should be denied
- reading `~/.ssh/id_rsa` should brake
- editing `.zshrc` should brake

It wraps Claude/Codex-style CLIs, adds PATH shims for high-impact child commands, applies policy to command intent + target scope, scans for secrets, proxies stdio MCP calls, and writes audit logs.

I am looking for feedback from people who use AI coding agents daily, especially command cases the analyzer should classify better.

GitHub: https://github.com/ansonlotiniat/agent-trust
```

## Newsletter Pitch

Subject:

```text
Open source: Agent Trust, a circuit breaker for dangerous-mode AI coding agents
```

Pitch:

```text
Agent Trust is an open-source terminal wrapper for AI coding agents. It lets developers keep tools like Claude Code and Codex in dangerous mode while braking before catastrophic deletes, credential access, system mutation, shell startup edits, MCP tool-call risk, and secret exfiltration.

The interesting design choice is default allow: project-local destructive work remains fast, while command intent and target scope determine when to ask or deny.

Repo: https://github.com/ansonlotiniat/agent-trust
```

## Maintainer Checklist

- [ ] Publish npm package after login: `npm publish --access public`
- [ ] Record 30 second terminal demo using `docs/demo-script.md`
- [ ] Add demo GIF to `assets/` and README
- [ ] Submit Show HN
- [ ] Reply to every serious HN comment for 24 hours
- [ ] Convert good feedback into issues
- [ ] Release `v0.1.1` within one week with launch feedback fixes
- [ ] Submit to Product Hunt after demo GIF and npm publish
- [ ] Submit targeted PRs to relevant awesome lists
