# Agent integration wrappers

The snippets below are practical examples for running agent CLIs through
`agent-trust`. They are examples, not endorsements for any specific vendor.

## Claude Code

```bash
agent-trust wrap claude --dangerous
# alias claude_safe="agent-trust run -- claude --dangerously-skip-permissions"

agent-trust run -- claude --dangerously-skip-permissions
```

## Codex

```bash
agent-trust wrap codex --dangerous
# alias codex_safe="agent-trust run -- codex --dangerously-bypass-approvals-and-sandbox"

agent-trust run -- codex --dangerously-bypass-approvals-and-sandbox
```

## Cursor-style / force-mode agents

```bash
agent-trust wrap cursor-agent --dangerous
# alias agent_safe="agent-trust run -- cursor-agent --force"

agent-trust run -- cursor-agent --force
```

## `agent-trust wrap` alias pattern

If you prefer short commands, use a small helper alias:

```bash
agent_wrap() {
  local cli=$1
  shift
  agent-trust run -- "$cli" "$@"
}

alias claude_safe='agent_wrap claude --dangerously-skip-permissions'
alias codex_safe='agent_wrap codex --dangerously-bypass-approvals-and-sandbox'
```

For production use, keep your policy strict where appropriate and
run `agent-trust validate` after editing `.agent-trust/policy.json`.
