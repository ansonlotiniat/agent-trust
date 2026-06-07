# Demo Script

Use this flow for a 30 second GIF, terminal recording, or launch post.

## Setup

```bash
npm install -g github:ansonlotiniat/agent-trust
mkdir agent-trust-demo
cd agent-trust-demo
agent-trust init
mkdir dist
```

## Recording

```bash
agent-trust decide -- rm -rf dist
agent-trust decide -- rm -rf /
agent-trust decide -- cat ~/.ssh/id_rsa
agent-trust decide -- bash -c 'echo x > ~/.zshrc'
```

Expected story:

- project-local cleanup is allowed;
- catastrophic root delete is denied;
- credential access pauses;
- shell startup mutation pauses.

## Full Wrapper Demo

```bash
agent-trust run -- claude --dangerously-skip-permissions
agent-trust run -- codex --dangerously-bypass-approvals-and-sandbox
```

Inside a wrapped agent, the PATH shim inspects high-impact child commands before execution.

## One-Sentence Voiceover

Agent Trust lets you keep AI coding agents in dangerous mode, but brakes before catastrophic deletes, credential access, system mutation, and secret exfiltration.
