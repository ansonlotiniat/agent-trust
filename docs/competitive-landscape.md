# Competitive Landscape

This project is not based on the claim that nobody has noticed AI agent security. Adjacent projects exist.

Observed categories and current examples:

- MCP firewall/proxy tools that focus on MCP server calls, such as [mcp-firewall](https://github.com/ressl/mcp-firewall), [mcpfw](https://mcpfw.dev/), [Agent Wall](https://agent-wall.github.io/agent-wall/) and [Pipelock](https://github.com/luckyPipewrench/pipelock).
- AI gateway/guardrail tools that focus on model traffic and policy at API boundaries.
- Agent workstations or vendor CLIs that bundle a managed environment or permission system, such as [Devin for Terminal permissions](https://cli.devin.ai/docs/reference/permissions).
- Static scanners for prompts, skills, MCP configs, repositories or dependency graphs.
- Broader stacks that combine multiple agent security and observability tools, such as [AgentOpsSec](https://agentopssec.com/).
- Enterprise governance platforms.

The gap Agent Trust targets:

- terminal-first UX for users who actually run dangerous AI coding CLIs;
- direct process wrapping rather than only model gateway integration;
- local-first operation without requiring a SaaS control plane;
- semantic command fuse plus PATH shims, policy, secret scanning and audit in one tool;
- MCP stdio proxy as a feature, not the whole product;
- policy validation and dry-run decisions so teams can debug controls before a live run;
- evidence export for teams that need to trust and review agent actions.

The initial product should be judged by whether a developer can replace:

```bash
claude --dangerously-skip-permissions
```

with:

```bash
agent-trust run -- claude --dangerously-skip-permissions
```

and get a meaningful safety boundary without changing their workflow.
