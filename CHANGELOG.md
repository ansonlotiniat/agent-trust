# Changelog

## v0.1.0

Initial public release.

- Added `agent-trust run` for wrapping AI coding agents.
- Added default-allow policy with brakes for catastrophic deletes, credential paths, system mutation, shell startup edits, disk operations, and privilege escalation.
- Added semantic command analysis and PATH shims for high-impact child commands.
- Added MCP stdio proxy for `tools/call` policy checks.
- Added secret scanning and redacted audit output.
- Added hash-chained audit logs and evidence export.
- Added optional macOS and Linux sandbox backend selection.
- Added strict policy example.
- Added CLI tests and runtime verification.
