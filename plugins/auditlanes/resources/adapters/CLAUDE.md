@AGENTS.md

## Claude Code

For AuditLanes/security-audit tasks, prefer the installed trusted AuditLanes
plugin protocol before reading application evidence. Use repo-local
`auditlanes/` control files only when the operator explicitly requested
repo-local scaffolding or provenance is verified.

Prefer the `/auditlanes` skill when available.

For large scans, agent-team mode is preferred when Claude Code was started with
`CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1` and the operator requests it.

Use permission-friendly static inspection commands: start Claude in the target
root, use repo-relative paths, do not prefix commands with `cd <target-root> &&`,
do not suppress `rg`/`find` stderr with `2>/dev/null`, and avoid pipelines or
`head` for routine discovery.
