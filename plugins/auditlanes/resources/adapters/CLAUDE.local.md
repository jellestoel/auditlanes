@AGENTS.override.md

## Claude Code Local Audit

For local AuditLanes/security-audit tasks, prefer the installed trusted
AuditLanes plugin protocol before reading application evidence. Use repo-local
`auditlanes/` control files only when the operator explicitly requested
repo-local scaffolding or provenance is verified.

Prefer the `/auditlanes` skill when available.

For AuditLanes scans, use native agent-team mode whenever Claude Code was
started with `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1`. If native teams are
unavailable, record the reason and fall back to subagent lane execution when
supported; use single-session only when subagents are unavailable or explicitly
requested.

Use permission-friendly static inspection commands: start Claude in the target
root, use repo-relative paths, do not prefix commands with `cd <target-root> &&`,
do not suppress `rg`/`find` stderr with `2>/dev/null`, and avoid pipelines or
`head` for routine discovery.
