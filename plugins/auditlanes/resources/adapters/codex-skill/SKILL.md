---
name: auditlanes
description: Use when the user asks for an AuditLanes run, codebase audit, full security scan, vulnerability review, or audit report for this repository.
---

# AuditLanes

Use this skill only when the operator explicitly invokes AuditLanes or asks for
a codebase audit, full security scan, vulnerability review, or audit report.

For Codex, default such requests to the complete pre-fix `security` protocol.
Do not pause for profile or strategy choices unless the operator explicitly asks
for a preview, comparison, or non-security profile. Run advisor output as
calibration input, then continue through `validate_run.py --complete`.

Prefer the installed trusted AuditLanes protocol. Use repo-local `auditlanes/`
control files only when the operator explicitly requested repo-local scaffolding
or provenance is verified.

Generated outputs go under `auditlanes/out/`.
