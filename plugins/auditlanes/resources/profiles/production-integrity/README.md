# Production Integrity Profile

Experimental AuditLanes profile metadata for launch integrity reviews.

This profile is intentionally not marked runnable yet. The stable security
profile uses security-shaped sidecar and reducer fields. Production-integrity
requires generic finding fields such as `control_objective`,
`trigger_condition`, `missing_control`, `detectability`, `recoverability`, and
`launch_gate_effect` before it should be set to `implemented: true`.

The profile focuses on whether ordinary users, retries, jobs, deploys, imports,
migrations, or partial failures can create wrong durable state, wrong external
commitments, unrecoverable data loss, or unjustified launch confidence.

Stable lanes:

- `state-model-integrity`
- `workflow-atomicity`
- `derived-output-reconciliation`
- `lifecycle-recovery`
- `runtime-cutover-controls`
- `assurance-evidence`

Default strategy: `production-gate`.
