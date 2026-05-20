# Workflow Evidence Profile

`workflow-evidence` is an experimental AuditLanes profile for building an agent-readable workflow evidence atlas.

It is not a security scan and it is not a browser-test runner. Its purpose is to combine:

- static topology
- scenario rules
- read-only usage/completion observations
- task/integration side-effect evidence
- fixture readiness
- tiered release-risk test recommendations

The profile preserves these match levels:

```text
candidate
attempted
completed
completed_with_side_effects
pain_signal
```

Static-only lanes must not claim `completed` or `completed_with_side_effects`.

The primary outputs are atlas state rows:

```text
state/workflow-atlas-entities.jsonl
state/workflow-atlas-edges.jsonl
state/workflow-atlas-evidence.jsonl
state/scenario-observations.jsonl
state/workflow-score-matrix.jsonl
```

Use `static-atlas` first. Use `read-only-enrichment` only after explicit approval for safe data/log reads.
