# AuditLanes Profile Loading

AuditLanes separates the small core workflow from profile-specific lane
definitions.

## Resolution

Profile files live under:

```text
resources/profiles/<profile-id>/
```

Each profile has:

```text
profile.yaml
lanes.yaml
strategies/
overlays/
cross-lane-triggers.yaml
```

`profile.yaml` declares whether the profile is implemented. `lanes.yaml`
declares lane IDs and optional specialist work items. Stable profiles may also
declare `strategy_source`, `overlay_source`, and `report_sidecar_schema`;
validators load those catalogs and the profile-specific report contract from
the selected profile root. Profiles may declare `cross_lane_trigger_source` for
reducer-owned follow-up routing.

`strategy: auto` is a calibration-time request. It must resolve into a concrete
strategy, overlays, coverage mode, suggested checks, and agent-discretion flags
recorded in `state/relevance-plan.yaml` before audit work starts. Suggested
checks frame the review; they do not bound reviewer judgment.

## Validation

Executable validators must derive allowed lane/family values from the selected
profile instead of hardcoding them in sidecar schemas.

For the selected profile:

- `family` may be a lane ID or specialist ID.
- `owner_family` must be a lane ID.
- `strategy` must exist in the selected profile's strategy catalog.
- every `overlays[]` entry must exist in the selected profile's overlay catalog.
- sidecar `mode` must be allowed by the selected strategy when the strategy
  declares `allowed_modes`.
- report sidecars are validated against the selected profile's
  `report_sidecar_schema`, defaulting to the security-compatible v3 schema.
- cross-lane trigger `notify` families must be normal lane IDs.
- profile feedback `family` must be a lane ID.
- batch manifest work item families must be lane IDs or specialist IDs.

## Stability

AuditLanes ships the `security` profile as the stable runnable profile.
`production-integrity` is runnable but experimental. `architecture` exists as
metadata only and must not be treated as a production-ready audit mode unless
its `profile.yaml` explicitly sets `implemented: true`.

`--allow-experimental` is limited to profile-loading and catalog compatibility
checks. It does not make metadata-only profile sidecars valid against a runnable
profile's report schema or reducer semantics.
