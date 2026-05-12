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
```

`profile.yaml` declares whether the profile is implemented. `lanes.yaml`
declares lane IDs and optional specialist work items.

## Validation

Executable validators must derive allowed lane/family values from the selected
profile instead of hardcoding them in sidecar schemas.

For the selected profile:

- `family` may be a lane ID or specialist ID.
- `owner_family` must be a lane ID.
- profile feedback `family` must be a lane ID.
- batch manifest work item families must be lane IDs or specialist IDs.

## Stability

AuditLanes v0.4.7 ships the `security` profile as the only stable runnable
profile. Other profiles may exist as experimental metadata, but must not be
treated as production-ready audit modes unless their `profile.yaml` explicitly
sets `implemented: true`.

`--allow-experimental` is limited to profile-loading and catalog compatibility
checks. It does not make metadata-only profile sidecars valid against the
security report schema or reducer semantics.
