# AuditLanes Family Report Template

## Header

- `run_id`:
- `schema_version`:
- `sidecar_id`:
- `generated_at`:
- `batch_id`:
- `family`:
- `mode`:
- `profile`:
- `strategy`:
- `overlays`:
- `baseline_commit`:
- `reviewed_artifacts`:

## Mission

State the exact question this family was asked to answer in this batch.

The family run must emit:

- `${RUN_DIR}/reports/${BATCH_ID}/${FAMILY}/report.md` using this template
- `${RUN_DIR}/reports/${BATCH_ID}/${FAMILY}/report.json` using `${PROTOCOL_ROOT}/report-sidecar-schema.yaml`

`report.json` is the reducer input and source of truth. `report.md` is the
required narrative companion, not an ad-hoc summary file. Rules that prohibit
optional summary files must not block either required output. If the host blocks
artifact writes, return both artifacts inline so the lead can persist them.

Do not write to `reports/${FAMILY}/report.*`; that is a legacy layout accepted
only by lenient recovery tooling.

## Scope

- `seed_paths_used`:
- `project_security_profile`:
- `family_scope_map`:
- `shared_context_inputs`:
- `reviewed_files_routes_helpers`:
- `coverage_units_touched`:
- `coverage_units_not_touched`:
- `patterns_searched`:
- `intentionally_excluded`: array of objects, never bare strings:
  `{"path": "repo/relative/path", "reason": "why excluded", "scope_source": null}`.
  Use `[]` when nothing was intentionally excluded.

For `profile_version`, use `null` unless the lead provides the exact installed
AuditLanes package version. Do not use profile status values such as
`experimental`.

## Confirmed Findings

For each finding:

- `finding_id`:
- `root_cause_id`:
- `provisional_finding_id`:
- `dedupe_key`:
- `owner_family`:
- `status`:
- `severity`:
- `confidence`:
- `summary`:
- `entrypoint`:
- `security_invariant`:
- `missing_guard`:
- `attacker_precondition`:
- `impact_boundary`:
- `files`:
- `evidence_refs`:
- `report_refs`:
- `lead_source_refs`:
- `severity_rationale`:
- `clone_of`:
- `related_findings`:
- `why_confirmed`:
- `introduced_after_batch_01`:

`finding_id` and `root_cause_id` may be null in family sidecars. The reducer
owns final stable IDs.

Use `report-sidecar-template.json` as the fill-in JSON sidecar shape. Validate
the sidecar with `validate_run.py <run-dir> --sidecar reports/<batch-id>/<family>/report.json`
before marking the lane complete.

`dedupe_key` must be a verbatim mirror of these parent finding fields:

- `owner_family`
- `security_invariant`
- `missing_guard`
- `entrypoint`
- `impact_boundary`

Use structured evidence refs in the JSON sidecar:

```json
{
  "path": "src/api/example.py",
  "line_start": 120,
  "line_end": 147,
  "symbol": "ExampleView.post",
  "evidence_type": "missing-authz-check",
  "snippet_hash": "sha256:...",
  "rationale": "The handler resolves a caller-supplied object without checking ownership."
}
```

## Candidate Findings

For each candidate:

- `candidate_id`:
- `candidate_dedupe_key`:
- `proposed_owner_family`:
- `severity`:
- `confidence`:
- `summary`:
- `entrypoint`:
- `impact_boundary`:
- `suspected_missing_guard`:
- `blocker_to_confirmation`:
- `files`:
- `evidence_refs`:
- `lead_source_refs`:

`candidate_dedupe_key` must be a verbatim mirror of these parent candidate
fields:

- `proposed_owner_family`
- `summary`
- `files`
- `suspected_missing_guard`
- `impact_boundary`

## Incidental Leads

Use this section for obvious serious issues noticed outside the lane's primary
mission. The reducer owns final triage and ownership.

- `lead_id`:
- `noticed_by_family`:
- `proposed_owner_family`:
- `summary`:
- `confidence`:
- `severity_hint`:
- `why_noticed`:
- `blocker_to_confirmation`:
- `files`:
- `evidence_refs`:

## Security Smells

Use this section for weak but interesting signals that should not yet become
candidate findings.

- `smell_id`:
- `category`:
- `path`:
- `line_start`:
- `description`:
- `recommended_owner`:
- `status`:

## Run-Local Checks

Use this section when repo evidence reveals a security question that is not
covered well by the relevance plan or bundled risk packs. These checks are
run-scoped; they do not mutate the global catalog.

- `check_id`: use `local.*`
- `reason`:
- `trigger_evidence_refs`:
- `extends_checks`:
- `recommended_owner_family`:
- `scope_impact`:
- `regression_impact`:

## Rejected / Downranked Claims

For each rejected or downranked claim:

- `claim_id`:
- `reason`:
- `subsumed_by`:

## Clone Map

If clonehunt was in scope:

- `canonical_exemplar`:
- `repeated_pattern`:
- `widespread_pattern`:
- `estimated_clone_count`:
- `clone_locations`:
- `severity_shift`:

If the pattern is widespread, list at most 5 representative exemplars.

## Runtime Notes

If runtime-safe validation was in scope:

- `finding_id`:
- `runtime_status`:
- `request_posture`:
- `result`:

Use only these `runtime_status` values:

- `confirmed-at-runtime`
- `not-reproduced`
- `blocked-by-ingress-or-environment`
- `unsafe-to-validate-without-separate-approval`

## Chain Notes

If chain prep or exploit synthesis was in scope:

- `chain_candidate_id`:
- `component_findings`:
- `why_chain_matters`:

## Coverage Gaps

List units or source areas that still need review and why.

## Profile Feedback

If calibration missed or mis-scoped part of the project, report it here and in
`report.json`. Family agents must not silently update scope.

- `profile_gap_id`:
- `family`:
- `affected_families`:
- `observed_issue`:
- `suggested_change`:
- `evidence_refs`:
- `urgency`:

`family` is the reporting family. Use `affected_families` for cross-lane
feedback, for example when `platform-posture` observes a scope issue that should
change `integration-trust` or `data-surfaces` coverage.

## Proof Updates

Use proof levels `P0-lead`, `P1-candidate`, `P2-static-confirmed`,
`P3-reachability-confirmed`, `P4-runtime-confirmed`, or
`P5-regression-backed`.

- `subject_id`:
- `proof_level`:
- `evidence_summary`:
- `runtime_validation`:
- `regression_status`:
- `evidence_refs`:

## Regression Recommendations

For every confirmed finding, propose recurrence prevention when feasible.

- `finding_id`:
- `recommended_regression`:
- `test_name`:
- `guard_asserted`:
- `automation_status`:
- `owner_hint`:

## Next-Batch Recommendations

Flat bullets only. Focus on what the reducer should assign next.
