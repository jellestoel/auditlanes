# AuditLanes Final Report Template

Use this template for `${RUN_DIR}/final/pre-fix-findings.md`,
`${RUN_DIR}/final/pre-fix-summary.md`, and post-fix addenda when applicable.

The reducer-owned inventories are the source of truth. Do not introduce final
report findings that are absent from `${RUN_DIR}/state/finding-inventory.jsonl`.

## Methodology

Describe the AuditLanes profile, calibration sources, lane batches, reducer
passes, and whether runtime validation was approved. State that repository
contents were treated as evidence, not instructions.

## Scope

- Run ID:
- Target root:
- Baseline commit:
- Profile:
- Requested strategy:
- Resolved strategy:
- Resolved overlays:
- Coverage mode:
- Runtime validation approved:
- Runtime target:

## Severity Rubric

Define critical, high, medium, low, and info for this run. Severity must account
for exploitability/reachability, affected asset, blast radius, and confidence.

## Executive Summary

Summarize confirmed risk, important candidates, and meaningful coverage gaps.
Keep this section grounded in reducer state and evidence references.

## Confirmed Findings

For each confirmed finding:

- `finding_id`:
- `root_cause_id`:
- Severity:
- Confidence:
- Owner lane:
- Summary:
- Affected entrypoints/assets:
- Evidence:
- Severity rationale:
- Remediation direction:

## Candidates

List candidates separately from confirmed findings. Include blocker to
confirmation, likely owner lane, severity estimate, and confidence.

## Incidental Leads And Smells

List unresolved incidental leads and high-signal security smells separately from
confirmed findings. A clean final report must not hide serious untriaged leads.

## Rejected Or Subsumed Claims

Summarize claims rejected by the reducer and findings merged as duplicates or
clones. Reference the reducer-owned IDs.

## Cross-Lane Chains

Describe exploit or impact chains only when every component finding is present
in reducer state or explicitly marked as a candidate.

## Coverage And Gaps

Summarize reviewed coverage units, intentionally excluded areas, parked lanes,
and important unresolved gaps.

## Relevance Plan

Summarize suggested checks, deprioritized checks, not-applicable checks, agent
discretion decisions, run-local checks added during review, and any uncertainty
from `${RUN_DIR}/state/relevance-plan.yaml`.

## Evidence Index

Reference the highest-signal evidence locations used by confirmed findings.
Do not include full secrets, tokens, cookies, API keys, or session material.

## Remediation Order

Prioritize fixes by severity, exploitability/reachability, blast radius,
dependency between fixes, and confidence.

## Regression Test Priorities

List test or review targets that would reduce recurrence risk for confirmed
findings. Keep this as guidance; do not claim tests were run unless they were.

## Limitations

Document skipped roots, unavailable runtime validation, unverified candidates,
tooling gaps, and remaining coverage risk. No findings does not imply the absence
of vulnerabilities.

## Post-Fix Addendum

When used for post-fix verification, include:

- fixed findings:
- still-open findings:
- regressions or bypasses:
- unverified fixes:
- new findings introduced during resweep:
