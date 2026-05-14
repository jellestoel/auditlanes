Below is a consolidated, Codex-ready design brief for evolving AuditLanes.

You can hand this to Codex as the working direction.

---

# AuditLanes redesign brief

## Final recommendation

AuditLanes should **not** become a collection of many narrow security profiles. That will increase tunnel vision.

The stronger design is:

```text
core protocol
+ broad profile
+ explicit strategy
+ optional overlays
+ anti-tunnel safeguards
+ reducer-owned evidence state
```

For security audits, the preferred shape should be:

```yaml
profile: security
strategy: invariant-audit
overlays:
  - auto
```

or, when the project shape is known:

```yaml
profile: security
strategy: invariant-audit
overlays:
  - webapp
  - multi-tenant-saas
```

The key principle:

> **Profiles define evidence contracts and reducer semantics. They must not define what reviewers are allowed to notice.**

Lanes can own findings, but lanes must not blind reviewers.

---

# 1. Profiles, strategies, and overlays

## Profiles

A profile should represent a genuinely different audit domain with different state, evidence, reducer behavior, and report shape.

Good top-level profiles:

```text
security
privacy
architecture
reliability
performance
migration
```

Avoid turning these into top-level profiles:

```text
object-auth
session-auth
api-security
webapp-security
asvs
diff-review
runtime-safe
django
fastapi
node
saas
```

Those should be lanes, strategies, or overlays.

Your current `architecture` profile should remain experimental until it has its own reducer semantics and report contracts. Do not run it through a security-shaped schema and call it stable.

## Strategies

A strategy defines **how** the selected profile is executed.

Recommended security strategies:

```text
invariant-audit
full
diff-review
asvs-baseline
authz-deep-dive
platform-supply-chain
runtime-validation
post-fix-verification
```

Example:

```yaml
profile: security
strategy: invariant-audit
```

means:

```text
Use the security profile’s finding/evidence model, but run the audit around
security invariants, attack-surface graphing, authorization matrices, proof
levels, and regression planning.
```

## Overlays

An overlay specializes a broad profile/strategy for project shape or audit emphasis.

Examples:

```text
webapp
api
multi-tenant-saas
integration-heavy
platform-heavy
data-heavy
library-package
mobile-backend
ai-agent-app
```

Overlays may add:

```text
seed patterns
invariant templates
priority surfaces
evidence expectations
required artifacts
report sections
```

But overlays must never hide unrelated serious findings.

Bad:

```yaml
profile: security-saas-only
```

Better:

```yaml
profile: security
strategy: invariant-audit
overlays:
  - multi-tenant-saas
```

---

# 2. Main audit model: invariant-first, not lane-first

The current six security lanes are useful:

```text
session-auth
object-auth
role-matrix
data-surfaces
integration-trust
platform-posture
```

But they should be **ownership labels**, not the primary discovery model.

The primary discovery model should become:

```text
security invariant
+ attack surface
+ principal/object/action
+ expected guard
+ observed guard
+ evidence
+ proof level
+ reducer-owned state
```

Example invariant:

```text
INV-tenant-export-001:
A user must never export invoices belonging to another tenant.
```

Map that to:

```text
asset: invoice
principal: authenticated tenant user
action: export
entrypoint: GET /orgs/:org_id/invoices/export
expected guard: tenant membership for target org
observed guard: session only / unclear
impact boundary: cross-tenant invoice disclosure
owner_family: object-auth
secondary_families: data-surfaces, role-matrix
```

This is better than saying “object-auth lane should find IDORs,” because real findings often cross lane boundaries.

OWASP ASVS is a useful external baseline for verifiable application security requirements; OWASP describes ASVS as a basis for testing web application technical security controls and for giving developers secure-development requirements, and the ASVS repository lists 5.0.0, dated May 2025, as the latest stable version. ([OWASP Foundation][1])

---

# 3. Recommended audit flow

Replace the lane-first flow:

```text
batch-01: all six lanes canonical-sweep
batch-02: adaptive
batch-03: adaptive
batch-04: exploit synthesis
```

with a broader, less tunnel-prone flow:

```text
batch-00: run init and static-safe calibration
batch-01: attack-surface graph + security invariant catalog
batch-02: broad obvious-risk sweep
batch-03: risk-ranked invariant work packets
batch-04: lane-owned deep review and proof escalation
batch-05: clone/variant search
batch-06: runtime-safe validation, only if approved
batch-07: adversarial final review
batch-08: exploit-chain synthesis
batch-09: final report and regression plan
```

For smaller repos, collapse this into fewer batches, but keep the pattern:

```text
broad first
focused second
broad again
```

That pattern is the main anti-tunnel safeguard.

---

# 4. Anti-tunnel rules

Add these rules to every security strategy:

```yaml
anti_tunnel:
  universal_reportability: true
  reviewers_may_emit_out_of_lane_leads: true
  reducer_assigns_final_owner: true
  broad_sanity_pass_required: true
  final_adversarial_review_required: true
  strategy_may_prioritize_but_not_exclude_issue_classes: true
  overlays_may_add_focus_but_not_hide_unrelated_high_severity_findings: true
  final_report_must_include_unresolved_incidental_leads: true
```

Reviewer rule:

```text
Your lane is your primary mission, not your blindfold.
Report any obvious serious security issue you encounter, even if it belongs to
another lane. If you cannot fully confirm it within your lane’s mission, emit it
as an incidental lead.
```

This directly addresses the concern:

```text
session-auth reviewer sees an IDOR but ignores it
platform reviewer sees missing admin auth but ignores it
data-surface reviewer sees a leaked secret but ignores it
```

Those observations must be preserved.

---

# 5. Discovery vs ownership

Use this distinction everywhere:

```text
Discovery: broad, opportunistic, cross-cutting
Ownership: reducer-assigned, structured, deduped
```

Do **not** use:

```text
Discovery: restricted to lane
Ownership: restricted to lane
```

A session-auth reviewer may discover an object-auth issue. The reducer should assign it to object-auth later.

---

# 6. Required new artifacts

Add these state artifacts:

```text
state/security-invariants.jsonl
state/attack-surface-graph.jsonl
state/authorization-matrix.jsonl
state/data-flow-sinks.jsonl
state/proof-ledger.jsonl
state/incidental-leads.jsonl
state/security-smells.jsonl
state/unowned-surfaces.jsonl
state/regression-plan.jsonl
```

## `security-invariants.jsonl`

Tracks what must never be violated.

Example:

```json
{
  "schema_version": 1,
  "invariant_id": "INV-tenant-export-001",
  "summary": "Users must not export invoices outside their tenant.",
  "asset_types": ["invoice", "customer_pii"],
  "principal_types": ["tenant-user", "org-admin", "support"],
  "actions": ["read", "export"],
  "expected_controls": ["require_session", "require_target_org_membership"],
  "owner_family": "object-auth",
  "secondary_families": ["data-surfaces", "role-matrix"],
  "evidence_refs": [
    {
      "path": "app/routes/invoices.py",
      "line_start": 42,
      "evidence_type": "route-definition",
      "rationale": "Invoice export route discovered during calibration."
    }
  ]
}
```

## `attack-surface-graph.jsonl`

Tracks principal → entrypoint → guard → asset/data → sink/trust boundary.

Example:

```json
{
  "schema_version": 1,
  "surface_id": "SURF-invoice-export",
  "entrypoint": "GET /orgs/:org_id/invoices/export",
  "principal_types": ["tenant-user", "org-admin"],
  "assets": ["invoice", "customer_pii"],
  "actions": ["export"],
  "guards": ["require_session"],
  "trust_boundaries": ["browser", "tenant-boundary", "csv-download"],
  "risk_score": 86,
  "owner_family": "object-auth",
  "secondary_families": ["data-surfaces"],
  "evidence_refs": [
    {
      "path": "app/routes/invoices.py",
      "line_start": 42,
      "evidence_type": "route-definition",
      "rationale": "Route exposes invoice export over HTTP."
    }
  ]
}
```

## `authorization-matrix.jsonl`

This should be required for SaaS, admin apps, APIs, and business apps.

Example:

```json
{
  "schema_version": 1,
  "matrix_id": "AUTHZ-invoice-export-user-cross-tenant",
  "principal": "tenant-user",
  "object": "invoice",
  "action": "export",
  "expected": "deny when invoice tenant differs from user tenant",
  "observed_guard": "require_session only",
  "status": "needs-review",
  "surface_id": "SURF-invoice-export",
  "evidence_refs": [
    {
      "path": "app/routes/invoices.py",
      "line_start": 42,
      "evidence_type": "missing-ownership-check",
      "rationale": "Route accepts org_id and exports invoice data."
    }
  ]
}
```

## `proof-ledger.jsonl`

Track proof level per finding or candidate.

Proof levels:

```text
P0 lead
P1 candidate
P2 static-confirmed
P3 reachability-confirmed
P4 runtime-confirmed
P5 regression-backed
```

Example:

```json
{
  "schema_version": 1,
  "subject_id": "F-object-auth-abc123",
  "proof_level": "P2-static-confirmed",
  "evidence_summary": "Static route and policy review show missing target-tenant check.",
  "runtime_validation": {
    "approved": false,
    "reason": "No runtime approval was granted."
  },
  "regression_status": "proposed"
}
```

## `incidental-leads.jsonl`

Stores out-of-lane obvious issues.

Example:

```json
{
  "schema_version": 1,
  "lead_id": "LEAD-session-auth-001",
  "noticed_by_family": "session-auth",
  "proposed_owner_family": "object-auth",
  "severity_hint": "high",
  "confidence": "probable",
  "summary": "Invoice export route appears to trust caller-supplied org_id.",
  "why_noticed": "Seen while reviewing session-bearing routes.",
  "blocker_to_confirmation": "Object policy helper was not fully reviewed by this lane.",
  "files": ["app/routes/invoices.py"],
  "evidence_refs": [
    {
      "path": "app/routes/invoices.py",
      "line_start": 42,
      "evidence_type": "missing-ownership-check",
      "rationale": "The route accepts org_id and exports invoice data."
    }
  ]
}
```

## `security-smells.jsonl`

Use this for weak but interesting signals that should not pollute candidate findings.

Example:

```json
{
  "schema_version": 1,
  "smell_id": "SMELL-001",
  "category": "direct-object-reference",
  "path": "app/routes/invoices.py",
  "line_start": 42,
  "description": "Route accepts org_id and invoice_id in the same handler.",
  "recommended_owner": "object-auth",
  "status": "needs-triage"
}
```

## `unowned-surfaces.jsonl`

Track surfaces calibration found but no lane/strategy clearly owns.

Example:

```json
{
  "schema_version": 1,
  "surface_id": "SURF-legacy-admin-export",
  "reason": "High-risk export route found but no lane scope assigned it.",
  "paths": ["legacy/admin/export.php"],
  "risk_hint": "admin export of sensitive data",
  "status": "requires-triage"
}
```

The final report should not appear clean when high-risk unowned surfaces remain.

## `regression-plan.jsonl`

Every confirmed finding should end with a recurrence-prevention plan.

Example:

```json
{
  "schema_version": 1,
  "finding_id": "F-object-auth-abc123",
  "recommended_regression": "negative integration test",
  "test_name": "test_user_cannot_export_other_tenant_invoice",
  "guard_asserted": "require_target_org_membership",
  "automation_status": "proposed",
  "owner_hint": "backend"
}
```

---

# 7. Sidecar schema changes

Add top-level fields:

```json
{
  "strategy": "invariant-audit",
  "overlays": ["webapp", "multi-tenant-saas"],
  "incidental_leads": [],
  "security_smells": [],
  "proof_updates": [],
  "regression_recommendations": []
}
```

Add `incidentalLead` definition:

```json
{
  "incidentalLead": {
    "type": "object",
    "additionalProperties": false,
    "required": [
      "lead_id",
      "noticed_by_family",
      "proposed_owner_family",
      "summary",
      "confidence",
      "severity_hint",
      "blocker_to_confirmation",
      "files",
      "evidence_refs"
    ],
    "properties": {
      "lead_id": { "type": "string" },
      "noticed_by_family": { "$ref": "#/$defs/family" },
      "proposed_owner_family": { "$ref": "#/$defs/ownerFamily" },
      "summary": { "type": "string" },
      "confidence": { "$ref": "#/$defs/confidence" },
      "severity_hint": { "$ref": "#/$defs/severity" },
      "why_noticed": { "type": "string" },
      "blocker_to_confirmation": { "type": "string" },
      "files": { "$ref": "#/$defs/stringList" },
      "evidence_refs": {
        "type": "array",
        "minItems": 1,
        "items": { "$ref": "#/$defs/evidenceRef" }
      }
    }
  }
}
```

Add validation rules:

```text
strategy must exist under selected profile
overlay IDs must exist under selected profile
sidecar mode must be allowed by strategy
strategy-required artifacts must exist
incidental leads must have evidence
incidental leads may propose any normal lane as owner
incidental leads must not use specialist families as owner
overlays may add requirements but not remove universal reportability
```

---

# 8. Finding identity changes

Current dedupe key:

```text
owner_family
security_invariant
missing_guard
entrypoint
impact_boundary
```

Better dedupe key:

```text
invariant_id
asset_type
principal
action
entrypoint
guard_expected
guard_observed
impact_boundary
```

Suggested confirmed finding identity fields:

```json
{
  "invariant_id": "INV-tenant-export-001",
  "surface_id": "SURF-invoice-export",
  "owner_family": "object-auth",
  "secondary_families": ["data-surfaces"],
  "asset_type": "invoice",
  "principal": "tenant-user",
  "action": "export",
  "entrypoint": "GET /orgs/:org_id/invoices/export",
  "guard_expected": "require target org membership",
  "guard_observed": "require session only",
  "impact_boundary": "cross-tenant invoice disclosure"
}
```

This makes duplicate suppression cleaner and remediation clearer.

---

# 9. Cross-lane triggers

Add reducer-level triggers so obvious cross-lane issues do not get lost.

Example:

```yaml
cross_lane_triggers:
  - id: object-id-route
    when:
      evidence_type: route-definition
      patterns:
        - "object_id"
        - "tenant_id"
        - "org_id"
        - "account_id"
        - "invoice_id"
    notify:
      - object-auth

  - id: export-download-route
    when:
      patterns:
        - "download"
        - "export"
        - "file"
        - "blob"
        - "attachment"
    notify:
      - data-surfaces
      - object-auth

  - id: admin-route
    when:
      patterns:
        - "admin"
        - "support"
        - "staff"
        - "moderation"
    notify:
      - role-matrix

  - id: webhook-callback-route
    when:
      patterns:
        - "webhook"
        - "callback"
        - "signature"
        - "state"
        - "nonce"
    notify:
      - integration-trust
      - session-auth

  - id: platform-config-change
    when:
      paths:
        - ".github/**"
        - "Dockerfile"
        - "docker-compose.yml"
        - "terraform/**"
        - "k8s/**"
        - "package.json"
        - "pyproject.toml"
    notify:
      - platform-posture
```

Reducer behavior:

```text
trigger match -> create directive or incidental lead
dedupe by surface/invariant/path
feed into next batch
record in run-events.jsonl
```

---

# 10. Broad obvious-risk sweep

Add a required generalist pass.

Name options:

```text
generalist-sanity
obvious-risk-sweep
embarrassing-miss-pass
```

Purpose:

```text
Find obvious serious issues that narrow lanes or overlays might miss.
This is not a deep proof pass; it preserves high-signal leads and quick confirmations.
```

Checklist:

```text
committed secrets
unauthenticated sensitive routes
admin routes protected only by login
IDOR-shaped route patterns
dangerous file downloads/uploads
export routes missing object scope
SSRF/proxy/fetch/URL preview paths
unsafe deserialization/eval/shell execution
webhooks without obvious signature or replay checks
OAuth/callback state handling issues
CORS/cookie/session misconfiguration
CI/CD token or permission hazards
logs containing tokens, credentials, or PII
public debug/dev endpoints
```

The OWASP Web Security Testing Guide is a useful reference for broad web coverage; its current “latest” web testing section includes categories such as information gathering, configuration/deployment, identity, authentication, authorization, session management, input validation, error handling, cryptography, business logic, client-side testing, and API testing. ([OWASP Foundation][2])

---

# 11. Final adversarial review

Add a final reviewer whose job is to attack the audit process itself.

Prompt:

```text
Assume this audit missed something obvious. Review the attack-surface graph,
invariants, authorization matrix, findings, candidates, incidental leads,
security smells, unowned surfaces, and final report. Identify the most likely
missed issue classes and the concrete files/surfaces where they would hide.
```

Output:

```text
likely missed issue class
why current lanes/strategy may have missed it
specific files/surfaces to inspect
recommended follow-up
whether final report should be blocked, caveated, or accepted
```

This is different from exploit synthesis:

```text
exploit synthesis chains known findings
adversarial review challenges coverage and methodology
```

---

# 12. Proof ladder

Use explicit proof levels:

```text
P0 lead
P1 candidate
P2 static-confirmed
P3 reachability-confirmed
P4 runtime-confirmed
P5 regression-backed
```

A finding is strongest when it reaches:

```text
P4 runtime-confirmed
or
P5 regression-backed
```

If runtime validation is not approved, record that explicitly.

Runtime-safe validation must remain opt-in and scoped. Keep your existing runtime approval model.

---

# 13. Regression-first remediation

A security audit should not end with “here are bugs.” It should end with recurrence prevention.

For every confirmed finding, require one of:

```text
unit test
integration test
policy test
configuration assertion
custom static rule
dependency/policy gate
manual compensating control
documented not-feasible reason
```

Add final report section:

```text
Regression Test Priorities
```

and machine-readable state:

```text
state/regression-plan.jsonl
```

NIST SSDF is useful as a program-level reference because SP 800-218 describes a set of secure software development practices that can be integrated into SDLC implementations. ([csrc.nist.gov][3])

---

# 14. Control-baseline mode

Add an `asvs-baseline` strategy, but do not make ASVS a separate top-level profile.

```yaml
profile: security
strategy: asvs-baseline
overlays:
  - webapp
```

Required artifacts:

```text
state/control-assessment.jsonl
state/requirement-map.jsonl
```

Example:

```json
{
  "schema_version": 1,
  "control_id": "ASVS-...",
  "status": "pass | fail | not-applicable | not-reviewed",
  "evidence_refs": [],
  "finding_ids": [],
  "notes": "Mapped to session cookie configuration."
}
```

ASVS gives you verifiable control coverage. WSTG gives you testing categories and methodology. SAMM is better for measuring and improving the organization’s broader software-security program over time; OWASP describes SAMM as an open framework for formulating and implementing a software security strategy tailored to organizational risk. ([OWASP Foundation][4])

---

# 15. Diff-review strategy

Add:

```yaml
profile: security
strategy: diff-review
```

Inputs:

```text
base_ref
head_ref
changed files
changed entrypoints
changed guards
changed dependencies
changed config
changed trust boundaries
```

Output:

```text
changed security surfaces
affected invariants
new or modified guards
new or modified sinks
dependency/config risk
required regression updates
residual risk
```

This should be used for PR/release review, not full repo audits.

---

# 16. Authorization deep dive

Add:

```yaml
profile: security
strategy: authz-deep-dive
overlays:
  - multi-tenant-saas
```

Required artifacts:

```text
authorization-matrix.jsonl
object-action-principal-map.jsonl
```

This is likely the highest-value strategy for SaaS apps.

Look for:

```text
normal read path has ownership check, export path does not
UI hides action, API allows it
admin route checks session only
bulk endpoint skips per-object checks
repository helper trusts caller-supplied tenant_id
background job trusts request-created payload
support impersonation lacks boundary checks
```

---

# 17. Platform and supply-chain strategy

Add:

```yaml
profile: security
strategy: platform-supply-chain
```

Focus:

```text
committed secrets
dependency manifests and lockfiles
CI/CD permissions
pull_request_target hazards
package-manager lifecycle scripts
container config
IaC/cloud config
deployment headers/config
logging of credentials or PII
release/package publishing posture
```

This is still a security strategy, not necessarily a separate profile yet.

---

# 18. Reducer behavior changes

The reducer should handle:

```text
confirmed findings
candidate findings
incidental leads
security smells
proof updates
regression recommendations
unowned surfaces
cross-lane triggers
late obvious findings
coverage gaps
profile feedback
strategy-required artifacts
```

Add run events:

```text
late-obvious-finding
out-of-lane-lead-imported
out-of-lane-lead-promoted
out-of-lane-lead-rejected
unowned-high-risk-surface
strategy-required-artifact-missing
adversarial-review-blocker
coverage-quality-warning
```

Track quality metrics:

```text
late high/critical findings
findings discovered by final sanity pass
out-of-lane leads per run
lead promotion rate
unowned high-risk surfaces
accepted profile feedback
coverage gaps closed after batch 1
findings reassigned by reducer
```

If the final sanity pass regularly finds high-severity issues, the earlier calibration or strategy is too narrow.

---

# 19. Suggested file layout

Add:

```text
plugins/auditlanes/resources/profiles/security/
  profile.yaml
  lanes.yaml
  invariants.yaml
  proof-levels.yaml
  cross-lane-triggers.yaml
  strategies/
    invariant-audit.yaml
    full.yaml
    diff-review.yaml
    asvs-baseline.yaml
    authz-deep-dive.yaml
    platform-supply-chain.yaml
    runtime-validation.yaml
    post-fix-verification.yaml
  overlays/
    webapp.yaml
    api.yaml
    multi-tenant-saas.yaml
    integration-heavy.yaml
    platform-heavy.yaml
    data-heavy.yaml
    library-package.yaml
```

Add schemas:

```text
resources/schemas/security-invariant.schema.json
resources/schemas/attack-surface.schema.json
resources/schemas/authorization-matrix.schema.json
resources/schemas/proof-ledger.schema.json
resources/schemas/incidental-lead.schema.json
resources/schemas/security-smell.schema.json
resources/schemas/unowned-surface.schema.json
resources/schemas/regression-plan.schema.json
```

---

# 20. Suggested CLI / invocation shape

Keep:

```text
/auditlanes:scan . --profile security
```

Add:

```text
/auditlanes:scan . --profile security --strategy invariant-audit
```

Add overlays:

```text
/auditlanes:scan . --profile security --strategy invariant-audit --overlay webapp --overlay multi-tenant-saas
```

Add diff mode:

```text
/auditlanes:scan . --profile security --strategy diff-review --base main --head HEAD
```

Add ASVS baseline:

```text
/auditlanes:scan . --profile security --strategy asvs-baseline --overlay webapp
```

Default should become:

```yaml
profile: security
strategy: invariant-audit
overlays:
  - auto
```

---

# 21. Rollout plan

## v0.4.8

Minimal schema and strategy groundwork.

```text
add strategy and overlays fields to sidecars
add incidental_leads to sidecars
add strategy catalog under security
add overlay catalog under security
add validator checks for strategy/overlay existence
add reducer import for incidental leads
add incidental-leads.jsonl
add broad obvious-risk sweep guidance
```

## v0.4.9

Attack-surface and invariant artifacts.

```text
add security-invariants.jsonl
add attack-surface-graph.jsonl
add unowned-surfaces.jsonl
add cross-lane trigger config
add reducer directives from cross-lane triggers
```

## v0.5.0

Stable invariant-audit strategy.

```text
make invariant-audit the recommended default
add proof-ledger.jsonl
add authorization-matrix.jsonl
add regression-plan.jsonl
add final adversarial review
add quality metrics
```

## v0.6.0

Stable diff-review strategy.

```text
support base/head inputs
changed-surface detection
changed-invariant mapping
targeted final report
```

## v0.7.0

ASVS/control-baseline strategy.

```text
control-assessment.jsonl
requirement-map.jsonl
ASVS mapping support
baseline final report sections
```

## v0.8.0+

Only then stabilize other top-level profiles.

```text
architecture
privacy
reliability
performance
```

Do not stabilize them until each has its own reducer semantics, state model, and report contract.

---

# 22. Final design principle

The final AuditLanes model should be:

```text
broad profiles
explicit strategies
optional overlays
universal reportability
incidental lead capture
reducer-owned ownership
proof-level tracking
regression-backed closure
```

The most important sentence to encode into the protocol is:

> **A lane is an ownership mechanism, not a visibility boundary.**

That single rule prevents the worst tunnel-vision failure mode while preserving the structure that makes AuditLanes useful.

---

# 23. Scan advisor and auto relevance UX

AuditLanes should be easy to invoke without requiring users to choose profiles,
strategies, overlays, runtime posture, lanes, and batch shape up front.

No-argument scan should start a **static-only scan advisor**, not a long audit:

```text
/auditlanes:scan
@auditlanes scan
./scan
```

Recommended behavior:

```text
1. Perform a tiny static-only pre-scan.
2. Infer the most suitable scan parameters.
3. Present a short recommended plan.
4. Offer numbered choices.
5. Let the operator accept, override, customize, or cancel.
```

Do not make beginners manually choose:

```text
profile
strategy
overlay
runtime validation
lane workers
batch mode
```

The default should be:

```yaml
profile: security
strategy: auto
overlays:
  - auto
```

Then calibration resolves that into a concrete plan, for example:

```yaml
resolved_profile: security
resolved_strategy: small-app-invariant-audit
resolved_overlays:
  - python
  - payment-flow
  - checkout
  - payment-flow
coverage_mode: full-read
runtime_validation: false
```

or, for a larger app:

```yaml
resolved_profile: security
resolved_strategy: invariant-audit
resolved_overlays:
  - webapp
  - api
  - multi-tenant-saas
coverage_mode: risk-ranked
runtime_validation: false
```

## Advisor modes

Support three invocation modes:

```text
advisor
auto
explicit
```

### Advisor mode

Triggered by no-argument or under-specified interactive invocations:

```text
/auditlanes:scan
@auditlanes scan
./scan
```

Behavior:

```text
pre-scan -> recommend -> ask user to choose
```

### Auto mode

Triggered by:

```text
/auditlanes:scan . --auto --yes
./scan --auto --yes
```

Behavior:

```text
pre-scan -> accept recommendation -> run without asking
```

Runtime validation remains disabled unless explicitly approved.

### Explicit mode

Triggered by explicit parameters:

```text
/auditlanes:scan . --profile security --strategy invariant-audit --overlay webapp
```

Behavior:

```text
respect user parameters
validate them
warn if they look mismatched
do not silently rewrite them
```

## Static-only pre-scan

The advisor may inspect:

```text
file tree
git root and dirty state
rough LOC
languages and framework indicators
dependency manifests
routes, handlers, CLI entrypoints, jobs, callbacks
third-party provider imports
domain-object naming such as cart, order, tenant, account, file, message, or job
webhook/callback/signature naming
auth/session indicators
database/model files
CI/config files
previous AuditLanes runs
```

The advisor must not run:

```text
tests
application code
install commands
package scripts
Docker
network calls
payment-provider calls
runtime probes
```

This phase runs before `run-init`. It should either write nothing or write only
a temporary preview. After the operator accepts the plan, the real run starts
and writes:

```text
state/relevance-plan.yaml
```

## Numbered choices

The advisor should usually offer:

```text
1. Recommended scan
2. Quick obvious-risk sweep
3. Deep invariant audit
4. Diff review
5. Customize parameters
6. Cancel
```

Meaning:

```text
Recommended:
  Use the inferred strategy, overlays, coverage mode, and output style.

Quick:
  Broad obvious-risk sweep plus top critical/high candidates.

Deep:
  Full invariant audit, reducer state, clone/variant pass, and final adversarial review.

Diff:
  Review changed files and changed security surfaces against a base branch.

Customize:
  Let the operator adjust profile, strategy, overlays, runtime posture, output style, and diff base.

Cancel:
  Exit without writing run artifacts.
```

Keep the questionnaire short. At most:

```text
1. recommended / quick / deep / diff / customize
2. runtime validation approved? default no
3. diff base branch? default main or detected upstream
```

## Small app rule

For small repositories, especially below roughly 2k LOC, `strategy: auto`
should usually resolve to:

```yaml
strategy: small-app-invariant-audit
coverage_mode: full-read
execution: agent-team
fallback_execution:
  - subagent
  - single-session
lanes_as_owner_labels_only: true
```

Rationale:

```text
Complete read-through is feasible.
Lane partitioning should not narrow coverage; accelerated workers still use
full-read coverage and lane ownership labels.
Splitting too early increases tunnel-vision risk.
```

If a small Python app has strong commerce/payment evidence, the advisor may
add those overlays as optional emphasis:

```yaml
profile: security
strategy: small-app-invariant-audit
overlays:
  - python
  - checkout
  - payment-flow
coverage_mode: full-read
runtime_validation: false
output_style: compact
```

This is an example, not the default mental model. Auto relevance should infer
archetypes from evidence, record uncertainty, and let agents adapt when the
code reveals scenarios the advisor did not predict.

## Relevance plan

The accepted plan should be recorded in:

```text
state/relevance-plan.yaml
```

Required content:

```yaml
schema_version: 1
profile: security
requested_strategy: auto
resolved_strategy: small-app-invariant-audit
resolved_overlays:
  - python
coverage_mode: full-read
runtime_validation: false
output_style: compact

repo_observations:
  languages:
    - python
  approximate_loc: 700
  detected_frameworks: []
  detected_surfaces:
    - cart
    - checkout
    - payment-session
  inferred_archetypes:
    - commerce-flow
    - payment-flow

selected_checks:
  - id: commerce.client-supplied-value-trust
    status: recommended
    reason: "Commerce/order-like names were detected; verify trusted server-side state before money, entitlement, or fulfillment decisions."
    evidence: []

deprioritized_checks:
  - id: large-repo.agent-team
    status: not-applicable
    reason: "Small codebase; keep full-read coverage, while execution still follows the agent-team-first policy."
    evidence: []

universal_checks_enabled: true
agent_discretion_enabled: true
uncertainty: []
coverage_gaps: []
```

Every selected or skipped check should have a reason. When possible, cite
evidence using file and line references.

## Auto relevance rule

Auto mode may prioritize, deprioritize, or mark checks not applicable, but it
must never silently suppress serious issues.

The advisor is not a deterministic checklist generator. It provides useful
pieces and framing:

```text
surface cues
language/framework cues
invariant templates
known risk packs
safety constraints
artifact contracts
```

Agents remain responsible for judgment. They may:

```text
ignore irrelevant suggested checks
raise or lower depth based on code evidence
combine risk packs
create run-local checks for unmodeled scenarios
report serious issues outside the relevance plan
record uncertainty instead of pretending the pre-scan was complete
```

When an agent adds a run-local check, it should record:

```text
check id
why the existing packs were insufficient
evidence that triggered the new check
how it affects scope, findings, or regression recommendations
```

Use this rule everywhere:

```text
Auto relevance may reduce depth, but it may not suppress reportability.
Advisor output frames the audit; it does not bound agent judgment.
```

Examples:

```text
No auth framework detected -> reduce role-matrix depth, but still check object ownership on sensitive flows.
Payment checks selected -> still report committed secrets.
Platform-heavy not selected -> still report unauthenticated admin routes if noticed.
No predicted archetype fits -> agents may add a new local check family and explain why.
```

This keeps `auto` useful without turning it into a tunnel-vision mechanism.

## Command surface

Support:

```text
/auditlanes:scan
/auditlanes:scan .
/auditlanes:scan . --auto
/auditlanes:scan . --auto --yes
/auditlanes:scan . --quick
/auditlanes:scan . --deep
/auditlanes:scan . --diff
/auditlanes:scan . --profile security --strategy invariant-audit
/auditlanes:scan show profiles
/auditlanes:scan show strategies
/auditlanes:scan show overlays
```

Portable host design:

```text
Use a conversational numbered-choice wizard.
Do not depend on a host-specific custom menu.
```

[1]: https://owasp.org/www-project-application-security-verification-standard/?utm_source=chatgpt.com "OWASP Application Security Verification Standard (ASVS)"
[2]: https://owasp.org/www-project-web-security-testing-guide/?utm_source=chatgpt.com "OWASP Web Security Testing Guide"
[3]: https://csrc.nist.gov/pubs/sp/800/218/final?utm_source=chatgpt.com "Secure Software Development Framework (SSDF) Version 1.1 ..."
[4]: https://owasp.org/www-project-samm/?utm_source=chatgpt.com "OWASP SAMM"
