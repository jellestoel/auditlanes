# GPT-5 Pro Prompt: Should AuditLanes Performance Be Its Own Profile?

You are advising on AuditLanes profile architecture. The immediate question is
whether `performance` should become its own top-level profile or be folded into
the existing experimental `production-integrity` profile.

Do not treat the local maintainer's current instinct as authoritative. Use your
extra reasoning time to challenge the taxonomy, the profile boundary, the lane
model, the sidecar contract, and the reducer semantics. The useful answer may be
"performance is its own profile", "performance belongs inside another broader
profile", "performance should be a strategy/overlay, not a profile", or a more
nuanced split.

Be concrete, skeptical, and practical. Avoid generic performance checklist
advice unless it affects how AuditLanes should model evidence, lanes, severity,
dedupe, reducer state, completion gates, and cross-profile launch gates.

## Context Note

This is a copy-paste prompt for ChatGPT/GPT-5 Pro in the web UI. You do not have
local filesystem or command access. All context you should use is included
inline below.

The local repo is `~/repos/fullsecscan`, which contains the AuditLanes plugin
and protocol.

## Core Decision

Answer these directly, but do not stop at a yes/no:

1. Should `performance` be a top-level AuditLanes profile?
2. If yes, what should its exact scope be, and what must remain out of scope?
3. If no, where should performance concerns live instead?
4. What performance issues, if any, should still be reportable from
   `production-integrity`?
5. How should performance findings interact with launch gates produced by
   `security` and `production-integrity`?
6. What is the smallest useful implementation that would be worth building?

## Creative Mandate

Do not limit yourself to patching current names.

You may propose:

- a separate `performance` profile
- a different profile name such as `runtime-performance`, `runtime-capacity`,
  `scalability`, `capacity-integrity`, `operational-fitness`, or something else
- making performance a strategy under `production-integrity`
- splitting latency/load/capacity into profiles, lanes, strategies, or overlays
- merging some planned profiles (`performance`, `reliability`, `migration`) into
  a better top-level domain
- changing the reducer model
- changing severity and proof models
- adding cross-profile launch gate imports
- a minimum viable profile that is deliberately narrow
- a reason not to build this yet

Preserve the things that make AuditLanes useful: evidence-first claims,
reducer-owned state, lane ownership, repeatable output, explicit coverage gaps,
runtime-safe posture, and adaptability to unknown products.

## Local Hypothesis To Challenge

The local working hypothesis is:

- `performance` should probably be its own profile because its evidence,
  severity, proof, and reducer semantics differ from `production-integrity`.
- `production-integrity` should only report performance-related issues when
  they break correctness, recovery, generated commitments, deadline-sensitive
  workflows, cutover safety, or launch confidence.
- General N+1 queries, missing indexes, p95/p99 latency risk, cache stampedes,
  queue saturation, pool exhaustion, capacity planning, and load test absence
  probably belong in a performance profile.

Your job is to attack or improve this hypothesis.

## What AuditLanes Is

AuditLanes is a Claude Code and Codex plugin/protocol for structured code
audits. The repo README describes the workflow as:

1. calibrate the project shape and risk surfaces
2. split work across stable lanes
3. require evidence-backed machine-readable sidecars
4. reduce duplicate lane findings into stable IDs
5. carry forward leads, rejected claims, proof updates, and follow-up work

It is a reasoning-driven audit harness. It is not intended to replace SAST,
dependency scanners, `npm audit`, APM tools, load testing platforms, or
benchmark suites.

Important recurring principles:

- Findings should cite concrete files, symbols, line ranges, and rationale.
- Runs are static-only unless runtime-safe validation is explicitly approved.
- Prior audit output can seed leads, but old reports do not become application
  evidence.
- Lanes may report out-of-lane leads, but the reducer owns final state.
- Profiles should derive lane IDs, strategy IDs, overlay IDs, modes, and
  cross-lane trigger destinations from profile files rather than hardcoding
  them.

## Current Repo State

The package manifest says the current package version is `0.4.19`. The README
still says `0.4.16`, so assume there is some doc drift.

Current status from the repo:

- `security` is stable runnable.
- `production-integrity` is experimental runnable.
- `architecture` is experimental metadata only.
- `performance`, `reliability`, `migration`, and `privacy` are planned but not
  implemented.
- There is no packaged `auditlanes` CLI yet.
- `scan_advisor.py` is a minimal static relevance preview, not a full
  orchestrator.
- The validator supports profile-specific report sidecars, manifests, and core
  state files.
- The reducer imports confirmed findings, candidates, rejected claims, profile
  feedback, chain candidates, incidental leads, security smells, production risk
  signals, proof updates, run-local checks, and regression recommendations.
- The reducer does not yet process coverage, final reports, or scope mutation.
- Candidate-to-confirmed transition crosswalk remains future work.
- `validate_run.py --complete` is currently a security-only completion gate.

## Profile Catalog Snapshot

```yaml
version: 1
name: auditlanes-profile-catalog

default_profile: security

profiles:
  - id: security
    status: stable
    implemented: true
    description: "Full security scan profile with authentication, authorization, data surface, integration, and platform lanes."
    profile_root: "resources/profiles/security"
    profile_file: "resources/profiles/security/profile.yaml"
    lanes_file: "resources/profiles/security/lanes.yaml"
    strategies_root: "resources/profiles/security/strategies"
    overlays_root: "resources/profiles/security/overlays"
    cross_lane_triggers_file: "resources/profiles/security/cross-lane-triggers.yaml"
    scaffold_root: "resources/repo-scaffold/auditlanes"
  - id: architecture
    status: experimental
    implemented: false
    description: "Architecture and maintainability audit profile metadata. Not yet a stable runnable profile."
    profile_root: "resources/profiles/architecture"
    profile_file: "resources/profiles/architecture/profile.yaml"
    lanes_file: "resources/profiles/architecture/lanes.yaml"
  - id: production-integrity
    status: experimental
    implemented: true
    description: "Experimental launch integrity profile for durable state correctness, workflow atomicity, generated-output reconciliation, lifecycle recovery, cutover controls, and assurance evidence."
    profile_root: "resources/profiles/production-integrity"
    profile_file: "resources/profiles/production-integrity/profile.yaml"
    lanes_file: "resources/profiles/production-integrity/lanes.yaml"
    strategies_root: "resources/profiles/production-integrity/strategies"
    overlays_root: "resources/profiles/production-integrity/overlays"
    cross_lane_triggers_file: "resources/profiles/production-integrity/cross-lane-triggers.yaml"
  - id: performance
    status: planned
    implemented: false
    description: "Performance and scalability audit profile."
  - id: reliability
    status: planned
    implemented: false
    description: "Reliability and resilience audit profile."
  - id: migration
    status: planned
    implemented: false
    description: "Migration readiness audit profile."
  - id: privacy
    status: planned
    implemented: false
    description: "Privacy and data governance audit profile."

rules:
  - "AuditLanes bundles the security profile as stable runnable and production-integrity as experimental runnable."
  - "Experimental profile metadata may exist to exercise core/profile loading, but only profiles with implemented:true are runnable audit modes."
  - "Executable validators derive lane and specialist IDs from the selected profile instead of hardcoding them in report schemas."
  - "Executable validators derive strategy and overlay IDs from the selected profile instead of hardcoding them in report schemas."
  - "Executable validators load the selected profile's report_sidecar_schema instead of forcing every profile through the security sidecar contract."
  - "Executable validators derive cross-lane trigger notification lanes from the selected profile instead of hardcoding them in reducer code."
  - "strategy:auto is resolved during calibration and must produce state/relevance-plan.yaml with the concrete strategy, overlays, coverage mode, suggested checks, and agent-discretion flags."
```

## Profile Design Principle From Existing Plan

The repo's internal planning notes say:

```text
A profile should represent a genuinely different audit domain with different
state, evidence, reducer behavior, and report shape.

Good top-level profiles:

security
privacy
architecture
reliability
performance
migration

Avoid turning these into top-level profiles:

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

Those should be lanes, strategies, or overlays.
```

You may challenge this principle if it is wrong or incomplete.

## Current `production-integrity` Profile

`production-integrity` is experimental but runnable.

```yaml
version: 1
id: production-integrity
status: experimental
implemented: true
report_sidecar_schema: production-integrity-report-sidecar.schema.json
lane_source: lanes.yaml
strategy_source: strategies
overlay_source: overlays
cross_lane_trigger_source: cross-lane-triggers.yaml
default_strategy: auto
default_overlays:
  - auto
description: "Production integrity review for durable state correctness, workflow atomicity, generated-output reconciliation, lifecycle recovery, runtime cutover controls, and assurance evidence."
default_execution_mode: agent-team
execution_fallback_order:
  - subagent
  - single-session
stability_notes:
  - "Experimental runnable profile; less stable than the security profile contract."
  - "Use after the stable security profile, treating unresolved security findings as launch gates."
  - "Prior audit output may seed leads, but current code and docs must provide application evidence."
non_goals:
  - "Generic QA coverage review."
  - "General maintainability or architecture critique."
  - "Broad SRE maturity assessment."
  - "Security re-review except importing unresolved high/critical security findings as launch gates."
external_gate_sources:
  - profile: security
    import_severities:
      - critical
      - high
    import_as: launch-gates
```

Its lanes are:

```yaml
version: 1
profile: production-integrity
lanes:
  - id: state-model-integrity
    owns: "Authoritative state, production invariants, relational constraints, uniqueness, status validity, temporal rules, and snapshot/live-state boundaries."
  - id: workflow-atomicity
    owns: "State transitions, approval flows, transaction boundaries, retries, idempotency, locking, concurrency, compensation, and partial-failure behavior."
  - id: derived-output-reconciliation
    owns: "Generated documents, invoices, reports, exports, PDFs, emails, delivery rows, accounting files, external commitments, and reconciliation between source state and outputs."
  - id: lifecycle-recovery
    owns: "Migrations, imports, backfills, retention, deletion/anonymization, backup/restore, private-file consistency, historical auditability, and recovery validation."
  - id: runtime-cutover-controls
    owns: "Production environment validation, deploy gates, migration execution, health/readiness checks, scheduled jobs, observability for core workflows, rollback, and production smoke controls."
  - id: assurance-evidence
    owns: "Evidence mapping for high-risk workflows, automated tests, scenario tests, smoke checks, CI gates, runtime proof, manual controls, and missing regression evidence."
specialists:
  - id: launch-gate-synthesis
    owns: "Cross-lane launch decision, blocker grouping, external security gates, module gates, residual risk, and go/no-go synthesis."
    mode: launch-gate-synthesis
  - id: failure-scenario-synthesis
    owns: "Concrete end-to-end production failure scenarios spanning lanes, especially durable state, generated commitments, files, jobs, deploys, and recovery."
    mode: failure-scenario-synthesis
```

Its default non-auto strategy is `production-gate`:

```yaml
version: 1
id: production-gate
profile: production-integrity
status: experimental
description: "Risk-ranked launch-integrity review across durable state correctness, workflow atomicity, generated-output reconciliation, lifecycle recovery, runtime cutover controls, and assurance evidence."
recommended_default: true
allowed_modes:
  - readiness-sweep
  - invariant-gap-fill
  - control-clonehunt
  - scenario-probe
  - runtime-safe
  - post-fix-resweep
  - launch-gate-synthesis
  - failure-scenario-synthesis
batch_shape:
  batch-01:
    expected_families: profile_lanes
    status: ran
    mode: readiness-sweep
  batch-02:
    expected_families: profile_lanes
    status: optional
    mode: invariant-gap-fill
  batch-03:
    expected_families:
      - launch-gate-synthesis
      - failure-scenario-synthesis
    status: optional
    modes_by_family:
      launch-gate-synthesis: launch-gate-synthesis
      failure-scenario-synthesis: failure-scenario-synthesis
required_state_artifacts:
  - state/relevance-plan.yaml
  - state/core-workflow-inventory.jsonl
  - state/production-invariants.jsonl
  - state/side-effect-map.jsonl
  - state/lifecycle-recovery-map.jsonl
  - state/assurance-evidence-map.jsonl
  - state/proof-ledger.jsonl
  - state/incidental-leads.jsonl
  - state/risk-signals.jsonl
  - state/run-local-checks.jsonl
  - state/regression-plan.jsonl
  - state/launch-gates.jsonl
review_requirements:
  - "Build a core workflow inventory before judging completeness."
  - "For every high-risk workflow, identify the authoritative source of truth, historical snapshot boundary, status machine, side effects, and recovery path."
  - "Prefer concrete code evidence over documentation. Documentation can establish intended behavior but cannot prove implementation."
  - "Do not report generic QA, style, architecture, or SRE maturity issues unless tied to a named production invariant, workflow, lifecycle event, generated commitment, recovery path, or launch gate."
  - "Every confirmed finding must state trigger condition, failure mode, missing control, impact boundary, detectability, and recoverability."
  - "Evidence gaps must name the high-risk workflow and invariant whose proof is missing."
  - "For each blocker, state whether it blocks launch, blocks a module, can launch with controls, or is an external security gate."
  - "Prior high/critical security findings are imported into launch-gates, not duplicated as production-integrity findings."
  - "Generated outputs and external commitments must be reconciled against authoritative state or explicit snapshots."
finding_fields:
  - owner_family
  - workflow_id
  - invariant_id
  - control_objective
  - trigger_condition
  - failure_mode
  - missing_control
  - affected_authoritative_state
  - affected_side_effects
  - impact_boundary
  - detectability
  - recoverability
  - launch_gate_effect
  - severity
  - confidence
  - evidence_refs
  - files
  - entrypoints
  - existing_controls_checked
  - recommended_regression
launch_gate_effect_values:
  - none
  - go-with-controls
  - module-gated
  - no-go
  - external-security-gate
detectability_values:
  - automatically-detected
  - dashboard-or-log-visible
  - manual-reconciliation-required
  - customer-or-finance-reported
  - silent
  - unknown
recoverability_values:
  - self-healing
  - operator-visible-retryable
  - manual-repair-required
  - restore-required
  - unrecoverable
  - unknown
```

## Current Implementation Gaps Relevant To This Decision

These are not necessarily blockers, but they shape what is realistic:

- `scan_advisor.py` currently always emits `profile: security` in its relevance
  plan, so non-security profiles do not yet get first-class automatic
  calibration.
- `validate_run.py --complete` is currently defined only for the full security
  protocol.
- `production-integrity` sidecar schema has several update arrays that are only
  typed as generic objects, so its state-update contract is less strict than it
  should be.
- The reducer has stable IDs and basic imports, but not full coverage-ledger,
  final-report, or scope-mutation semantics yet.
- The plugin intentionally supports out-of-lane leads and profile feedback, so
  a profile boundary should not prevent reviewers from noticing severe adjacent
  risks.

## Candidate Performance Scope

Potential performance concerns that might deserve first-class treatment:

- p95/p99 latency budget failures
- throughput and concurrency limits
- N+1 queries
- missing indexes and bad query plans
- database pool exhaustion
- cache stampedes and stale cache invalidation behavior
- queue saturation and worker backlog growth
- retry storms and fanout amplification
- bulk export/import/report generation time
- slow cold starts or deploy warmup risk
- memory/CPU pressure and leak-prone paths
- static asset and client-side bundle performance
- third-party API latency amplification
- rate-limit bottlenecks
- load test absence or unrealistic test coverage
- capacity planning gaps
- graceful degradation under load
- noisy-neighbor risk in multi-tenant systems

Potential performance concerns that might belong in `production-integrity`
instead, because they can corrupt workflow integrity or launch confidence:

- timeouts leave partial invoices, exports, generated documents, or delivery
  rows
- slow jobs miss business deadlines and create stale authoritative state
- backfills/imports exceed maintenance windows and leave partially migrated data
- retry storms create duplicate side effects or double external commitments
- health checks pass while core workflows are unusably slow
- missing observability means critical workflow failure is silent
- concurrency/load creates state-machine races or broken idempotency

Do not assume these lists are correct. Improve or replace them.

## What I Need From You

Please produce a design review with concrete recommendations.

Preferred structure, but adjust if another structure is clearer:

1. **Recommendation**: one clear stance on profile vs lane/strategy/overlay.
2. **Boundary Rule**: the crisp rule for when a performance concern belongs in
   `production-integrity` vs `performance`.
3. **Profile Shape**: proposed profile name, lanes, specialists, strategies,
   overlays, required state artifacts, and sidecar finding fields.
4. **Severity And Proof**: how severity should be computed without live load
   tests by default, and what proof levels should exist for static, modeled,
   runtime-safe, benchmark, APM, and regression-backed evidence.
5. **Reducer Semantics**: what a performance root cause is, how to dedupe, what
   state ledgers are needed, and how to close coverage gaps.
6. **Cross-Profile Gates**: how high/critical performance findings should
   interact with `security` and `production-integrity` launch gates.
7. **Minimum Useful Version**: the smallest implementation worth adding now,
   including exact files/directories and rough content.
8. **Failure Modes**: what this profile would still miss, and what should not be
   attempted by an LLM audit harness.
9. **Concrete Edits**: propose changes to catalog/profile files, strategy files,
   schema fields, advisor behavior, reducer behavior, and completion gates.

Be willing to say "do not build this yet" if the current protocol maturity makes
that the better engineering call. If you think the right answer is a combined
`performance-reliability` or `runtime-fitness` profile rather than a narrow
`performance` profile, explain exactly why and define its limits.
