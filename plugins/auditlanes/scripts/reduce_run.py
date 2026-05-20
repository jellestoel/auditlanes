#!/usr/bin/env python3
"""Deterministically reduce AuditLanes sidecars into run state."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
import tempfile
from hashlib import sha256
from pathlib import Path
from typing import Any

import validate_run


ID_POLICY_VERSION = 1
STATE_SCHEMA_VERSION = 1
SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1
}
PROOF_LEVEL_RANK = {
    "P0-lead": 0,
    "P1-candidate": 1,
    "P1-static-structural": 1,
    "P2-static-confirmed": 2,
    "P2-modeled": 2,
    "P3-reachability-confirmed": 3,
    "P3-runtime-safe-observed": 3,
    "P4-runtime-confirmed": 4,
    "P4-benchmark-or-apm-backed": 4,
    "P5-regression-backed": 5,
}
PROVISIONAL_ID_PREFIXES = ("PF-", "CAND-")
LENIENT_DEFAULT_GENERATED_AT = "1970-01-01T00:00:00Z"
LENIENT_WARNING_LIMIT = 200
TOP_LEVEL_ARRAY_FIELDS = (
    "reviewed_artifacts",
    "reviewed_files_routes_helpers",
    "shared_context_inputs",
    "coverage_units_touched",
    "coverage_units_not_touched",
    "patterns_searched",
    "intentionally_excluded",
    "confirmed_findings",
    "candidate_findings",
    "rejected_claims",
    "clone_maps",
    "runtime_updates",
    "chain_candidates",
    "coverage_gaps",
    "profile_feedback",
    "incidental_leads",
    "security_smells",
    "risk_signals",
    "proof_updates",
    "regression_recommendations",
    "run_local_checks",
    "performance_workflow_inventory_updates",
    "performance_budget_updates",
    "hot_path_map_updates",
    "data_access_ledger_updates",
    "async_capacity_ledger_updates",
    "resource_saturation_ledger_updates",
    "dependency_amplification_ledger_updates",
    "client_edge_ledger_updates",
    "performance_evidence_map_updates",
    "performance_coverage_gap_updates",
    "workflow_entity_updates",
    "workflow_edge_updates",
    "workflow_evidence_updates",
    "scenario_observation_updates",
    "workflow_score_updates",
    "workflow_card_updates",
    "segment_card_updates",
    "fixture_card_updates",
    "workflow_unknown_updates",
    "next_batch_recommendations",
)
TOP_LEVEL_COLLECTION_ALIASES = {
    "findings": "confirmed_findings",
    "confirmed": "confirmed_findings",
    "candidates": "candidate_findings",
    "leads": "incidental_leads",
    "incidental": "incidental_leads",
    "smells": "security_smells",
    "risks": "risk_signals",
    "proof": "proof_updates",
    "regressions": "regression_recommendations",
    "local_checks": "run_local_checks",
}
CONFIRMED_STATUSES = {"confirmed-static", "runtime-confirmed", "reswept-open", "reswept-closed"}
SEVERITIES = {"critical", "high", "medium", "low", "info"}
CONFIDENCES = {"certain", "probable", "speculative"}
PROOF_LEVELS = set(PROOF_LEVEL_RANK.keys())
STATUS_TRANSITIONS = {
    "lead": {"candidate", "confirmed-static", "rejected"},
    "candidate": {"confirmed-static", "blocked", "rejected", "duplicate"},
    "confirmed-static": {"runtime-confirmed", "fixed", "duplicate", "reswept-open", "reswept-closed"},
    "runtime-confirmed": {"fixed", "duplicate", "reswept-open", "reswept-closed"},
    "reswept-open": {"reswept-closed", "fixed", "duplicate"},
    "fixed": {"reswept-open", "reswept-closed", "duplicate"},
    "blocked": {"candidate", "confirmed-static", "rejected"},
}
REPAIRABLE_STATE_SCHEMAS = {
    "incidental-leads.jsonl": "incidental-lead.schema.json",
    "proof-ledger.jsonl": "proof-ledger.schema.json",
    "regression-plan.jsonl": "regression-plan.schema.json",
    "risk-signals.jsonl": "risk-signal.schema.json",
    "run-local-checks.jsonl": "run-local-check.schema.json",
    "security-smells.jsonl": "security-smell.schema.json",
}
SCHEMA_ALLOWED_PROPERTIES: dict[str, set[str]] = {}


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return re.sub(r"\s+", " ", value.strip())
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        return json.dumps(sorted(normalize_value(item) for item in value), separators=(",", ":"), sort_keys=True)
    if isinstance(value, dict):
        return json.dumps(normalize_value(value), separators=(",", ":"), sort_keys=True)
    return re.sub(r"\s+", " ", str(value).strip())


def normalize_value(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, str):
        return normalize_text(value)
    if isinstance(value, list):
        normalized_items = [normalize_value(item) for item in value]
        return sorted(normalized_items, key=lambda item: json.dumps(item, separators=(",", ":"), sort_keys=True))
    if isinstance(value, dict):
        return {key: normalize_value(value[key]) for key in sorted(value)}
    return value


def stable_hash(parts: list[Any], length: int = 12) -> str:
    material = json.dumps([normalize_value(part) for part in parts], separators=(",", ":"), sort_keys=True)
    return sha256(material.encode("utf-8")).hexdigest()[:length]


def warn_lenient(warnings: list[str], message: str) -> None:
    if len(warnings) < LENIENT_WARNING_LIMIT:
        warnings.append(message)
    elif len(warnings) == LENIENT_WARNING_LIMIT:
        warnings.append("additional lenient reducer warnings suppressed")


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def string_list(value: Any) -> list[str]:
    values: list[str] = []
    for item in as_list(value):
        if isinstance(item, str):
            text = normalize_text(item)
        elif item is None:
            continue
        else:
            text = normalize_text(item)
        if text:
            values.append(text)
    return unique_sorted(values)


def coerce_string(value: Any, default: str) -> str:
    text = normalize_text(value)
    return text if text else default


def coerce_nullable_string(value: Any) -> str | None:
    text = normalize_text(value)
    return text if text else None


def coerce_int(value: Any, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return default
    return default


def coerce_enum(value: Any, allowed: set[str], default: str) -> str:
    raw = normalize_text(value)
    if raw in allowed:
        return raw
    normalized = raw.lower().replace("_", "-")
    if normalized in allowed:
        return normalized
    for item in allowed:
        if item.lower().replace("_", "-") == normalized:
            return item
    return default


def path_line_from_string(value: str) -> tuple[str, int | None]:
    text = value.strip()
    match = re.match(r"^(?P<path>.+?):(?P<line>[0-9]+)(?::[0-9]+)?$", text)
    if not match:
        return validate_run.repo_path_without_line_suffix(text), None
    return match.group("path"), int(match.group("line"))


def evidence_ref_from_string(value: str, rationale: str) -> dict[str, Any] | None:
    path, line_start = path_line_from_string(value)
    if not path:
        return None
    return {
        "path": path,
        "line_start": line_start,
        "line_end": None,
        "symbol": None,
        "evidence_type": "other",
        "snippet_hash": None,
        "rationale": rationale,
    }


def coerce_evidence_refs(item: dict[str, Any], fallback_files: list[str], rationale: str) -> list[dict[str, Any]]:
    raw_refs = item.get("evidence_refs")
    if raw_refs is None:
        raw_refs = item.get("evidence") or item.get("refs") or item.get("trigger_evidence_refs")
    refs: list[dict[str, Any]] = []
    for ref in as_list(raw_refs):
        if isinstance(ref, str):
            if fallback_files and not re.search(r"(^|/)[^/\s]+\.[A-Za-z0-9]{1,12}(:[0-9]+)?$", ref.strip()):
                refs.append({
                    "path": fallback_files[0],
                    "line_start": None,
                    "line_end": None,
                    "symbol": None,
                    "evidence_type": "other",
                    "snippet_hash": None,
                    "rationale": ref.strip() or rationale,
                })
            else:
                coerced = evidence_ref_from_string(ref, rationale)
                if coerced:
                    refs.append(coerced)
            continue
        if not isinstance(ref, dict):
            continue
        path = coerce_string(ref.get("path") or ref.get("file") or (fallback_files[0] if fallback_files else ""), "")
        if not path:
            continue
        line_start = ref.get("line_start", ref.get("line"))
        if line_start is not None:
            line_start = coerce_int(line_start, 0) or None
        line_end = ref.get("line_end")
        if line_end is not None:
            line_end = coerce_int(line_end, 0) or None
        refs.append({
            "path": validate_run.repo_path_without_line_suffix(path),
            "line_start": line_start,
            "line_end": line_end,
            "symbol": coerce_nullable_string(ref.get("symbol")),
            "evidence_type": coerce_enum(ref.get("evidence_type"), {
                "entrypoint",
                "missing-authn-check",
                "missing-authz-check",
                "insufficient-role-check",
                "missing-ownership-check",
                "unsafe-data-sink",
                "integration-trust-boundary",
                "platform-config",
                "dependency-or-supply-chain",
                "runtime-observation",
                "route-definition",
                "framework-convention",
                "repository-structure",
                "dependency-manifest",
                "ci-workflow",
                "secret-pattern-redacted",
                "config-default",
                "middleware-registration",
                "policy-registration",
                "other",
            }, "other"),
            "snippet_hash": coerce_nullable_string(ref.get("snippet_hash")),
            "rationale": coerce_string(ref.get("rationale") or ref.get("reason"), rationale),
        })
    if not refs and fallback_files:
        refs.append({
            "path": fallback_files[0],
            "line_start": None,
            "line_end": None,
            "symbol": None,
            "evidence_type": "other",
            "snippet_hash": None,
            "rationale": rationale,
        })
    return refs


def files_from_item(item: dict[str, Any], sidecar: dict[str, Any] | None = None) -> list[str]:
    files = string_list(item.get("files"))
    for field in ("file", "path"):
        value = item.get(field)
        if isinstance(value, str) and value:
            files.append(validate_run.repo_path_without_line_suffix(value))
    refs = item.get("evidence_refs") or item.get("evidence") or item.get("refs") or item.get("source_refs") or []
    for ref in as_list(refs):
        if isinstance(ref, str):
            path, _ = path_line_from_string(ref)
            if path:
                files.append(path)
        elif isinstance(ref, dict) and isinstance(ref.get("path"), str):
            files.append(validate_run.repo_path_without_line_suffix(ref["path"]))
    if not files and sidecar is not None:
        files = string_list(sidecar.get("reviewed_artifacts") or sidecar.get("reviewed_files_routes_helpers"))
    return unique_sorted(files)


def infer_batch_family_from_report_path(run_dir: Path, report_path: Path) -> tuple[str | None, str | None]:
    try:
        parts = report_path.resolve().relative_to(run_dir.resolve()).parts
    except ValueError:
        return None, None
    if len(parts) == 4 and parts[0] == "reports":
        return parts[1], parts[2]
    if len(parts) == 3 and parts[0] == "reports":
        return "batch-01", parts[1]
    if len(parts) >= 3 and parts[0] == "candidates":
        return "batch-01", parts[1]
    return None, None


def relevance_plan_defaults(run_dir: Path) -> tuple[str | None, list[str]]:
    plan_path = run_dir / "state" / "relevance-plan.yaml"
    if not plan_path.exists() or plan_path.is_symlink():
        return None, []
    try:
        plan = validate_run.load_json_or_yaml(plan_path)
    except Exception:  # noqa: BLE001
        return None, []
    if not isinstance(plan, dict):
        return None, []
    strategy = plan.get("resolved_strategy") if isinstance(plan.get("resolved_strategy"), str) else None
    overlays = string_list(plan.get("resolved_overlays"))
    return strategy, overlays


def default_mode_for_batch(batch_id: str | None, family: str | None, selected_profile: dict[str, Any]) -> str:
    if family in selected_profile.get("specialist_modes", {}):
        return selected_profile["specialist_modes"][family]
    if batch_id == "batch-01":
        return "canonical-sweep"
    return "canonical-gap-fill"


def coerce_top_level_sidecar(
    sidecar: dict[str, Any],
    report_path: Path,
    manifest: dict[str, Any] | None,
    item: dict[str, Any] | None,
    run_dir: Path,
    profile: str,
    selected_profile: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any]:
    coerced = dict(sidecar)
    path_batch, path_family = infer_batch_family_from_report_path(run_dir, report_path)
    plan_strategy, plan_overlays = relevance_plan_defaults(run_dir)
    batch_id = coerce_string(coerced.get("batch_id") or (manifest or {}).get("batch_id") or path_batch, "batch-01")
    family = coerce_string(coerced.get("family") or (item or {}).get("family") or path_family, selected_profile["lane_order"][0])
    mode = coerce_string(coerced.get("mode") or (item or {}).get("mode"), default_mode_for_batch(batch_id, family, selected_profile))

    if coerced.get("schema_version") != 3:
        warn_lenient(warnings, f"{report_path}: inferred sidecar schema_version=3")
    coerced["schema_version"] = 3
    coerced["run_id"] = coerce_string(coerced.get("run_id") or (manifest or {}).get("run_id"), run_dir.name)
    coerced["batch_id"] = batch_id
    coerced["family"] = family
    coerced["mode"] = mode
    coerced["profile"] = coerce_string(coerced.get("profile"), profile)
    if profile == "security":
        default_strategy = "invariant-audit"
    elif profile == "performance":
        default_strategy = "static-capacity-sweep"
    else:
        default_strategy = "production-gate"
    coerced["strategy"] = coerce_string(coerced.get("strategy") or plan_strategy, default_strategy)
    overlays = string_list(coerced.get("overlays")) or plan_overlays or ["auto"]
    coerced["overlays"] = overlays
    coerced["sidecar_id"] = coerce_string(coerced.get("sidecar_id") or coerced.get("id"), f"sidecar-{batch_id}-{family}-{stable_hash([report_path.as_posix()])}")
    generated_at = coerced.get("generated_at") or (manifest or {}).get("generated_at")
    coerced["generated_at"] = generated_at if validate_run.is_datetime(generated_at) else LENIENT_DEFAULT_GENERATED_AT
    coerced["baseline_commit"] = coerced.get("baseline_commit") if isinstance(coerced.get("baseline_commit"), str) or coerced.get("baseline_commit") is None else None

    for alias, canonical in TOP_LEVEL_COLLECTION_ALIASES.items():
        if canonical not in coerced and alias in coerced:
            coerced[canonical] = coerced[alias]
            warn_lenient(warnings, f"{report_path}: treated top-level {alias!r} as {canonical!r}")
    for field in TOP_LEVEL_ARRAY_FIELDS:
        coerced[field] = as_list(coerced.get(field))
    return coerced


def coerce_confirmed_finding(item: Any, sidecar: dict[str, Any], report_path: Path, warnings: list[str]) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        warn_lenient(warnings, f"{report_path}: skipped non-object confirmed finding")
        return None
    finding = dict(item)
    dedupe_key = finding.get("dedupe_key") if isinstance(finding.get("dedupe_key"), dict) else {}
    owner = coerce_string(finding.get("owner_family") or finding.get("proposed_owner_family") or finding.get("family") or dedupe_key.get("owner_family"), sidecar["family"])
    summary = coerce_string(finding.get("summary") or finding.get("title") or finding.get("description"), "Unspecified security finding.")
    files = files_from_item(finding, sidecar)
    entrypoints = string_list(finding.get("entrypoints"))
    entrypoint = coerce_string(finding.get("entrypoint") or (", ".join(entrypoints) if entrypoints else None) or finding.get("surface_id") or (files[0] if files else None), summary[:120])
    security_invariant = coerce_string(finding.get("security_invariant") or finding.get("invariant") or finding.get("control_objective"), summary)
    missing_guard = coerce_string(finding.get("missing_guard") or finding.get("missing_control") or finding.get("guard"), "unspecified missing guard")
    impact_boundary = coerce_string(finding.get("impact_boundary") or finding.get("impact") or finding.get("boundary"), summary)
    finding["provisional_finding_id"] = coerce_string(
        finding.get("provisional_finding_id") or finding.get("local_id") or finding.get("id") or finding.get("finding_id"),
        f"PF-{owner}-{stable_hash([sidecar['sidecar_id'], summary, files])}",
    )
    finding["owner_family"] = owner
    finding["status"] = coerce_enum(finding.get("status"), CONFIRMED_STATUSES, "confirmed-static")
    finding["severity"] = coerce_enum(finding.get("severity"), SEVERITIES, "medium")
    finding["confidence"] = coerce_enum(finding.get("confidence"), {"certain", "probable"}, "probable")
    finding["summary"] = summary
    finding["entrypoint"] = entrypoint
    finding["security_invariant"] = security_invariant
    finding["missing_guard"] = missing_guard
    finding["attacker_precondition"] = coerce_string(finding.get("attacker_precondition") or finding.get("precondition"), "Not specified by lane output.")
    finding["impact_boundary"] = impact_boundary
    finding["files"] = files
    finding["evidence_refs"] = coerce_evidence_refs(finding, files, "Lenient reducer imported agent-authored finding evidence.")
    finding["report_refs"] = string_list(finding.get("report_refs"))
    finding["lead_source_refs"] = string_list(finding.get("lead_source_refs"))
    finding["severity_rationale"] = coerce_string(finding.get("severity_rationale") or finding.get("impact"), "Not specified by lane output.")
    finding["clone_of"] = coerce_nullable_string(finding.get("clone_of"))
    finding["related_findings"] = string_list(finding.get("related_findings"))
    finding["why_confirmed"] = coerce_string(finding.get("why_confirmed") or finding.get("rationale"), "Lenient reducer preserved a lane-confirmed claim.")
    finding["introduced_after_batch_01"] = bool(finding.get("introduced_after_batch_01")) if sidecar.get("batch_id") != "batch-01" else False
    finding["dedupe_key"] = {
        "owner_family": owner,
        "security_invariant": security_invariant,
        "missing_guard": missing_guard,
        "entrypoint": entrypoint,
        "impact_boundary": impact_boundary,
    }
    return finding


def coerce_candidate_finding(item: Any, sidecar: dict[str, Any], report_path: Path, warnings: list[str]) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        warn_lenient(warnings, f"{report_path}: skipped non-object candidate finding")
        return None
    candidate = dict(item)
    owner = coerce_string(candidate.get("proposed_owner_family") or candidate.get("owner_family") or candidate.get("family"), sidecar["family"])
    summary = coerce_string(candidate.get("summary") or candidate.get("title") or candidate.get("description"), "Unspecified candidate finding.")
    files = files_from_item(candidate, sidecar)
    missing_guard = coerce_nullable_string(candidate.get("suspected_missing_guard") or candidate.get("missing_guard") or candidate.get("suspected_missing_control"))
    impact_boundary = coerce_nullable_string(candidate.get("impact_boundary") or candidate.get("impact") or summary)
    candidate["candidate_id"] = coerce_string(candidate.get("candidate_id") or candidate.get("id"), f"CAND-{owner}-{stable_hash([sidecar['sidecar_id'], summary, files])}")
    candidate["proposed_owner_family"] = owner
    candidate["severity"] = coerce_enum(candidate.get("severity"), SEVERITIES, "medium")
    candidate["confidence"] = coerce_enum(candidate.get("confidence"), CONFIDENCES, "speculative")
    candidate["summary"] = summary
    candidate["entrypoint"] = coerce_nullable_string(candidate.get("entrypoint"))
    candidate["impact_boundary"] = impact_boundary
    candidate["suspected_missing_guard"] = missing_guard
    candidate["blocker_to_confirmation"] = coerce_string(candidate.get("blocker_to_confirmation") or candidate.get("blocker"), "Needs owner-lane confirmation.")
    candidate["files"] = files
    candidate["evidence_refs"] = coerce_evidence_refs(candidate, files, "Lenient reducer imported candidate evidence.")
    candidate["report_refs"] = string_list(candidate.get("report_refs"))
    candidate["lead_source_refs"] = string_list(candidate.get("lead_source_refs"))
    candidate["candidate_dedupe_key"] = {
        "proposed_owner_family": owner,
        "summary": summary,
        "files": files,
        "suspected_missing_guard": missing_guard,
        "impact_boundary": impact_boundary,
    }
    return candidate


def coerce_incidental_lead(item: Any, sidecar: dict[str, Any], report_path: Path, warnings: list[str]) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        warn_lenient(warnings, f"{report_path}: skipped non-object incidental lead")
        return None
    lead = dict(item)
    files = files_from_item(lead, sidecar)
    summary = coerce_string(lead.get("summary") or lead.get("title") or lead.get("description"), "Unspecified incidental lead.")
    noticed_by = coerce_string(lead.get("noticed_by_family") or lead.get("source_family") or lead.get("family"), sidecar["family"])
    proposed_owner = coerce_string(lead.get("proposed_owner_family") or lead.get("owner_family") or lead.get("recommended_owner"), noticed_by)
    lead["lead_id"] = coerce_string(lead.get("lead_id") or lead.get("id"), f"LEAD-{noticed_by}-{stable_hash([sidecar['sidecar_id'], summary, files])}")
    lead["noticed_by_family"] = noticed_by
    lead["proposed_owner_family"] = proposed_owner
    lead["summary"] = summary
    lead["confidence"] = coerce_enum(lead.get("confidence"), CONFIDENCES, "speculative")
    lead["severity_hint"] = coerce_enum(lead.get("severity_hint") or lead.get("severity"), SEVERITIES, "medium")
    lead["why_noticed"] = coerce_nullable_string(lead.get("why_noticed"))
    lead["blocker_to_confirmation"] = coerce_string(lead.get("blocker_to_confirmation") or lead.get("blocker"), "Needs owner-lane confirmation.")
    lead["files"] = files
    lead["evidence_refs"] = coerce_evidence_refs(lead, files, "Lenient reducer imported incidental lead evidence.")
    return lead


def coerce_security_smell(item: Any, sidecar: dict[str, Any], report_path: Path, warnings: list[str]) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        warn_lenient(warnings, f"{report_path}: skipped non-object security smell")
        return None
    smell = dict(item)
    files = files_from_item(smell, sidecar)
    description = coerce_string(smell.get("description") or smell.get("summary"), "Unspecified security smell.")
    smell["smell_id"] = coerce_string(smell.get("smell_id") or smell.get("id"), f"SMELL-{stable_hash([sidecar['sidecar_id'], description, files])}")
    smell["category"] = coerce_string(smell.get("category") or smell.get("type"), "uncategorized")
    smell["path"] = coerce_string(smell.get("path") or (files[0] if files else None), "unknown")
    smell["line_start"] = coerce_int(smell.get("line_start") or smell.get("line"), 0) or None
    smell["description"] = description
    smell["recommended_owner"] = coerce_string(smell.get("recommended_owner") or smell.get("owner_family") or smell.get("source_family"), sidecar["family"])
    smell["status"] = coerce_enum(smell.get("status"), {"needs-triage", "promoted", "rejected"}, "needs-triage")
    return smell


def coerce_risk_signal(item: Any, sidecar: dict[str, Any], report_path: Path, warnings: list[str]) -> dict[str, Any] | None:
    signal = coerce_security_smell(item, sidecar, report_path, warnings)
    if signal is None:
        return None
    signal["signal_id"] = coerce_string(signal.pop("smell_id", None), f"RISK-{stable_hash([sidecar['sidecar_id'], signal.get('description')])}")
    return signal


def coerce_proof_update(item: Any, sidecar: dict[str, Any], report_path: Path, warnings: list[str]) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        warn_lenient(warnings, f"{report_path}: skipped non-object proof update")
        return None
    update = dict(item)
    update["subject_id"] = coerce_string(update.get("subject_id") or update.get("finding_id") or update.get("lead_id") or update.get("candidate_id"), f"unknown-{stable_hash([sidecar['sidecar_id'], update])}")
    update["proof_level"] = coerce_enum(update.get("proof_level"), PROOF_LEVELS, "P1-candidate")
    update["evidence_summary"] = coerce_string(update.get("evidence_summary") or update.get("summary"), "Lenient reducer imported proof update.")
    update["evidence_refs"] = coerce_evidence_refs(update, files_from_item(update, sidecar), "Lenient reducer imported proof evidence.")
    return update


def coerce_regression_recommendation(item: Any, sidecar: dict[str, Any], report_path: Path, warnings: list[str]) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        warn_lenient(warnings, f"{report_path}: skipped non-object regression recommendation")
        return None
    rec = dict(item)
    rec["finding_id"] = coerce_string(rec.get("finding_id") or rec.get("subject_id"), f"PF-{sidecar['family']}-{stable_hash([sidecar['sidecar_id'], rec])}")
    rec["recommended_regression"] = coerce_enum(rec.get("recommended_regression"), {
        "unit test",
        "integration test",
        "policy test",
        "configuration assertion",
        "custom static rule",
        "dependency/policy gate",
        "manual compensating control",
        "documented not-feasible reason",
    }, "integration test")
    rec["test_name"] = coerce_string(rec.get("test_name"), f"test_{stable_hash([rec['finding_id']])}")
    rec["guard_asserted"] = coerce_string(rec.get("guard_asserted"), "Preserve the missing security guard.")
    rec["automation_status"] = coerce_enum(rec.get("automation_status"), {"proposed", "implemented", "not-feasible"}, "proposed")
    return rec


def coerce_run_local_check(item: Any, sidecar: dict[str, Any], report_path: Path, warnings: list[str]) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        warn_lenient(warnings, f"{report_path}: skipped non-object run-local check")
        return None
    check = dict(item)
    raw_id = coerce_string(check.get("check_id") or check.get("id"), f"local.{stable_hash([sidecar['sidecar_id'], check])}")
    if not raw_id.startswith("local."):
        raw_id = f"local.{re.sub(r'[^a-z0-9.-]+', '-', raw_id.lower()).strip('-') or stable_hash([raw_id])}"
    check["check_id"] = raw_id
    check["reason"] = coerce_string(check.get("reason") or check.get("summary"), "Lenient reducer imported a run-local check.")
    check["trigger_evidence_refs"] = coerce_evidence_refs(check, files_from_item(check, sidecar), "Lenient reducer imported run-local check evidence.")
    check["extends_checks"] = string_list(check.get("extends_checks"))
    check["recommended_owner_family"] = coerce_nullable_string(check.get("recommended_owner_family") or check.get("recommended_owner"))
    check["scope_impact"] = coerce_string(check.get("scope_impact"), "Review scope may need owner-lane follow-up.")
    check["regression_impact"] = coerce_nullable_string(check.get("regression_impact"))
    return check


def coerce_sidecar_for_reduce(
    sidecar: dict[str, Any],
    report_path: Path,
    manifest: dict[str, Any] | None,
    item: dict[str, Any] | None,
    run_dir: Path,
    profile: str,
    selected_profile: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any]:
    coerced = coerce_top_level_sidecar(sidecar, report_path, manifest, item, run_dir, profile, selected_profile, warnings)
    coerced["confirmed_findings"] = [
        value for value in (coerce_confirmed_finding(raw, coerced, report_path, warnings) for raw in coerced.get("confirmed_findings", []))
        if value is not None
    ]
    coerced["candidate_findings"] = [
        value for value in (coerce_candidate_finding(raw, coerced, report_path, warnings) for raw in coerced.get("candidate_findings", []))
        if value is not None
    ]
    coerced["incidental_leads"] = [
        value for value in (coerce_incidental_lead(raw, coerced, report_path, warnings) for raw in coerced.get("incidental_leads", []))
        if value is not None
    ]
    coerced["security_smells"] = [
        value for value in (coerce_security_smell(raw, coerced, report_path, warnings) for raw in coerced.get("security_smells", []))
        if value is not None
    ]
    coerced["risk_signals"] = [
        value for value in (coerce_risk_signal(raw, coerced, report_path, warnings) for raw in coerced.get("risk_signals", []))
        if value is not None
    ]
    coerced["proof_updates"] = [
        value for value in (coerce_proof_update(raw, coerced, report_path, warnings) for raw in coerced.get("proof_updates", []))
        if value is not None
    ]
    coerced["regression_recommendations"] = [
        value for value in (coerce_regression_recommendation(raw, coerced, report_path, warnings) for raw in coerced.get("regression_recommendations", []))
        if value is not None
    ]
    coerced["run_local_checks"] = [
        value for value in (coerce_run_local_check(raw, coerced, report_path, warnings) for raw in coerced.get("run_local_checks", []))
        if value is not None
    ]
    return coerced


def root_cause_id(finding: dict[str, Any]) -> str:
    key = finding["dedupe_key"]
    if "bottleneck_class" in key:
        short = stable_hash([
            key["owner_family"],
            key["bottleneck_class"],
            key["resource_dimension"],
            key["root_cause_location"],
            key.get("workflow_id_or_entrypoint_id"),
            key["trigger_load_condition"],
            key["budget_dimension"],
            key["cardinality_driver"],
            key["impact_boundary"],
        ])
    elif "control_objective" in key:
        short = stable_hash([
            key["owner_family"],
            key["control_objective"],
            key.get("failure_mode"),
            key["missing_control"],
            key.get("affected_authoritative_state_or_commitment"),
            key["impact_boundary"],
        ])
    else:
        short = stable_hash([
            key["owner_family"],
            key["security_invariant"],
            key["missing_guard"],
            key["impact_boundary"],
        ])
    return f"RC-{key['owner_family']}-{short}"


def finding_id(finding: dict[str, Any], rc_id: str) -> str:
    key = finding["dedupe_key"]
    short = stable_hash([
        rc_id,
        key.get("workflow_id_or_entrypoint_id") or key.get("entrypoint") or finding.get("entrypoint") or finding.get("entrypoints", []),
        finding.get("files", []),
        key["impact_boundary"],
    ])
    return f"F-{key['owner_family']}-{short}"


def candidate_id(candidate: dict[str, Any]) -> str:
    key = candidate["candidate_dedupe_key"]
    if "bottleneck_class" in key:
        short = stable_hash([
            key["proposed_owner_family"],
            key["summary"],
            key["files"],
            key.get("bottleneck_class"),
            key.get("resource_dimension"),
            key.get("root_cause_location"),
            key.get("trigger_load_condition"),
            key.get("impact_boundary"),
        ])
    else:
        short = stable_hash([
            key["proposed_owner_family"],
            key["summary"],
            key["files"],
            key.get("suspected_missing_guard") or key.get("suspected_missing_control"),
            key.get("impact_boundary"),
        ])
    return f"C-{key['proposed_owner_family']}-{short}"


def event_id(event_type: str, batch_id: str | None, material: Any) -> str:
    short = stable_hash([event_type, batch_id, material])
    if batch_id:
        return f"EV-{event_type}-{batch_id}-{short}"
    return f"EV-{event_type}-{short}"


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    if path.is_symlink():
        raise SystemExit(f"refusing to read symlinked state file: {path}")
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def safe_read_jsonl(path: Path, warnings: list[str]) -> list[dict[str, Any]]:
    try:
        return read_jsonl(path)
    except Exception as exc:  # noqa: BLE001
        warn_lenient(warnings, f"{path}: could not read existing JSONL state: {exc}")
        return []


def schema_allowed_properties(schema_name: str) -> set[str]:
    if schema_name not in SCHEMA_ALLOWED_PROPERTIES:
        schema = validate_run.load_json(validate_run.DEFAULT_SCHEMAS_DIR / schema_name)
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            raise SystemExit(f"state schema {schema_name} does not declare object properties")
        SCHEMA_ALLOWED_PROPERTIES[schema_name] = set(properties)
    return SCHEMA_ALLOWED_PROPERTIES[schema_name]


def prune_rows_to_schema(rows: list[dict[str, Any]], schema_name: str) -> list[dict[str, Any]]:
    allowed = schema_allowed_properties(schema_name)
    pruned: list[dict[str, Any]] = []
    for row in rows:
        clean = {key: value for key, value in row.items() if key in allowed}
        if "schema_version" in allowed:
            clean["schema_version"] = STATE_SCHEMA_VERSION
        pruned.append(clean)
    return pruned


def repair_reducer_owned_state(run_dir: Path) -> None:
    state_dir = run_dir / "state"
    if not state_dir.exists():
        return
    if state_dir.is_symlink():
        return
    for filename, schema_name in sorted(REPAIRABLE_STATE_SCHEMAS.items()):
        path = state_dir / filename
        if not path.exists() or path.is_symlink():
            continue
        try:
            rows = read_jsonl(path)
        except Exception:  # noqa: BLE001
            continue
        if not all(isinstance(row, dict) for row in rows):
            continue
        repaired = prune_rows_to_schema(rows, schema_name)
        if repaired != rows:
            atomic_write_jsonl(path, repaired)


def secure_state_temp(path: Path) -> tuple[int, Path]:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise SystemExit(f"refusing to write through symlinked state directory: {path.parent}")
    try:
        path.parent.resolve()
    except (OSError, RuntimeError) as exc:
        raise SystemExit(f"could not resolve state directory: {exc}") from exc
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    return fd, Path(tmp_name)


def atomic_write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    fd, tmp = secure_state_temp(path)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")))
                handle.write("\n")
        os.replace(tmp, path)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise


def atomic_write_text(path: Path, text: str) -> None:
    fd, tmp = secure_state_temp(path)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(tmp, path)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise


def atomic_write_json(path: Path, value: Any) -> None:
    fd, tmp = secure_state_temp(path)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, indent=2)
            handle.write("\n")
        os.replace(tmp, path)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise


def ensure_state_dir(run_dir: Path) -> Path:
    state_dir = run_dir / "state"
    if state_dir.is_symlink():
        raise SystemExit("refusing to write through symlinked state directory")
    if state_dir.exists() and not state_dir.is_dir():
        raise SystemExit("state path exists but is not a directory")
    state_dir.mkdir(parents=True, exist_ok=True)
    try:
        state_dir.resolve().relative_to(run_dir.resolve())
    except ValueError as exc:
        raise SystemExit("state directory escapes run dir") from exc
    except (OSError, RuntimeError) as exc:
        raise SystemExit(f"could not resolve state directory: {exc}") from exc
    return state_dir


def ensure_reducer_dir(run_dir: Path) -> Path:
    reducer_dir = run_dir / "reducer"
    if reducer_dir.is_symlink():
        raise SystemExit("refusing to write through symlinked reducer directory")
    if reducer_dir.exists() and not reducer_dir.is_dir():
        raise SystemExit("reducer path exists but is not a directory")
    reducer_dir.mkdir(parents=True, exist_ok=True)
    try:
        reducer_dir.resolve().relative_to(run_dir.resolve())
    except ValueError as exc:
        raise SystemExit("reducer directory escapes run dir") from exc
    except (OSError, RuntimeError) as exc:
        raise SystemExit(f"could not resolve reducer directory: {exc}") from exc
    return reducer_dir


def snapshot_state_before_lenient_repair(run_dir: Path, warnings: list[str]) -> None:
    state_dir = run_dir / "state"
    if not state_dir.exists() or state_dir.is_symlink() or not state_dir.is_dir():
        return
    reducer_dir = ensure_reducer_dir(run_dir)
    snapshot_dir = reducer_dir / "raw-state-before-lenient"
    if snapshot_dir.is_symlink():
        raise SystemExit("refusing to write through symlinked lenient state snapshot directory")
    if snapshot_dir.exists():
        return
    snapshot_dir.mkdir()
    copied = 0
    for path in sorted(state_dir.iterdir()):
        if path.is_symlink() or not path.is_file():
            continue
        if path.suffix not in {".jsonl", ".yaml", ".yml", ".md"}:
            continue
        destination = snapshot_dir / path.name
        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=snapshot_dir)
        tmp = Path(tmp_name)
        try:
            with path.open("rb") as source, os.fdopen(fd, "wb") as handle:
                handle.write(source.read())
            os.replace(tmp, destination)
            copied += 1
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass
            raise
    if copied:
        warn_lenient(
            warnings,
            f"preserved {copied} pre-repair state file(s) in reducer/raw-state-before-lenient",
        )


def resolve_local_schema_ref(schema: dict[str, Any], root_schema: dict[str, Any]) -> dict[str, Any]:
    ref = schema.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/$defs/"):
        return schema
    name = ref.removeprefix("#/$defs/")
    resolved = root_schema.get("$defs", {}).get(name)
    return resolved if isinstance(resolved, dict) else schema


def prune_value_to_schema(value: Any, schema: dict[str, Any], root_schema: dict[str, Any]) -> Any:
    schema = resolve_local_schema_ref(schema, root_schema)
    if isinstance(value, dict):
        properties = schema.get("properties")
        if not isinstance(properties, dict):
            return value
        source_keys = properties if schema.get("additionalProperties") is False else value
        pruned: dict[str, Any] = {}
        for key in source_keys:
            if key not in value:
                continue
            child_schema = properties.get(key)
            pruned[key] = prune_value_to_schema(value[key], child_schema, root_schema) if isinstance(child_schema, dict) else value[key]
        return pruned
    if isinstance(value, list):
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            return [prune_value_to_schema(item, item_schema, root_schema) for item in value]
    return value


def sidecar_schema_for_profile(selected_profile: dict[str, Any]) -> dict[str, Any]:
    schema_name = selected_profile.get("report_sidecar_schema", "report-sidecar.schema.json")
    if not isinstance(schema_name, str) or not schema_name:
        schema_name = "report-sidecar.schema.json"
    return validate_run.load_json(validate_run.DEFAULT_SCHEMAS_DIR / schema_name)


def normalized_sidecar_for_write(sidecar: dict[str, Any], selected_profile: dict[str, Any]) -> dict[str, Any]:
    schema = sidecar_schema_for_profile(selected_profile)
    return prune_value_to_schema(sidecar, schema, schema)


def snapshot_sidecar_before_normalize(run_dir: Path, report_path: Path, warnings: list[str]) -> None:
    if not validate_run.is_plain_file_under(run_dir, report_path):
        raise SystemExit(f"refusing to snapshot sidecar outside run dir: {report_path}")
    reducer_dir = ensure_reducer_dir(run_dir)
    snapshot_root = reducer_dir / "raw-sidecars-before-normalize"
    if snapshot_root.is_symlink():
        raise SystemExit("refusing to write through symlinked sidecar snapshot directory")
    rel = report_path.resolve().relative_to(run_dir.resolve())
    destination = snapshot_root / rel
    if destination.exists():
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
    tmp = Path(tmp_name)
    try:
        with report_path.open("rb") as source, os.fdopen(fd, "wb") as handle:
            handle.write(source.read())
        os.replace(tmp, destination)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise
    warn_lenient(warnings, f"{report_path}: preserved original sidecar in reducer/raw-sidecars-before-normalize")


def unique_sorted(items: list[Any]) -> list[Any]:
    seen: dict[str, Any] = {}
    for item in items:
        seen[json.dumps(normalize_value(item), sort_keys=True, separators=(",", ":"))] = item
    return [seen[key] for key in sorted(seen)]


def load_manifests(run_dir: Path, batch_id: str | None) -> list[tuple[Path, dict[str, Any]]]:
    paths = validate_run.manifest_paths(run_dir, batch_id)
    manifests: list[tuple[Path, dict[str, Any]]] = []
    for path in paths:
        manifests.append((path, validate_run.load_json_or_yaml(path)))
    return manifests


def lenient_sidecar_paths(run_dir: Path, batch_id: str | None) -> list[Path]:
    paths = set(validate_run.sidecar_paths(run_dir, batch_id))
    if batch_id in {None, "batch-01"}:
        paths.update((run_dir / "reports").glob("*/report.json"))
    return sorted(paths)


def lenient_candidate_paths(run_dir: Path) -> list[Path]:
    candidates_dir = run_dir / "candidates"
    if not candidates_dir.exists() or candidates_dir.is_symlink():
        return []
    return sorted(candidates_dir.glob("*/*.yaml")) + sorted(candidates_dir.glob("*/*.yml")) + sorted(candidates_dir.glob("*/*.json"))


def parse_line_range(value: Any) -> tuple[int | None, int | None]:
    if isinstance(value, int) and not isinstance(value, bool):
        return value, value
    if not isinstance(value, str):
        return None, None
    text = value.strip()
    match = re.match(r"^([0-9]+)(?:\s*-\s*([0-9]+))?$", text)
    if not match:
        return None, None
    start = int(match.group(1))
    end = int(match.group(2)) if match.group(2) else start
    return start, end


def normalize_candidate_yaml_item(data: dict[str, Any], path: Path) -> dict[str, Any]:
    item = dict(data)
    location = item.get("location")
    if isinstance(location, dict):
        file_value = location.get("file") or location.get("path")
        if isinstance(file_value, str) and file_value:
            item.setdefault("files", [file_value])
            line_start, line_end = parse_line_range(location.get("lines") or location.get("line"))
            item.setdefault("evidence_refs", [{
                "path": file_value,
                "line_start": line_start,
                "line_end": line_end,
                "symbol": coerce_nullable_string(location.get("symbol")),
                "evidence_type": "other",
                "snippet_hash": None,
                "rationale": "Lane candidate location.",
            }])
    if "summary" not in item and "title" in item:
        item["summary"] = item["title"]
    if "family" not in item and "lane" in item:
        item["family"] = item["lane"]
    if "proposed_owner_family" not in item:
        item["proposed_owner_family"] = item.get("owner_family") or item.get("family") or item.get("lane")
    if "candidate_id" not in item and "id" in item:
        item["candidate_id"] = item["id"]
    if "blocker_to_confirmation" not in item:
        item["blocker_to_confirmation"] = "Imported from lane candidate YAML; owner-lane confirmation may still be needed."
    if "impact_boundary" not in item and "impact" in item:
        item["impact_boundary"] = item["impact"]
    return item


def sidecar_from_candidate_file(
    path: Path,
    run_dir: Path,
    profile: str,
    selected_profile: dict[str, Any],
    warnings: list[str],
) -> dict[str, Any] | None:
    try:
        data = validate_run.load_json_or_yaml(path)
    except Exception as exc:  # noqa: BLE001
        warn_lenient(warnings, f"{path}: could not parse candidate file: {exc}")
        return None
    if not isinstance(data, dict):
        warn_lenient(warnings, f"{path}: skipped non-object candidate file")
        return None

    batch_id, family_from_path = infer_batch_family_from_report_path(run_dir, path)
    family = coerce_string(data.get("family") or data.get("lane") or data.get("proposed_owner_family") or family_from_path, selected_profile["lane_order"][0])
    item = normalize_candidate_yaml_item(data, path)
    status = normalize_text(item.get("status")).lower().replace("_", "-")
    collection = "confirmed_findings" if status in CONFIRMED_STATUSES else "candidate_findings"
    return {
        "schema_version": 3,
        "sidecar_id": f"sidecar-{batch_id or 'batch-01'}-{family}-{path.stem}",
        "generated_at": LENIENT_DEFAULT_GENERATED_AT,
        "run_id": run_dir.name,
        "batch_id": batch_id or "batch-01",
        "family": family,
        "mode": default_mode_for_batch(batch_id or "batch-01", family, selected_profile),
        "profile": profile,
        "strategy": coerce_string(
            item.get("strategy"),
            "invariant-audit" if profile == "security" else ("static-capacity-sweep" if profile == "performance" else "production-gate"),
        ),
        "overlays": string_list(item.get("overlays") or item.get("overlays_relevant")) or ["auto"],
        "baseline_commit": None,
        "reviewed_artifacts": files_from_item(item),
        "reviewed_files_routes_helpers": [],
        "shared_context_inputs": [],
        "coverage_units_touched": [],
        "coverage_units_not_touched": [],
        "patterns_searched": [],
        "intentionally_excluded": [],
        "confirmed_findings": [item] if collection == "confirmed_findings" else [],
        "candidate_findings": [item] if collection == "candidate_findings" else [],
        "rejected_claims": [],
        "clone_maps": [],
        "runtime_updates": [],
        "chain_candidates": [],
        "coverage_gaps": [],
        "profile_feedback": [],
        "incidental_leads": [],
        "security_smells": [],
        "proof_updates": [],
        "regression_recommendations": [],
        "run_local_checks": [],
        "next_batch_recommendations": [],
    }


def lenient_input_hashes(run_dir: Path, batch_id: str | None) -> list[dict[str, str]]:
    paths = set(validate_run.manifest_paths(run_dir, batch_id))
    paths.update(lenient_sidecar_paths(run_dir, batch_id))
    if batch_id in {None, "batch-01"}:
        paths.update(lenient_candidate_paths(run_dir))
    hashed: list[dict[str, str]] = []
    for path in sorted(paths):
        if validate_run.is_plain_file_under(run_dir, path):
            hashed.append({"path": path.relative_to(run_dir).as_posix(), "sha256": validate_run.hash_file(path)})
    return hashed


def collect_report_inputs(
    run_dir: Path,
    batch_id: str | None,
    profile: str,
    selected_profile: dict[str, Any],
    lenient: bool,
    warnings: list[str],
) -> list[tuple[Path, dict[str, Any], dict[str, Any], Path, dict[str, Any] | None]]:
    inputs: list[tuple[Path, dict[str, Any], dict[str, Any], Path, dict[str, Any] | None]] = []
    seen_reports: set[Path] = set()
    try:
        manifests = load_manifests(run_dir, batch_id)
    except Exception as exc:  # noqa: BLE001
        if not lenient:
            raise
        warn_lenient(warnings, f"could not load batch manifests; reducing discovered report files instead: {exc}")
        manifests = []
    for manifest_path, manifest in manifests:
        if not isinstance(manifest, dict):
            warn_lenient(warnings, f"{manifest_path}: skipped non-object manifest")
            continue
        for item in manifest.get("families", []):
            if not isinstance(item, dict):
                continue
            if item.get("status") != "ran" or not isinstance(item.get("json"), str):
                inputs.append((manifest_path, manifest, item, manifest_path, None))
                continue
            try:
                report_path = resolve_report_path(run_dir, manifest_path, item["json"])
            except Exception as exc:  # noqa: BLE001
                warn_lenient(warnings, f"{manifest_path}: could not resolve report path {item.get('json')!r}: {exc}")
                continue
            seen_reports.add(report_path)
            inputs.append((manifest_path, manifest, item, report_path, None))

    if not lenient:
        return inputs

    sidecar_paths = lenient_sidecar_paths(run_dir, batch_id)
    if sidecar_paths and not manifests:
        warn_lenient(warnings, "no batch manifests found; synthesized reducer inputs from report.json files")
    for report_path in sidecar_paths:
        if report_path in seen_reports:
            continue
        try:
            sidecar = validate_run.load_json(report_path)
        except Exception as exc:  # noqa: BLE001
            warn_lenient(warnings, f"{report_path}: could not parse sidecar JSON: {exc}")
            continue
        if not isinstance(sidecar, dict):
            warn_lenient(warnings, f"{report_path}: skipped non-object sidecar")
            continue
        path_batch, path_family = infer_batch_family_from_report_path(run_dir, report_path)
        current_batch = coerce_string(sidecar.get("batch_id") or path_batch, "batch-01")
        if batch_id is not None and current_batch != batch_id:
            continue
        family = coerce_string(sidecar.get("family") or path_family, selected_profile["lane_order"][0])
        mode = coerce_string(sidecar.get("mode"), default_mode_for_batch(current_batch, family, selected_profile))
        manifest = {
            "schema_version": 1,
            "run_id": run_dir.name,
            "batch_id": current_batch,
            "generated_at": coerce_string(sidecar.get("generated_at"), LENIENT_DEFAULT_GENERATED_AT),
            "producer": "reduce_run.py --lenient",
            "manifest_status": "completed",
            "expected_families": [family],
            "families": [],
        }
        item = {
            "family": family,
            "status": "ran",
            "mode": mode,
            "json": report_path.relative_to(run_dir).as_posix(),
        }
        inputs.append((run_dir / "reports" / current_batch / "manifest.yaml", manifest, item, report_path, sidecar))

    if batch_id in {None, "batch-01"}:
        for candidate_path in lenient_candidate_paths(run_dir):
            sidecar = sidecar_from_candidate_file(candidate_path, run_dir, profile, selected_profile, warnings)
            if sidecar is None:
                continue
            family = sidecar["family"]
            current_batch = sidecar["batch_id"]
            manifest = {
                "schema_version": 1,
                "run_id": run_dir.name,
                "batch_id": current_batch,
                "generated_at": sidecar["generated_at"],
                "producer": "reduce_run.py --lenient",
                "manifest_status": "completed",
                "expected_families": [family],
                "families": [],
            }
            item = {
                "family": family,
                "status": "ran",
                "mode": sidecar["mode"],
                "json": candidate_path.relative_to(run_dir).as_posix(),
            }
            inputs.append((run_dir / "reports" / current_batch / "manifest.yaml", manifest, item, candidate_path, sidecar))

    return inputs


def resolve_report_path(run_dir: Path, manifest_path: Path, value: str) -> Path:
    return validate_run.resolve_run_path(run_dir, value, manifest_path.parent)


def source_report(batch_id: str, family: str, report_json: Path, local_id: str) -> dict[str, str]:
    return {
        "batch_id": batch_id,
        "family": family,
        "report_json": report_json.as_posix(),
        "local_id": local_id,
    }


def confirmed_record(sidecar: dict[str, Any], finding: dict[str, Any], report_path: Path) -> dict[str, Any]:
    rc_id = root_cause_id(finding)
    f_id = finding_id(finding, rc_id)
    batch_id = sidecar["batch_id"]
    family = sidecar["family"]
    entrypoint = finding.get("entrypoint")
    if entrypoint is None and isinstance(finding.get("entrypoints"), list):
        entrypoint = ", ".join(str(item) for item in finding.get("entrypoints", []))
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "finding_id": f_id,
        "root_cause_id": rc_id,
        "id_policy_version": ID_POLICY_VERSION,
        "dedupe_key": finding["dedupe_key"],
        "provisional_ids": [finding["provisional_finding_id"]],
        "source_reports": [source_report(batch_id, family, report_path, finding["provisional_finding_id"])],
        "record_created_at": sidecar["generated_at"],
        "record_updated_at": sidecar["generated_at"],
        "owner_family": finding["owner_family"],
        "status": finding["status"],
        "severity": finding["severity"],
        "confidence": finding["confidence"],
        "first_seen_batch": batch_id,
        "last_touched_batch": batch_id,
        "summary": finding["summary"],
        "entrypoint": entrypoint,
        "entrypoints": finding.get("entrypoints", []),
        "workflow_id": finding.get("workflow_id"),
        "invariant_id": finding.get("invariant_id"),
        "security_invariant": finding.get("security_invariant"),
        "control_objective": finding.get("control_objective"),
        "attacker_precondition": finding.get("attacker_precondition"),
        "trigger_condition": finding.get("trigger_condition"),
        "failure_mode": finding.get("failure_mode"),
        "introduced_after_batch_01": finding["introduced_after_batch_01"],
        "duplicate_of": None,
        "clone_of": finding.get("clone_of"),
        "related_findings": finding.get("related_findings", []),
        "files": finding.get("files", []),
        "evidence_refs": finding.get("evidence_refs", []),
        "report_refs": finding.get("report_refs", []),
        "lead_source_refs": finding.get("lead_source_refs", []),
        "widespread_pattern": False,
        "estimated_clone_count": None,
        "missing_guard": finding.get("missing_guard"),
        "missing_control": finding.get("missing_control"),
        "affected_authoritative_state": finding.get("affected_authoritative_state"),
        "affected_side_effects": finding.get("affected_side_effects", []),
        "impact_boundary": finding["impact_boundary"],
        "detectability": finding.get("detectability"),
        "recoverability": finding.get("recoverability"),
        "launch_gate_effect": finding.get("launch_gate_effect"),
        "entrypoint_id": finding.get("entrypoint_id"),
        "budget_id": finding.get("budget_id"),
        "budget_dimension": finding.get("budget_dimension"),
        "bottleneck_class": finding.get("bottleneck_class"),
        "resource_dimension": finding.get("resource_dimension"),
        "root_cause_location": finding.get("root_cause_location"),
        "trigger_load_condition": finding.get("trigger_load_condition"),
        "demand_assumption": finding.get("demand_assumption"),
        "cardinality_driver": finding.get("cardinality_driver"),
        "growth_model": finding.get("growth_model"),
        "amplification_factor": finding.get("amplification_factor"),
        "impacted_budget": finding.get("impacted_budget"),
        "affected_users_or_tenants": finding.get("affected_users_or_tenants"),
        "degradation_behavior": finding.get("degradation_behavior"),
        "proof_level": finding.get("proof_level"),
        "existing_controls_checked": finding.get("existing_controls_checked", []),
        "recommended_regression": finding.get("recommended_regression"),
        "severity_rationale": finding["severity_rationale"],
        "candidate_blocker": None,
        "runtime_status": None,
    }


def candidate_record(sidecar: dict[str, Any], candidate: dict[str, Any], report_path: Path) -> dict[str, Any]:
    c_id = candidate_id(candidate)
    batch_id = sidecar["batch_id"]
    family = sidecar["family"]
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "finding_id": c_id,
        "root_cause_id": None,
        "id_policy_version": ID_POLICY_VERSION,
        "dedupe_key": candidate["candidate_dedupe_key"],
        "provisional_ids": [candidate["candidate_id"]],
        "source_reports": [source_report(batch_id, family, report_path, candidate["candidate_id"])],
        "record_created_at": sidecar["generated_at"],
        "record_updated_at": sidecar["generated_at"],
        "owner_family": candidate["proposed_owner_family"],
        "status": "candidate",
        "severity": candidate["severity"],
        "confidence": candidate["confidence"],
        "first_seen_batch": batch_id,
        "last_touched_batch": batch_id,
        "summary": candidate["summary"],
        "entrypoint": candidate.get("entrypoint"),
        "entrypoints": candidate.get("entrypoints", []),
        "workflow_id": candidate.get("workflow_id"),
        "invariant_id": candidate.get("invariant_id"),
        "security_invariant": None,
        "control_objective": candidate.get("control_objective"),
        "attacker_precondition": None,
        "trigger_condition": candidate.get("trigger_condition"),
        "failure_mode": candidate.get("failure_mode"),
        "introduced_after_batch_01": batch_id != "batch-01",
        "duplicate_of": None,
        "clone_of": None,
        "related_findings": [],
        "files": candidate.get("files", []),
        "evidence_refs": candidate.get("evidence_refs", []),
        "report_refs": candidate.get("report_refs", []),
        "lead_source_refs": candidate.get("lead_source_refs", []),
        "widespread_pattern": False,
        "estimated_clone_count": None,
        "missing_guard": candidate.get("suspected_missing_guard") or "",
        "missing_control": candidate.get("suspected_missing_control") or "",
        "impact_boundary": candidate.get("impact_boundary") or "",
        "detectability": candidate.get("detectability"),
        "recoverability": candidate.get("recoverability"),
        "launch_gate_effect": candidate.get("launch_gate_effect"),
        "entrypoint_id": candidate.get("entrypoint_id"),
        "budget_id": candidate.get("budget_id"),
        "budget_dimension": candidate.get("budget_dimension"),
        "bottleneck_class": candidate.get("bottleneck_class"),
        "resource_dimension": candidate.get("resource_dimension"),
        "root_cause_location": candidate.get("root_cause_location"),
        "trigger_load_condition": candidate.get("trigger_load_condition"),
        "demand_assumption": candidate.get("demand_assumption"),
        "cardinality_driver": candidate.get("cardinality_driver"),
        "impacted_budget": candidate.get("impacted_budget"),
        "proof_level": candidate.get("proof_level"),
        "severity_rationale": None,
        "candidate_blocker": candidate["blocker_to_confirmation"],
        "runtime_status": None,
    }


def incidental_lead_record(sidecar: dict[str, Any], lead: dict[str, Any], report_path: Path) -> dict[str, Any]:
    batch_id = sidecar["batch_id"]
    family = sidecar["family"]
    files = files_from_item(lead, sidecar)
    summary = coerce_string(lead.get("summary") or lead.get("title") or lead.get("description"), "Unspecified incidental lead.")
    noticed_by = coerce_string(lead.get("noticed_by_family") or lead.get("source_family") or lead.get("family"), family)
    proposed_owner = coerce_string(
        lead.get("proposed_owner_family") or lead.get("owner_family") or lead.get("recommended_owner"),
        noticed_by,
    )
    lead_id = coerce_string(
        lead.get("lead_id") or lead.get("id"),
        f"LEAD-{noticed_by}-{stable_hash([sidecar.get('sidecar_id'), summary, files])}",
    )
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "lead_id": lead_id,
        "noticed_by_family": noticed_by,
        "proposed_owner_family": proposed_owner,
        "source_reports": [source_report(batch_id, family, report_path, lead_id)],
        "first_seen_batch": batch_id,
        "last_touched_batch": batch_id,
        "severity_hint": coerce_enum(lead.get("severity_hint") or lead.get("severity"), SEVERITIES, "medium"),
        "confidence": coerce_enum(lead.get("confidence"), CONFIDENCES, "speculative"),
        "summary": summary,
        "why_noticed": lead.get("why_noticed"),
        "blocker_to_confirmation": coerce_string(
            lead.get("blocker_to_confirmation") or lead.get("blocker"),
            "Needs owner-lane confirmation.",
        ),
        "files": files,
        "evidence_refs": coerce_evidence_refs(lead, files, "Reducer imported incidental lead evidence."),
        "status": "needs-triage",
    }


def security_smell_record(sidecar: dict[str, Any], smell: dict[str, Any], report_path: Path) -> dict[str, Any]:
    batch_id = sidecar["batch_id"]
    family = sidecar["family"]
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "smell_id": smell["smell_id"],
        "category": smell["category"],
        "source_family": family,
        "source_reports": [source_report(batch_id, family, report_path, smell["smell_id"])],
        "first_seen_batch": batch_id,
        "last_touched_batch": batch_id,
        "path": smell["path"],
        "line_start": smell.get("line_start"),
        "description": smell["description"],
        "recommended_owner": smell["recommended_owner"],
        "status": smell["status"],
    }


def risk_signal_record(sidecar: dict[str, Any], signal: dict[str, Any], report_path: Path) -> dict[str, Any]:
    batch_id = sidecar["batch_id"]
    family = sidecar["family"]
    files = files_from_item(signal, sidecar)
    description = coerce_string(
        signal.get("description") or signal.get("summary") or signal.get("title"),
        "Unspecified risk signal.",
    )
    signal_id = coerce_string(
        signal.get("signal_id") or signal.get("risk_id") or signal.get("id"),
        f"RISK-{stable_hash([sidecar.get('sidecar_id'), description, files])}",
    )
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "signal_id": signal_id,
        "category": coerce_string(signal.get("category") or signal.get("risk_type"), "general"),
        "source_family": family,
        "source_reports": [source_report(batch_id, family, report_path, signal_id)],
        "first_seen_batch": batch_id,
        "last_touched_batch": batch_id,
        "path": coerce_string(signal.get("path") or (files[0] if files else None), "unknown"),
        "line_start": coerce_int(signal.get("line_start") or signal.get("line"), 0) or None,
        "description": description,
        "recommended_owner": coerce_string(
            signal.get("recommended_owner")
            or signal.get("owner_family_hint")
            or signal.get("owner_family")
            or signal.get("source_family"),
            family,
        ),
        "status": coerce_enum(signal.get("status"), {"needs-triage", "promoted", "rejected"}, "needs-triage"),
    }


def proof_update_record(sidecar: dict[str, Any], update: dict[str, Any], report_path: Path) -> dict[str, Any]:
    batch_id = sidecar["batch_id"]
    family = sidecar["family"]
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "subject_id": update["subject_id"],
        "proof_level": update["proof_level"],
        "source_family": family,
        "source_reports": [source_report(batch_id, family, report_path, update["subject_id"])],
        "last_touched_batch": batch_id,
        "evidence_summary": update["evidence_summary"],
        "runtime_validation": update.get("runtime_validation"),
        "regression_status": update.get("regression_status"),
        "evidence_refs": update.get("evidence_refs", []),
    }


def regression_recommendation_id(recommendation: dict[str, Any]) -> str:
    short = stable_hash([
        recommendation["finding_id"],
        recommendation["recommended_regression"],
        recommendation["test_name"],
        recommendation["guard_asserted"],
    ])
    return f"REG-{short}"


def regression_record_id(record: dict[str, Any]) -> str:
    return regression_recommendation_id(record)


def regression_recommendation_record(sidecar: dict[str, Any], recommendation: dict[str, Any], report_path: Path) -> dict[str, Any]:
    batch_id = sidecar["batch_id"]
    family = sidecar["family"]
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "regression_id": regression_recommendation_id(recommendation),
        "finding_id": recommendation["finding_id"],
        "source_family": family,
        "source_reports": [source_report(batch_id, family, report_path, recommendation["finding_id"])],
        "last_touched_batch": batch_id,
        "recommended_regression": recommendation["recommended_regression"],
        "test_name": recommendation["test_name"],
        "guard_asserted": recommendation["guard_asserted"],
        "automation_status": recommendation["automation_status"],
        "owner_hint": recommendation.get("owner_hint"),
    }


def runtime_update_record(sidecar: dict[str, Any], update: dict[str, Any], report_path: Path) -> dict[str, Any]:
    batch_id = sidecar["batch_id"]
    family = sidecar["family"]
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "finding_id": update["finding_id"],
        "source_family": family,
        "source_reports": [source_report(batch_id, family, report_path, update["finding_id"])],
        "last_touched_batch": batch_id,
        "runtime_status": update["runtime_status"],
        "request_posture": update["request_posture"],
        "result": update["result"],
        "evidence_refs": update.get("evidence_refs", []),
    }


def run_local_check_record(sidecar: dict[str, Any], local_check: dict[str, Any], report_path: Path) -> dict[str, Any]:
    batch_id = sidecar["batch_id"]
    family = sidecar["family"]
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "check_id": local_check["check_id"],
        "source_family": family,
        "recommended_owner_family": local_check.get("recommended_owner_family"),
        "source_reports": [source_report(batch_id, family, report_path, local_check["check_id"])],
        "first_seen_batch": batch_id,
        "last_touched_batch": batch_id,
        "reason": local_check["reason"],
        "trigger_evidence_refs": local_check.get("trigger_evidence_refs", []),
        "extends_checks": local_check.get("extends_checks", []),
        "scope_impact": local_check["scope_impact"],
        "regression_impact": local_check.get("regression_impact"),
        "status": "active",
    }


def scalar_strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, bool):
        return ["true" if value else "false"]
    if isinstance(value, (int, float)):
        return [str(value)]
    if isinstance(value, list):
        values: list[str] = []
        for item in value:
            values.extend(scalar_strings(item))
        return values
    if isinstance(value, dict):
        values = []
        for item in value.values():
            values.extend(scalar_strings(item))
        return values
    return [str(value)]


def evidence_refs_from_item(item: dict[str, Any]) -> list[dict[str, Any]]:
    refs = item.get("evidence_refs", item.get("trigger_evidence_refs", []))
    return refs if isinstance(refs, list) else []


def paths_from_item(item: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    files = item.get("files")
    if isinstance(files, list):
        paths.extend(path for path in files if isinstance(path, str))
    path = item.get("path")
    if isinstance(path, str):
        paths.append(path)
    for ref in evidence_refs_from_item(item):
        if isinstance(ref, dict) and isinstance(ref.get("path"), str):
            paths.append(ref["path"])
    return unique_sorted(paths)


def source_id_for_item(kind: str, item: dict[str, Any]) -> str:
    for field in (
        "provisional_finding_id",
        "candidate_id",
        "lead_id",
        "smell_id",
        "signal_id",
        "check_id",
        "surface_id",
        "matrix_id",
        "invariant_id",
    ):
        value = item.get(field)
        if isinstance(value, str) and value:
            return value
    return f"{kind}-{stable_hash([item])}"


def signal_from_item(kind: str, sidecar: dict[str, Any] | None, item: dict[str, Any]) -> dict[str, Any]:
    refs = evidence_refs_from_item(item)
    evidence_types = {
        ref["evidence_type"]
        for ref in refs
        if isinstance(ref, dict) and isinstance(ref.get("evidence_type"), str)
    }
    paths = paths_from_item(item)
    searchable_refs = [
        {
            "path": ref.get("path"),
            "symbol": ref.get("symbol"),
            "evidence_type": ref.get("evidence_type"),
        }
        for ref in refs
        if isinstance(ref, dict)
    ]
    text_parts = scalar_strings({
        "kind": kind,
        "summary": item.get("summary") if kind in {"incidental-lead", "security-smell"} else None,
        "control_objective": item.get("control_objective"),
        "trigger_condition": item.get("trigger_condition"),
        "failure_mode": item.get("failure_mode"),
        "missing_control": item.get("missing_control"),
        "affected_authoritative_state": item.get("affected_authoritative_state"),
        "affected_side_effects": item.get("affected_side_effects"),
        "reason": item.get("reason"),
        "description": item.get("description"),
        "scope_impact": item.get("scope_impact"),
        "regression_impact": item.get("regression_impact"),
        "entrypoint": item.get("entrypoint"),
        "category": item.get("category"),
        "assets": item.get("assets"),
        "actions": item.get("actions"),
        "guards": item.get("guards"),
        "trust_boundaries": item.get("trust_boundaries"),
        "principal_types": item.get("principal_types"),
        "paths": paths,
        "evidence_refs": searchable_refs,
    })
    return {
        "source_id": source_id_for_item(kind, item),
        "source_kind": kind,
        "family": sidecar.get("family") if sidecar else item.get("owner_family") or item.get("recommended_owner") or item.get("proposed_owner_family"),
        "text": " ".join(text_parts).lower(),
        "paths": paths,
        "evidence_types": evidence_types,
        "priority_targets": paths,
    }


def sidecar_signals(sidecar: dict[str, Any]) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    for collection, kind in (
        ("confirmed_findings", "confirmed-finding"),
        ("candidate_findings", "candidate-finding"),
        ("incidental_leads", "incidental-lead"),
        ("security_smells", "security-smell"),
        ("risk_signals", "risk-signal"),
        ("run_local_checks", "run-local-check"),
    ):
        for item in sidecar.get(collection, []):
            if isinstance(item, dict):
                signals.append(signal_from_item(kind, sidecar, item))
    return signals


def state_surface_signals(state_dir: Path) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    for filename, kind in (
        ("attack-surface-inventory.jsonl", "attack-surface-inventory"),
        ("attack-surface-graph.jsonl", "attack-surface-graph"),
        ("authorization-matrix.jsonl", "authorization-matrix"),
        ("security-invariants.jsonl", "security-invariant"),
        ("risk-signals.jsonl", "risk-signal"),
    ):
        for row in read_jsonl(state_dir / filename):
            signals.append(signal_from_item(kind, None, row))
    return signals


def trigger_matches_signal(trigger: dict[str, Any], signal: dict[str, Any]) -> bool:
    when = trigger.get("when", {})
    if not isinstance(when, dict):
        return False

    evidence_type = when.get("evidence_type")
    if isinstance(evidence_type, str) and evidence_type not in signal.get("evidence_types", set()):
        return False

    patterns = when.get("patterns", [])
    if isinstance(patterns, list) and patterns:
        text = signal.get("text", "")
        if not any(isinstance(pattern, str) and pattern.lower() in text for pattern in patterns):
            return False

    path_patterns = when.get("paths", [])
    if isinstance(path_patterns, list) and path_patterns:
        paths = signal.get("paths", [])
        if not any(
            isinstance(pattern, str)
            and any(fnmatch.fnmatch(path, pattern) or path == pattern for path in paths)
            for pattern in path_patterns
        ):
            return False

    return bool(evidence_type or patterns or path_patterns)


def profile_mode(selected_profile: dict[str, Any], preferred: str, fallback: str) -> str:
    for strategy in selected_profile.get("strategies", {}).values():
        modes = strategy.get("allowed_modes", set())
        if preferred in modes:
            return preferred
    return fallback


def directive_mode_for_source(source_kind: str, selected_profile: dict[str, Any]) -> str:
    if source_kind in {"confirmed-finding", "candidate-finding"}:
        return profile_mode(selected_profile, "control-clonehunt", "clonehunt")
    return profile_mode(selected_profile, "invariant-gap-fill", "canonical-gap-fill")


def add_directive(
    directives: dict[str, dict[str, Any]],
    family: str,
    next_mode: str,
    reason: str,
    priority_targets: list[str],
    source_id: str,
) -> None:
    existing = directives.get(family)
    if existing is None:
        directives[family] = {
            "family": family,
            "next_mode": next_mode,
            "reason": reason,
            "priority_targets": unique_sorted(priority_targets),
            "source_ids": [source_id],
        }
        return

    if existing["next_mode"] != "canonical-gap-fill" and next_mode == "canonical-gap-fill":
        existing["next_mode"] = next_mode
    existing["reason"] = "; ".join(unique_sorted([existing["reason"], reason]))
    existing["priority_targets"] = unique_sorted(existing.get("priority_targets", []) + priority_targets)
    existing["source_ids"] = unique_sorted(existing.get("source_ids", []) + [source_id])


def build_family_directives(
    selected_profile: dict[str, Any],
    incidental_lead_rows: list[dict[str, Any]],
    run_local_check_rows: list[dict[str, Any]],
    signals: list[dict[str, Any]],
    source_batches: set[str],
    events: list[dict[str, Any]],
    input_hashes: list[dict[str, str]],
) -> list[dict[str, Any]]:
    lanes = selected_profile["lanes"]
    directives: dict[str, dict[str, Any]] = {}

    for lead in incidental_lead_rows:
        family = lead.get("proposed_owner_family")
        if not isinstance(family, str) or family not in lanes:
            continue
        add_directive(
            directives,
            family,
            profile_mode(selected_profile, "invariant-gap-fill", "canonical-gap-fill"),
            f"Triaging incidental lead {lead.get('lead_id')}: {lead.get('summary')}",
            lead.get("files", []),
            lead.get("lead_id", "unknown-lead"),
        )

    for local_check in run_local_check_rows:
        family = local_check.get("recommended_owner_family") or local_check.get("source_family")
        if not isinstance(family, str) or family not in lanes:
            continue
        targets = paths_from_item(local_check)
        add_directive(
            directives,
            family,
            profile_mode(selected_profile, "invariant-gap-fill", "canonical-gap-fill"),
            f"Run-local check {local_check.get('check_id')}: {local_check.get('scope_impact')}",
            targets,
            local_check.get("check_id", "unknown-local-check"),
        )

    for trigger in selected_profile.get("cross_lane_triggers", []):
        notify = trigger.get("notify", [])
        for signal in signals:
            if not trigger_matches_signal(trigger, signal):
                continue
            source_id = signal["source_id"]
            for family in notify:
                if family not in lanes:
                    continue
                add_directive(
                    directives,
                    family,
                    directive_mode_for_source(signal["source_kind"], selected_profile),
                    f"Cross-lane trigger {trigger['id']} matched {signal['source_kind']} {source_id}.",
                    signal.get("priority_targets", []),
                    source_id,
                )
                events.append(make_event(
                    "cross-lane-trigger-matched",
                    ",".join(sorted(source_batches)) if source_batches else None,
                    family,
                    "info",
                    f"Trigger {trigger['id']} matched {signal['source_kind']} {source_id}.",
                    input_hashes,
                ))

    return [directives[family] for family in sorted(directives)]


def yaml_quote(value: Any) -> str:
    text = "" if value is None else str(value)
    return json.dumps(text)


def family_directives_yaml(directives: list[dict[str, Any]], source_batches: set[str]) -> str:
    lines = [
        "schema_version: 1",
        "generated_by: reduce_run.py",
    ]
    if source_batches:
        lines.append("source_batches:")
        for batch in sorted(source_batches):
            lines.append(f"  - {yaml_quote(batch)}")
    else:
        lines.append("source_batches: []")
    if directives:
        lines.append("directives:")
    else:
        lines.append("directives: []")
    for directive in directives:
        lines.append(f"  - family: {yaml_quote(directive['family'])}")
        lines.append(f"    next_mode: {yaml_quote(directive['next_mode'])}")
        lines.append(f"    reason: {yaml_quote(directive['reason'])}")
        targets = directive.get("priority_targets", [])
        if targets:
            lines.append("    priority_targets:")
            for target in targets:
                lines.append(f"      - {yaml_quote(target)}")
        else:
            lines.append("    priority_targets: []")
        lines.append("    source_ids:")
        for source_id in directive.get("source_ids", []):
            lines.append(f"      - {yaml_quote(source_id)}")
    return "\n".join(lines) + "\n"


def choose_better_record(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    old_status = existing.get("status", "")
    new_status = incoming.get("status", "")
    if old_status != new_status and transition_allowed(old_status, new_status):
        base, other = incoming, existing
    elif SEVERITY_RANK.get(incoming["severity"], 0) > SEVERITY_RANK.get(existing["severity"], 0):
        base, other = incoming, existing
    else:
        base, other = existing, incoming

    merged = dict(base)
    merged["provisional_ids"] = unique_sorted(base.get("provisional_ids", []) + other.get("provisional_ids", []))
    merged["source_reports"] = unique_sorted(base.get("source_reports", []) + other.get("source_reports", []))
    merged["files"] = unique_sorted(base.get("files", []) + other.get("files", []))
    merged["evidence_refs"] = unique_sorted(base.get("evidence_refs", []) + other.get("evidence_refs", []))
    merged["report_refs"] = unique_sorted(base.get("report_refs", []) + other.get("report_refs", []))
    merged["lead_source_refs"] = unique_sorted(base.get("lead_source_refs", []) + other.get("lead_source_refs", []))
    merged["first_seen_batch"] = min(base["first_seen_batch"], other["first_seen_batch"])
    merged["last_touched_batch"] = max(base["last_touched_batch"], other["last_touched_batch"])
    merged["record_created_at"] = min(base["record_created_at"], other["record_created_at"])
    merged["record_updated_at"] = max(base["record_updated_at"], other["record_updated_at"])
    return merged


def merge_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for record in records:
        key = record["finding_id"]
        if key in by_id:
            by_id[key] = choose_better_record(by_id[key], record)
        else:
            by_id[key] = record
    return [by_id[key] for key in sorted(by_id)]


def inventory_key(record: dict[str, Any]) -> str | None:
    for key in ("finding_id", "lead_id"):
        value = record.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def merge_inventory(existing: list[dict[str, Any]], incoming: list[dict[str, Any]]) -> list[dict[str, Any]]:
    keyed: dict[str, dict[str, Any]] = {}
    unkeyed: list[dict[str, Any]] = []

    for record in existing:
        key = inventory_key(record)
        if key is None:
            unkeyed.append(record)
        else:
            keyed[key] = record

    for record in incoming:
        key = inventory_key(record)
        if key is None:
            unkeyed.append(record)
        elif key in keyed and "finding_id" in keyed[key] and "finding_id" in record:
            keyed[key] = choose_better_record(keyed[key], record)
        else:
            keyed[key] = record

    sorted_keyed = [keyed[key] for key in sorted(keyed)]
    sorted_unkeyed = sorted(unkeyed, key=lambda row: json.dumps(normalize_value(row), sort_keys=True, separators=(",", ":")))
    return sorted_keyed + sorted_unkeyed


def transition_allowed(old_status: str, new_status: str) -> bool:
    return old_status == new_status or new_status in STATUS_TRANSITIONS.get(old_status, set())


def enforce_status_transitions(existing: dict[str, dict[str, Any]], records: list[dict[str, Any]], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    enforced: list[dict[str, Any]] = []
    for record in records:
        prior = existing.get(record["finding_id"])
        if prior and not transition_allowed(prior.get("status", ""), record["status"]):
            rejected = dict(record)
            rejected["status"] = prior["status"]
            rejected["record_updated_at"] = prior.get("record_updated_at", record["record_updated_at"])
            events.append(make_event(
                "status-transition-rejected",
                record.get("last_touched_batch"),
                record.get("owner_family"),
                "warn",
                f"Rejected transition for {record['finding_id']}: {prior.get('status')} -> {record['status']}",
                []
            ))
            enforced.append(rejected)
        else:
            enforced.append(record)
    return enforced


def make_event(event_type: str, batch_id: str | None, family: str | None, severity: str, message: str, input_hashes: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "event_id": event_id(event_type, batch_id, [family, severity, message, input_hashes]),
        "event_type": event_type,
        "occurred_at": "deterministic",
        "batch_id": batch_id,
        "family": family,
        "severity": severity,
        "message": message,
        "input_hashes": input_hashes,
    }


def build_id_crosswalk(existing_inventory: list[dict[str, Any]], incoming_records: list[dict[str, Any]]) -> dict[str, str]:
    crosswalk: dict[str, str] = {}
    for record in existing_inventory + incoming_records:
        stable_id = record.get("finding_id")
        if not isinstance(stable_id, str) or not stable_id:
            continue
        crosswalk.setdefault(stable_id, stable_id)
        for provisional_id in record.get("provisional_ids", []) or []:
            if isinstance(provisional_id, str) and provisional_id:
                crosswalk[provisional_id] = stable_id
        for source in record.get("source_reports", []) or []:
            if isinstance(source, dict) and isinstance(source.get("local_id"), str) and source["local_id"]:
                crosswalk[source["local_id"]] = stable_id
    return crosswalk


def should_report_unresolved_reference(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(PROVISIONAL_ID_PREFIXES)


def rewrite_reference_id(
    value: Any,
    crosswalk: dict[str, str],
    events: list[dict[str, Any]],
    batch_id: str | None,
    family: str | None,
    context: str,
    input_hashes: list[dict[str, str]],
) -> Any:
    if not isinstance(value, str):
        return value
    rewritten = crosswalk.get(value)
    if rewritten:
        return rewritten
    if should_report_unresolved_reference(value):
        events.append(make_event(
            "stable-id-reference-unresolved",
            batch_id,
            family,
            "warn",
            f"Could not map {context} reference {value!r} to a reducer stable ID.",
            input_hashes,
        ))
    return value


def rewrite_proof_references(
    records: list[dict[str, Any]],
    crosswalk: dict[str, str],
    events: list[dict[str, Any]],
    input_hashes: list[dict[str, str]],
) -> list[dict[str, Any]]:
    rewritten_records: list[dict[str, Any]] = []
    for record in records:
        rewritten = dict(record)
        rewritten["subject_id"] = rewrite_reference_id(
            record.get("subject_id"),
            crosswalk,
            events,
            record.get("last_touched_batch"),
            record.get("source_family"),
            "proof subject_id",
            input_hashes,
        )
        rewritten_records.append(rewritten)
    return rewritten_records


def rewrite_regression_references(
    records: list[dict[str, Any]],
    crosswalk: dict[str, str],
    events: list[dict[str, Any]],
    input_hashes: list[dict[str, str]],
) -> list[dict[str, Any]]:
    rewritten_records: list[dict[str, Any]] = []
    for record in records:
        rewritten = dict(record)
        rewritten["finding_id"] = rewrite_reference_id(
            record.get("finding_id"),
            crosswalk,
            events,
            record.get("last_touched_batch"),
            record.get("source_family"),
            "regression finding_id",
            input_hashes,
        )
        try:
            rewritten["regression_id"] = regression_record_id(rewritten)
        except KeyError:
            pass
        rewritten_records.append(rewritten)
    return rewritten_records


def rewrite_runtime_update_references(
    records: list[dict[str, Any]],
    crosswalk: dict[str, str],
    events: list[dict[str, Any]],
    input_hashes: list[dict[str, str]],
) -> list[dict[str, Any]]:
    rewritten_records: list[dict[str, Any]] = []
    for record in records:
        rewritten = dict(record)
        rewritten["finding_id"] = rewrite_reference_id(
            record.get("finding_id"),
            crosswalk,
            events,
            record.get("last_touched_batch"),
            record.get("source_family"),
            "runtime finding_id",
            input_hashes,
        )
        rewritten_records.append(rewritten)
    return rewritten_records


def chain_record_id(record: dict[str, Any]) -> str:
    return f"CH-{stable_hash([record.get('source_chain_candidate_id', record.get('chain_id')), record.get('component_findings', [])])}"


def rewrite_chain_references(
    records: list[dict[str, Any]],
    crosswalk: dict[str, str],
    events: list[dict[str, Any]],
    input_hashes: list[dict[str, str]],
) -> list[dict[str, Any]]:
    rewritten_records: list[dict[str, Any]] = []
    for record in records:
        rewritten = dict(record)
        components = []
        for component in record.get("component_findings", []) or []:
            components.append(rewrite_reference_id(
                component,
                crosswalk,
                events,
                None,
                None,
                "chain component_findings",
                input_hashes,
            ))
        rewritten["component_findings"] = unique_sorted(components)
        rewritten["chain_id"] = chain_record_id(rewritten)
        rewritten_records.append(rewritten)
    return rewritten_records


def apply_runtime_updates(
    records: list[dict[str, Any]],
    runtime_updates: list[dict[str, Any]],
    events: list[dict[str, Any]],
    input_hashes: list[dict[str, str]],
) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    unkeyed: list[dict[str, Any]] = []
    for record in records:
        if isinstance(record.get("finding_id"), str) and record["finding_id"]:
            by_id[record["finding_id"]] = dict(record)
        else:
            unkeyed.append(record)
    for update in runtime_updates:
        finding_id_value = update.get("finding_id")
        if not isinstance(finding_id_value, str):
            continue
        record = by_id.get(finding_id_value)
        if record is None:
            events.append(make_event(
                "runtime-update-unmatched",
                update.get("last_touched_batch"),
                update.get("source_family"),
                "warn",
                f"Runtime update referenced unknown finding {finding_id_value}.",
                input_hashes,
            ))
            continue
        record["runtime_status"] = update.get("runtime_status")
        record["evidence_refs"] = unique_sorted(record.get("evidence_refs", []) + update.get("evidence_refs", []))
        record["source_reports"] = unique_sorted(record.get("source_reports", []) + update.get("source_reports", []))
        if "last_touched_batch" in record and isinstance(update.get("last_touched_batch"), str):
            record["last_touched_batch"] = max(record["last_touched_batch"], update["last_touched_batch"])
        if update.get("runtime_status") == "confirmed-at-runtime" and record.get("status") != "runtime-confirmed":
            if transition_allowed(record.get("status", ""), "runtime-confirmed"):
                record["status"] = "runtime-confirmed"
            else:
                events.append(make_event(
                    "runtime-status-transition-rejected",
                    update.get("last_touched_batch"),
                    update.get("source_family"),
                    "warn",
                    f"Rejected runtime confirmation transition for {finding_id_value}: {record.get('status')} -> runtime-confirmed",
                    input_hashes,
                ))
        by_id[finding_id_value] = record
    return [by_id[key] for key in sorted(by_id)] + sorted(
        unkeyed,
        key=lambda row: json.dumps(normalize_value(row), sort_keys=True, separators=(",", ":")),
    )


def reduce_run(
    run_dir: Path,
    batch_id: str | None = None,
    profile: str = validate_run.DEFAULT_PROFILE,
    profiles_dir: Path = validate_run.DEFAULT_PROFILES_DIR,
    allow_experimental: bool = False,
    lenient: bool = False,
    write_normalized_sidecars: bool = False,
) -> dict[str, int]:
    run_dir = run_dir.resolve()
    lenient_warnings: list[str] = []
    if lenient:
        snapshot_state_before_lenient_repair(run_dir, lenient_warnings)
    repair_reducer_owned_state(run_dir)
    selected_profile = validate_run.load_profile(profile, profiles_dir)
    issues = validate_run.validate_run(
        run_dir,
        validate_run.DEFAULT_SCHEMAS_DIR,
        profile=profile,
        profiles_dir=profiles_dir,
        allow_experimental=allow_experimental,
        batch_id=batch_id,
    )
    if issues and not lenient:
        formatted = "\n".join(issue.format() for issue in issues)
        raise SystemExit(f"validation failed before reduce:\n{formatted}")
    state_dir = ensure_state_dir(run_dir)
    if issues and lenient:
        warn_lenient(lenient_warnings, f"strict validation reported {len(issues)} issue(s); reducing best-effort")
        for issue in issues[:LENIENT_WARNING_LIMIT]:
            warn_lenient(lenient_warnings, issue.format())
    read_state_jsonl = (lambda path: safe_read_jsonl(path, lenient_warnings)) if lenient else read_jsonl
    existing_inventory = read_state_jsonl(state_dir / "finding-inventory.jsonl")
    existing_records = {
        row["finding_id"]: row
        for row in existing_inventory
        if isinstance(row.get("finding_id"), str) and row["finding_id"]
    }
    existing_rejected = read_state_jsonl(state_dir / "rejected-claims.jsonl")
    existing_profile_feedback = read_state_jsonl(state_dir / "profile-feedback.jsonl")
    existing_chains = read_state_jsonl(state_dir / "chain-inventory.jsonl")
    existing_incidental_leads = read_state_jsonl(state_dir / "incidental-leads.jsonl")
    existing_security_smells = read_state_jsonl(state_dir / "security-smells.jsonl")
    existing_risk_signals = read_state_jsonl(state_dir / "risk-signals.jsonl")
    existing_proof_updates = read_state_jsonl(state_dir / "proof-ledger.jsonl")
    existing_regression_recommendations = read_state_jsonl(state_dir / "regression-plan.jsonl")
    existing_run_local_checks = read_state_jsonl(state_dir / "run-local-checks.jsonl")
    events = read_state_jsonl(state_dir / "run-events.jsonl")
    records: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    profile_feedback: list[dict[str, Any]] = []
    chain_records: list[dict[str, Any]] = []
    incidental_leads: list[dict[str, Any]] = []
    security_smells: list[dict[str, Any]] = []
    risk_signals: list[dict[str, Any]] = []
    proof_updates: list[dict[str, Any]] = []
    regression_recommendations: list[dict[str, Any]] = []
    runtime_updates: list[dict[str, Any]] = []
    run_local_checks: list[dict[str, Any]] = []
    try:
        trigger_signals = state_surface_signals(state_dir)
    except Exception as exc:  # noqa: BLE001
        if not lenient:
            raise
        warn_lenient(lenient_warnings, f"{state_dir}: skipped malformed state surface signals: {exc}")
        trigger_signals = []

    input_hashes = lenient_input_hashes(run_dir, batch_id) if lenient else validate_run.collect_input_hashes(run_dir, batch_id)
    report_inputs = collect_report_inputs(run_dir, batch_id, profile, selected_profile, lenient, lenient_warnings)
    processed_batches: set[str] = set()

    for manifest_path, manifest, item, report_path, sidecar_override in report_inputs:
        current_batch = manifest["batch_id"]
        processed_batches.add(current_batch)
        if item.get("status") != "ran" or ("json" not in item and sidecar_override is None):
            if item.get("status") in {"failed", "missing"}:
                events.append(make_event(
                    "lane-output-unavailable",
                    current_batch,
                    item.get("family"),
                    "error",
                    item.get("failure_reason") or f"Family status was {item.get('status')}",
                    input_hashes,
                ))
            continue
        try:
            sidecar = sidecar_override if sidecar_override is not None else validate_run.load_json(report_path)
        except Exception as exc:  # noqa: BLE001
            if lenient:
                warn_lenient(lenient_warnings, f"{report_path}: could not load report input: {exc}")
                continue
            raise
        if not isinstance(sidecar, dict):
            if lenient:
                warn_lenient(lenient_warnings, f"{report_path}: skipped non-object report input")
                continue
            raise SystemExit(f"sidecar must be an object: {report_path}")
        if lenient:
            sidecar = coerce_sidecar_for_reduce(sidecar, report_path, manifest, item, run_dir, profile, selected_profile, lenient_warnings)
            if lenient and write_normalized_sidecars and sidecar_override is None:
                normalized = normalized_sidecar_for_write(sidecar, selected_profile)
                snapshot_sidecar_before_normalize(run_dir, report_path, lenient_warnings)
                atomic_write_json(report_path, normalized)
                sidecar = normalized
        relative_report_path = report_path.relative_to(run_dir)
        trigger_signals.extend(sidecar_signals(sidecar))
        for finding in sidecar.get("confirmed_findings", []):
            try:
                records.append(confirmed_record(sidecar, finding, relative_report_path))
            except Exception as exc:  # noqa: BLE001
                if lenient:
                    warn_lenient(lenient_warnings, f"{report_path}: skipped confirmed finding during import: {exc}")
                    continue
                raise
        for candidate in sidecar.get("candidate_findings", []):
            try:
                records.append(candidate_record(sidecar, candidate, relative_report_path))
            except Exception as exc:  # noqa: BLE001
                if lenient:
                    warn_lenient(lenient_warnings, f"{report_path}: skipped candidate finding during import: {exc}")
                    continue
                raise
        for lead in sidecar.get("incidental_leads", []):
            try:
                lead_record = incidental_lead_record(sidecar, lead, relative_report_path)
                incidental_leads.append(lead_record)
            except Exception as exc:  # noqa: BLE001
                if lenient:
                    warn_lenient(lenient_warnings, f"{report_path}: skipped incidental lead during import: {exc}")
                    continue
                raise
            if lead_record.get("noticed_by_family") != lead_record.get("proposed_owner_family"):
                events.append(make_event(
                    "out-of-lane-lead-imported",
                    current_batch,
                    sidecar.get("family"),
                    "info",
                    f"Imported incidental lead {lead_record.get('lead_id')} from {lead_record.get('noticed_by_family')} for {lead_record.get('proposed_owner_family')}.",
                    input_hashes,
                ))
        for smell in sidecar.get("security_smells", []):
            try:
                security_smells.append(security_smell_record(sidecar, smell, relative_report_path))
            except Exception as exc:  # noqa: BLE001
                if lenient:
                    warn_lenient(lenient_warnings, f"{report_path}: skipped security smell during import: {exc}")
                    continue
                raise
        for signal in sidecar.get("risk_signals", []):
            try:
                risk_signals.append(risk_signal_record(sidecar, signal, relative_report_path))
            except Exception as exc:  # noqa: BLE001
                if lenient:
                    warn_lenient(lenient_warnings, f"{report_path}: skipped risk signal during import: {exc}")
                    continue
                raise
        for proof_update in sidecar.get("proof_updates", []):
            try:
                proof_updates.append(proof_update_record(sidecar, proof_update, relative_report_path))
            except Exception as exc:  # noqa: BLE001
                if lenient:
                    warn_lenient(lenient_warnings, f"{report_path}: skipped proof update during import: {exc}")
                    continue
                raise
        for recommendation in sidecar.get("regression_recommendations", []):
            try:
                regression_recommendations.append(regression_recommendation_record(sidecar, recommendation, relative_report_path))
            except Exception as exc:  # noqa: BLE001
                if lenient:
                    warn_lenient(lenient_warnings, f"{report_path}: skipped regression recommendation during import: {exc}")
                    continue
                raise
        for runtime_update in sidecar.get("runtime_updates", []):
            try:
                runtime_updates.append(runtime_update_record(sidecar, runtime_update, relative_report_path))
            except Exception as exc:  # noqa: BLE001
                if lenient:
                    warn_lenient(lenient_warnings, f"{report_path}: skipped runtime update during import: {exc}")
                    continue
                raise
        for local_check in sidecar.get("run_local_checks", []):
            try:
                run_local_checks.append(run_local_check_record(sidecar, local_check, relative_report_path))
            except Exception as exc:  # noqa: BLE001
                if lenient:
                    warn_lenient(lenient_warnings, f"{report_path}: skipped run-local check during import: {exc}")
                    continue
                raise
            events.append(make_event(
                "run-local-check-imported",
                current_batch,
                sidecar.get("family"),
                "info",
                f"Imported run-local check {local_check.get('check_id')}.",
                input_hashes,
            ))
        for claim in sidecar.get("rejected_claims", []):
            if not isinstance(claim, dict) or "claim_id" not in claim or "reason" not in claim:
                if lenient:
                    warn_lenient(lenient_warnings, f"{report_path}: skipped malformed rejected claim")
                    continue
            rejected.append({
                "schema_version": STATE_SCHEMA_VERSION,
                "claim_id": claim["claim_id"],
                "source_family": sidecar["family"],
                "batch_id": sidecar["batch_id"],
                "reason": claim["reason"],
                "subsumed_by": claim.get("subsumed_by"),
            })
        for feedback in sidecar.get("profile_feedback", []):
            if not isinstance(feedback, dict):
                if lenient:
                    warn_lenient(lenient_warnings, f"{report_path}: skipped malformed profile feedback")
                    continue
                raise TypeError("profile feedback must be an object")
            observed_issue = coerce_string(
                feedback.get("observed_issue") or feedback.get("note") or feedback.get("summary") or feedback.get("title"),
                "Unspecified profile feedback.",
            )
            feedback_family = coerce_string(feedback.get("family") or feedback.get("source_family"), sidecar["family"])
            feedback_id = coerce_string(
                feedback.get("profile_gap_id") or feedback.get("feedback_id") or feedback.get("id"),
                f"PG-{feedback_family}-{stable_hash([sidecar.get('sidecar_id'), observed_issue])}",
            )
            files = files_from_item(feedback, sidecar)
            profile_feedback.append({
                "schema_version": STATE_SCHEMA_VERSION,
                "profile_gap_id": feedback_id,
                "family": feedback_family,
                "affected_families": [
                    family
                    for family in (normalize_text(item) for item in as_list(feedback.get("affected_families")))
                    if family
                ],
                "observed_issue": observed_issue,
                "suggested_change": coerce_string(
                    feedback.get("suggested_change") or feedback.get("recommendation"),
                    "Review the profile contract for this lane output shape.",
                ),
                "evidence_refs": coerce_evidence_refs(feedback, files, "Reducer imported profile feedback evidence."),
                "urgency": coerce_enum(feedback.get("urgency"), {"high", "medium", "low"}, "medium"),
                "reducer_status": "deferred",
                "reducer_reason": "v0.4 reducer records profile feedback but does not mutate scope.",
            })
        for chain in sidecar.get("chain_candidates", []):
            if not isinstance(chain, dict) or "chain_candidate_id" not in chain or "why_chain_matters" not in chain:
                if lenient:
                    warn_lenient(lenient_warnings, f"{report_path}: skipped malformed chain candidate")
                    continue
            chain_records.append({
                "schema_version": STATE_SCHEMA_VERSION,
                "chain_id": f"CH-{stable_hash([chain['chain_candidate_id'], chain.get('component_findings', [])])}",
                "source_chain_candidate_id": chain["chain_candidate_id"],
                "component_findings": chain.get("component_findings", []),
                "families_involved": sorted({sidecar["family"]}),
                "impact": chain["why_chain_matters"],
                "confidence": chain.get("confidence", "speculative"),
                "status": "candidate",
            })

    id_crosswalk = build_id_crosswalk(existing_inventory, records)
    existing_proof_updates = rewrite_proof_references(existing_proof_updates, id_crosswalk, events, input_hashes)
    proof_updates = rewrite_proof_references(proof_updates, id_crosswalk, events, input_hashes)
    existing_regression_recommendations = rewrite_regression_references(existing_regression_recommendations, id_crosswalk, events, input_hashes)
    regression_recommendations = rewrite_regression_references(regression_recommendations, id_crosswalk, events, input_hashes)
    runtime_updates = rewrite_runtime_update_references(runtime_updates, id_crosswalk, events, input_hashes)
    existing_chains = rewrite_chain_references(existing_chains, id_crosswalk, events, input_hashes)
    chain_records = rewrite_chain_references(chain_records, id_crosswalk, events, input_hashes)

    incoming_merged = merge_records(records)
    incoming_merged = enforce_status_transitions(existing_records, incoming_merged, events)
    merged = merge_inventory(existing_inventory, incoming_merged)
    merged = apply_runtime_updates(merged, runtime_updates, events, input_hashes)
    merged_incidental_leads = merge_aux_records_by_key(existing_incidental_leads + incidental_leads, "lead_id")
    merged_security_smells = merge_aux_records_by_key(existing_security_smells + security_smells, "smell_id")
    merged_risk_signals = merge_aux_records_by_key(existing_risk_signals + risk_signals, "signal_id")
    merged_proof_updates = merge_proof_records(existing_proof_updates + proof_updates)
    merged_regression_recommendations = merge_aux_records_by_key(existing_regression_recommendations + regression_recommendations, "regression_id")
    merged_run_local_checks = merge_aux_records_by_key(existing_run_local_checks + run_local_checks, "check_id")
    merged_incidental_leads = prune_rows_to_schema(merged_incidental_leads, "incidental-lead.schema.json")
    merged_security_smells = prune_rows_to_schema(merged_security_smells, "security-smell.schema.json")
    merged_risk_signals = prune_rows_to_schema(merged_risk_signals, "risk-signal.schema.json")
    merged_proof_updates = prune_rows_to_schema(merged_proof_updates, "proof-ledger.schema.json")
    merged_regression_recommendations = prune_rows_to_schema(merged_regression_recommendations, "regression-plan.schema.json")
    merged_run_local_checks = prune_rows_to_schema(merged_run_local_checks, "run-local-check.schema.json")
    family_directives = build_family_directives(
        selected_profile,
        merged_incidental_leads,
        merged_run_local_checks,
        trigger_signals,
        processed_batches,
        events,
        input_hashes,
    )
    for warning in lenient_warnings:
        events.append(make_event(
            "lenient-reducer-warning",
            ",".join(sorted(processed_batches)) if processed_batches else batch_id,
            None,
            "warn",
            warning,
            input_hashes,
        ))
    events.append(make_event(
        "reducer-run",
        ",".join(sorted(processed_batches)) if processed_batches else batch_id,
        None,
        "info",
        f"Reduced {len(records)} input finding/candidate records into {len(incoming_merged)} incoming records; state now has {len(merged)} records.",
        input_hashes,
    ))

    atomic_write_jsonl(state_dir / "finding-inventory.jsonl", merged)
    atomic_write_jsonl(state_dir / "rejected-claims.jsonl", merge_records_by_key(existing_rejected + rejected, "claim_id"))
    atomic_write_jsonl(state_dir / "profile-feedback.jsonl", merge_records_by_key(existing_profile_feedback + profile_feedback, "profile_gap_id"))
    atomic_write_jsonl(state_dir / "chain-inventory.jsonl", merge_records_by_key(existing_chains + chain_records, "chain_id"))
    atomic_write_jsonl(state_dir / "incidental-leads.jsonl", merged_incidental_leads)
    atomic_write_jsonl(state_dir / "security-smells.jsonl", merged_security_smells)
    atomic_write_jsonl(state_dir / "risk-signals.jsonl", merged_risk_signals)
    atomic_write_jsonl(state_dir / "proof-ledger.jsonl", merged_proof_updates)
    atomic_write_jsonl(state_dir / "regression-plan.jsonl", merged_regression_recommendations)
    atomic_write_jsonl(state_dir / "run-local-checks.jsonl", merged_run_local_checks)
    atomic_write_jsonl(state_dir / "run-events.jsonl", merge_records_by_key(events, "event_id"))
    atomic_write_text(state_dir / "family-directives.yaml", family_directives_yaml(family_directives, processed_batches))
    atomic_write_text(state_dir / "shared-context-summary.md", shared_context_summary(merged))

    summary = {
        "records": len(merged),
        "events": len(merge_records_by_key(events, "event_id")),
        "rejected": len(rejected),
        "profile_feedback": len(profile_feedback),
        "chains": len(chain_records),
        "incidental_leads": len(incidental_leads),
        "security_smells": len(security_smells),
        "risk_signals": len(risk_signals),
        "proof_updates": len(proof_updates),
        "regression_recommendations": len(regression_recommendations),
        "runtime_updates": len(runtime_updates),
        "run_local_checks": len(run_local_checks),
        "family_directives": len(family_directives),
        "lenient_warnings": len(lenient_warnings),
    }
    reducer_dir = ensure_reducer_dir(run_dir)
    atomic_write_json(reducer_dir / "summary.json", summary)
    if lenient_warnings:
        atomic_write_json(
            reducer_dir / "lenient-warnings.json",
            {"count": len(lenient_warnings), "warnings": lenient_warnings},
        )
    return summary


def merge_records_by_key(records: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    by_key: dict[str, dict[str, Any]] = {}
    for record in records:
        if key not in record:
            continue
        by_key[record[key]] = record
    return [by_key[value] for value in sorted(by_key)]


def merge_aux_records_by_key(records: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    by_key: dict[str, dict[str, Any]] = {}
    for record in records:
        if key not in record:
            continue
        value = record[key]
        if value not in by_key:
            by_key[value] = record
            continue
        existing = dict(by_key[value])
        merged = {**existing, **record}
        for list_field in ("source_reports", "files", "evidence_refs", "trigger_evidence_refs", "extends_checks"):
            if list_field in existing or list_field in record:
                merged[list_field] = unique_sorted(existing.get(list_field, []) + record.get(list_field, []))
        if "first_seen_batch" in existing and "first_seen_batch" in record:
            merged["first_seen_batch"] = min(existing["first_seen_batch"], record["first_seen_batch"])
        if "last_touched_batch" in existing and "last_touched_batch" in record:
            merged["last_touched_batch"] = max(existing["last_touched_batch"], record["last_touched_batch"])
        by_key[value] = merged
    return [by_key[value] for value in sorted(by_key)]


def choose_stronger_proof(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    existing_rank = PROOF_LEVEL_RANK.get(existing.get("proof_level"), -1)
    incoming_rank = PROOF_LEVEL_RANK.get(incoming.get("proof_level"), -1)
    if incoming_rank > existing_rank:
        base, other = incoming, existing
    elif incoming_rank < existing_rank:
        base, other = existing, incoming
    elif incoming.get("last_touched_batch", "") > existing.get("last_touched_batch", ""):
        base, other = incoming, existing
    else:
        base, other = existing, incoming

    merged = {**other, **base}
    for list_field in ("source_reports", "evidence_refs"):
        merged[list_field] = unique_sorted(existing.get(list_field, []) + incoming.get(list_field, []))
    if "last_touched_batch" in existing and "last_touched_batch" in incoming:
        merged["last_touched_batch"] = max(existing["last_touched_batch"], incoming["last_touched_batch"])
    return merged


def merge_proof_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_subject: dict[str, dict[str, Any]] = {}
    for record in records:
        subject_id = record.get("subject_id")
        if not isinstance(subject_id, str) or not subject_id:
            continue
        if subject_id in by_subject:
            by_subject[subject_id] = choose_stronger_proof(by_subject[subject_id], record)
        else:
            by_subject[subject_id] = record
    return [by_subject[value] for value in sorted(by_subject)]


def shared_context_summary(records: list[dict[str, Any]]) -> str:
    lines = ["# AuditLanes Shared Context Summary", ""]
    for record in records:
        record_id = record.get("finding_id") or record.get("lead_id") or "unknown"
        status = record.get("status", "unknown")
        severity = record.get("severity", "unknown")
        summary = record.get("summary", "")
        lines.append(f"- `{record_id}` {status} {severity}: {summary}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Reduce AuditLanes sidecars into deterministic state.")
    parser.add_argument("run_dir", type=Path, help="Path to auditlanes/out/runs/<run-id>.")
    parser.add_argument("--batch-id", help="Reduce only one batch, for example batch-01.")
    parser.add_argument("--profile", default=validate_run.DEFAULT_PROFILE, help="AuditLanes profile id to validate against before reducing.")
    parser.add_argument("--profiles-dir", type=Path, default=validate_run.DEFAULT_PROFILES_DIR)
    parser.add_argument("--allow-experimental", action="store_true", help="Allow metadata-only profiles for profile-loading/catalog compatibility checks.")
    parser.add_argument("--lenient", action="store_true", help="Reduce best-effort when lane outputs or state files deviate from schema; records warnings in run-events.jsonl.")
    parser.add_argument("--write-normalized-sidecars", action="store_true", help="With --lenient, overwrite existing report.json files with reducer-normalized schema-shaped JSON after snapshotting originals under reducer/.")
    args = parser.parse_args(argv)
    if args.write_normalized_sidecars and not args.lenient:
        parser.error("--write-normalized-sidecars requires --lenient")

    summary = reduce_run(
        args.run_dir,
        args.batch_id,
        profile=args.profile,
        profiles_dir=args.profiles_dir.resolve(),
        allow_experimental=args.allow_experimental,
        lenient=args.lenient,
        write_normalized_sidecars=args.write_normalized_sidecars,
    )
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
