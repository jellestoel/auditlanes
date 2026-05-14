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
    "P2-static-confirmed": 2,
    "P3-reachability-confirmed": 3,
    "P4-runtime-confirmed": 4,
    "P5-regression-backed": 5,
}
PROVISIONAL_ID_PREFIXES = ("PF-", "CAND-")
STATUS_TRANSITIONS = {
    "lead": {"candidate", "confirmed-static", "rejected"},
    "candidate": {"confirmed-static", "blocked", "rejected", "duplicate"},
    "confirmed-static": {"runtime-confirmed", "fixed", "duplicate", "reswept-open", "reswept-closed"},
    "runtime-confirmed": {"fixed", "duplicate", "reswept-open", "reswept-closed"},
}


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


def root_cause_id(finding: dict[str, Any]) -> str:
    key = finding["dedupe_key"]
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
        key["entrypoint"],
        finding.get("files", []),
        key["impact_boundary"],
    ])
    return f"F-{key['owner_family']}-{short}"


def candidate_id(candidate: dict[str, Any]) -> str:
    key = candidate["candidate_dedupe_key"]
    short = stable_hash([
        key["proposed_owner_family"],
        key["summary"],
        key["files"],
        key.get("suspected_missing_guard"),
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
        "entrypoint": finding["entrypoint"],
        "security_invariant": finding["security_invariant"],
        "attacker_precondition": finding["attacker_precondition"],
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
        "missing_guard": finding["missing_guard"],
        "impact_boundary": finding["impact_boundary"],
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
        "security_invariant": None,
        "attacker_precondition": None,
        "introduced_after_batch_01": batch_id != "batch-01",
        "duplicate_of": None,
        "clone_of": None,
        "related_findings": [],
        "files": candidate.get("files", []),
        "evidence_refs": candidate.get("evidence_refs", []),
        "report_refs": [],
        "lead_source_refs": candidate.get("lead_source_refs", []),
        "widespread_pattern": False,
        "estimated_clone_count": None,
        "missing_guard": candidate.get("suspected_missing_guard") or "",
        "impact_boundary": candidate.get("impact_boundary") or "",
        "severity_rationale": None,
        "candidate_blocker": candidate["blocker_to_confirmation"],
        "runtime_status": None,
    }


def incidental_lead_record(sidecar: dict[str, Any], lead: dict[str, Any], report_path: Path) -> dict[str, Any]:
    batch_id = sidecar["batch_id"]
    family = sidecar["family"]
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "lead_id": lead["lead_id"],
        "noticed_by_family": lead["noticed_by_family"],
        "proposed_owner_family": lead["proposed_owner_family"],
        "source_reports": [source_report(batch_id, family, report_path, lead["lead_id"])],
        "first_seen_batch": batch_id,
        "last_touched_batch": batch_id,
        "severity_hint": lead["severity_hint"],
        "confidence": lead["confidence"],
        "summary": lead["summary"],
        "why_noticed": lead.get("why_noticed"),
        "blocker_to_confirmation": lead["blocker_to_confirmation"],
        "files": lead.get("files", []),
        "evidence_refs": lead.get("evidence_refs", []),
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
        "family": sidecar.get("family") if sidecar else item.get("owner_family"),
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


def directive_mode_for_source(source_kind: str) -> str:
    if source_kind in {"confirmed-finding", "candidate-finding"}:
        return "clonehunt"
    return "canonical-gap-fill"


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
            "canonical-gap-fill",
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
            "canonical-gap-fill",
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
                    directive_mode_for_source(signal["source_kind"]),
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
) -> dict[str, int]:
    run_dir = run_dir.resolve()
    issues = validate_run.validate_run(
        run_dir,
        validate_run.DEFAULT_SCHEMAS_DIR,
        profile=profile,
        profiles_dir=profiles_dir,
        allow_experimental=allow_experimental,
        batch_id=batch_id,
    )
    if issues:
        formatted = "\n".join(issue.format() for issue in issues)
        raise SystemExit(f"validation failed before reduce:\n{formatted}")

    selected_profile = validate_run.load_profile(profile, profiles_dir)
    state_dir = ensure_state_dir(run_dir)
    existing_inventory = read_jsonl(state_dir / "finding-inventory.jsonl")
    existing_records = {
        row["finding_id"]: row
        for row in existing_inventory
        if isinstance(row.get("finding_id"), str) and row["finding_id"]
    }
    existing_rejected = read_jsonl(state_dir / "rejected-claims.jsonl")
    existing_profile_feedback = read_jsonl(state_dir / "profile-feedback.jsonl")
    existing_chains = read_jsonl(state_dir / "chain-inventory.jsonl")
    existing_incidental_leads = read_jsonl(state_dir / "incidental-leads.jsonl")
    existing_security_smells = read_jsonl(state_dir / "security-smells.jsonl")
    existing_proof_updates = read_jsonl(state_dir / "proof-ledger.jsonl")
    existing_regression_recommendations = read_jsonl(state_dir / "regression-plan.jsonl")
    existing_run_local_checks = read_jsonl(state_dir / "run-local-checks.jsonl")
    events = read_jsonl(state_dir / "run-events.jsonl")
    records: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    profile_feedback: list[dict[str, Any]] = []
    chain_records: list[dict[str, Any]] = []
    incidental_leads: list[dict[str, Any]] = []
    security_smells: list[dict[str, Any]] = []
    proof_updates: list[dict[str, Any]] = []
    regression_recommendations: list[dict[str, Any]] = []
    runtime_updates: list[dict[str, Any]] = []
    run_local_checks: list[dict[str, Any]] = []
    trigger_signals = state_surface_signals(state_dir)

    manifests = load_manifests(run_dir, batch_id)
    input_hashes = validate_run.collect_input_hashes(run_dir, batch_id)
    processed_batches: set[str] = set()

    for manifest_path, manifest in manifests:
        current_batch = manifest["batch_id"]
        processed_batches.add(current_batch)
        for item in manifest.get("families", []):
            if item.get("status") != "ran" or "json" not in item:
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
            report_path = resolve_report_path(run_dir, manifest_path, item["json"])
            sidecar = validate_run.load_json(report_path)
            trigger_signals.extend(sidecar_signals(sidecar))
            for finding in sidecar.get("confirmed_findings", []):
                records.append(confirmed_record(sidecar, finding, report_path.relative_to(run_dir)))
            for candidate in sidecar.get("candidate_findings", []):
                records.append(candidate_record(sidecar, candidate, report_path.relative_to(run_dir)))
            for lead in sidecar.get("incidental_leads", []):
                incidental_leads.append(incidental_lead_record(sidecar, lead, report_path.relative_to(run_dir)))
                if lead.get("noticed_by_family") != lead.get("proposed_owner_family"):
                    events.append(make_event(
                        "out-of-lane-lead-imported",
                        current_batch,
                        sidecar.get("family"),
                        "info",
                        f"Imported incidental lead {lead.get('lead_id')} from {lead.get('noticed_by_family')} for {lead.get('proposed_owner_family')}.",
                        input_hashes,
                    ))
            for smell in sidecar.get("security_smells", []):
                security_smells.append(security_smell_record(sidecar, smell, report_path.relative_to(run_dir)))
            for proof_update in sidecar.get("proof_updates", []):
                proof_updates.append(proof_update_record(sidecar, proof_update, report_path.relative_to(run_dir)))
            for recommendation in sidecar.get("regression_recommendations", []):
                regression_recommendations.append(regression_recommendation_record(sidecar, recommendation, report_path.relative_to(run_dir)))
            for runtime_update in sidecar.get("runtime_updates", []):
                runtime_updates.append(runtime_update_record(sidecar, runtime_update, report_path.relative_to(run_dir)))
            for local_check in sidecar.get("run_local_checks", []):
                run_local_checks.append(run_local_check_record(sidecar, local_check, report_path.relative_to(run_dir)))
                events.append(make_event(
                    "run-local-check-imported",
                    current_batch,
                    sidecar.get("family"),
                    "info",
                    f"Imported run-local check {local_check.get('check_id')}.",
                    input_hashes,
                ))
            for claim in sidecar.get("rejected_claims", []):
                rejected.append({
                    "schema_version": STATE_SCHEMA_VERSION,
                    "claim_id": claim["claim_id"],
                    "source_family": sidecar["family"],
                    "batch_id": sidecar["batch_id"],
                    "reason": claim["reason"],
                    "subsumed_by": claim.get("subsumed_by"),
                })
            for feedback in sidecar.get("profile_feedback", []):
                profile_feedback.append({
                    "schema_version": STATE_SCHEMA_VERSION,
                    "profile_gap_id": feedback["profile_gap_id"],
                    "family": feedback["family"],
                    "affected_families": feedback.get("affected_families", []),
                    "observed_issue": feedback["observed_issue"],
                    "suggested_change": feedback["suggested_change"],
                    "evidence_refs": feedback.get("evidence_refs", []),
                    "urgency": feedback["urgency"],
                    "reducer_status": "deferred",
                    "reducer_reason": "v0.4 reducer records profile feedback but does not mutate scope.",
                })
            for chain in sidecar.get("chain_candidates", []):
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
    merged_proof_updates = merge_proof_records(existing_proof_updates + proof_updates)
    merged_regression_recommendations = merge_aux_records_by_key(existing_regression_recommendations + regression_recommendations, "regression_id")
    merged_run_local_checks = merge_aux_records_by_key(existing_run_local_checks + run_local_checks, "check_id")
    family_directives = build_family_directives(
        selected_profile,
        merged_incidental_leads,
        merged_run_local_checks,
        trigger_signals,
        processed_batches,
        events,
        input_hashes,
    )
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
    atomic_write_jsonl(state_dir / "proof-ledger.jsonl", merged_proof_updates)
    atomic_write_jsonl(state_dir / "regression-plan.jsonl", merged_regression_recommendations)
    atomic_write_jsonl(state_dir / "run-local-checks.jsonl", merged_run_local_checks)
    atomic_write_jsonl(state_dir / "run-events.jsonl", merge_records_by_key(events, "event_id"))
    atomic_write_text(state_dir / "family-directives.yaml", family_directives_yaml(family_directives, processed_batches))
    atomic_write_text(state_dir / "shared-context-summary.md", shared_context_summary(merged))

    return {
        "records": len(merged),
        "events": len(merge_records_by_key(events, "event_id")),
        "rejected": len(rejected),
        "profile_feedback": len(profile_feedback),
        "chains": len(chain_records),
        "incidental_leads": len(incidental_leads),
        "security_smells": len(security_smells),
        "proof_updates": len(proof_updates),
        "regression_recommendations": len(regression_recommendations),
        "runtime_updates": len(runtime_updates),
        "run_local_checks": len(run_local_checks),
        "family_directives": len(family_directives),
    }


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
    args = parser.parse_args(argv)

    summary = reduce_run(
        args.run_dir,
        args.batch_id,
        profile=args.profile,
        profiles_dir=args.profiles_dir.resolve(),
        allow_experimental=args.allow_experimental,
    )
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
