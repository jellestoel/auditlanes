#!/usr/bin/env python3
"""Deterministically reduce AuditLanes sidecars into run state."""

from __future__ import annotations

import argparse
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
    events = read_jsonl(state_dir / "run-events.jsonl")
    records: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    profile_feedback: list[dict[str, Any]] = []
    chain_records: list[dict[str, Any]] = []

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
            for finding in sidecar.get("confirmed_findings", []):
                records.append(confirmed_record(sidecar, finding, report_path.relative_to(run_dir)))
            for candidate in sidecar.get("candidate_findings", []):
                records.append(candidate_record(sidecar, candidate, report_path.relative_to(run_dir)))
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
                    "component_findings": chain.get("component_findings", []),
                    "families_involved": sorted({sidecar["family"]}),
                    "impact": chain["why_chain_matters"],
                    "confidence": chain.get("confidence", "speculative"),
                    "status": "candidate",
                })

    incoming_merged = merge_records(records)
    incoming_merged = enforce_status_transitions(existing_records, incoming_merged, events)
    merged = merge_inventory(existing_inventory, incoming_merged)
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
    atomic_write_jsonl(state_dir / "run-events.jsonl", merge_records_by_key(events, "event_id"))
    atomic_write_text(state_dir / "shared-context-summary.md", shared_context_summary(merged))

    return {
        "records": len(merged),
        "events": len(merge_records_by_key(events, "event_id")),
        "rejected": len(rejected),
        "profile_feedback": len(profile_feedback),
        "chains": len(chain_records),
    }


def merge_records_by_key(records: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    by_key: dict[str, dict[str, Any]] = {}
    for record in records:
        if key not in record:
            continue
        by_key[record[key]] = record
    return [by_key[value] for value in sorted(by_key)]


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
