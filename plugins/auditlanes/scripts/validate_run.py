#!/usr/bin/env python3
"""Validate AuditLanes run artifacts.

This script intentionally keeps dependencies optional. If `jsonschema` is
installed, it is used. Otherwise a small validator handles the JSON Schema
subset shipped with AuditLanes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCHEMAS_DIR = PLUGIN_ROOT / "resources" / "schemas"
DEFAULT_PROFILES_DIR = PLUGIN_ROOT / "resources" / "profiles"
DEFAULT_PROFILE = "security"
MANIFEST_FILENAMES = ("manifest.yaml", "manifest.yml", "manifest.json")
RUNTIME_APPROVAL_PATH = "state/run-metadata.yaml"


class ValidationIssue:
    def __init__(self, path: Path, location: str, message: str) -> None:
        self.path = path
        self.location = location
        self.message = message

    def format(self) -> str:
        return f"{self.path}:{self.location}: {self.message}"


class SchemaError(Exception):
    pass


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_json_or_yaml(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    try:
        import yaml  # type: ignore

        return yaml.safe_load(text)
    except ModuleNotFoundError:
        return parse_simple_yaml(text)


def parse_simple_yaml(text: str) -> Any:
    """Parse the small YAML subset used by AuditLanes fixtures/manifests.

    This is not a general YAML parser. It supports nested mappings, lists,
    scalar strings, integers, booleans, and nulls.
    """

    lines: list[tuple[int, str]] = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        lines.append((indent, raw.strip()))

    def scalar(value: str) -> Any:
        value = value.strip()
        if value in {"null", "~"}:
            return None
        if value == "true":
            return True
        if value == "false":
            return False
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            return value[1:-1]
        if re.fullmatch(r"-?[0-9]+", value):
            return int(value)
        return value

    def split_key_value(content: str) -> tuple[str, str | None]:
        if ":" not in content:
            raise ValueError(f"expected key/value YAML line: {content!r}")
        key, value = content.split(":", 1)
        key = key.strip()
        value = value.strip()
        return key, value if value else None

    def parse_block(index: int, indent: int) -> tuple[Any, int]:
        if index >= len(lines):
            return {}, index
        current_indent, current_content = lines[index]
        if current_indent < indent:
            return {}, index
        if current_content.startswith("- "):
            return parse_list(index, indent)
        return parse_dict(index, indent)

    def parse_dict(index: int, indent: int) -> tuple[dict[str, Any], int]:
        result: dict[str, Any] = {}
        while index < len(lines):
            current_indent, content = lines[index]
            if current_indent < indent:
                break
            if current_indent > indent:
                raise ValueError(f"unexpected indentation before {content!r}")
            if content.startswith("- "):
                break
            key, value = split_key_value(content)
            index += 1
            if value is None:
                parsed, index = parse_block(index, indent + 2)
                result[key] = parsed
            else:
                result[key] = scalar(value)
        return result, index

    def parse_list(index: int, indent: int) -> tuple[list[Any], int]:
        result: list[Any] = []
        while index < len(lines):
            current_indent, content = lines[index]
            if current_indent < indent:
                break
            if current_indent != indent or not content.startswith("- "):
                break
            item_text = content[2:].strip()
            index += 1
            if not item_text:
                item, index = parse_block(index, indent + 2)
                result.append(item)
            elif ":" in item_text:
                key, value = split_key_value(item_text)
                item_dict: dict[str, Any] = {
                    key: scalar(value) if value is not None else {}
                }
                if index < len(lines) and lines[index][0] > indent:
                    nested, index = parse_dict(index, indent + 2)
                    item_dict.update(nested)
                result.append(item_dict)
            else:
                result.append(scalar(item_text))
        return result, index

    parsed, final_index = parse_block(0, lines[0][0] if lines else 0)
    if final_index != len(lines):
        raise ValueError("could not parse complete YAML document")
    return parsed


def resolve_ref(schema: dict[str, Any], ref: str) -> dict[str, Any]:
    if not ref.startswith("#/"):
        raise SchemaError(f"unsupported external $ref: {ref}")
    current: Any = schema
    for part in ref[2:].split("/"):
        current = current[part]
    if not isinstance(current, dict):
        raise SchemaError(f"$ref does not resolve to an object schema: {ref}")
    return current


def type_matches(expected: Any, value: Any) -> bool:
    expected_types = expected if isinstance(expected, list) else [expected]
    for expected_type in expected_types:
        if expected_type == "object" and isinstance(value, dict):
            return True
        if expected_type == "array" and isinstance(value, list):
            return True
        if expected_type == "string" and isinstance(value, str):
            return True
        if expected_type == "integer" and isinstance(value, int) and not isinstance(value, bool):
            return True
        if expected_type == "boolean" and isinstance(value, bool):
            return True
        if expected_type == "null" and value is None:
            return True
    return False


def validate_with_fallback(instance: Any, schema: dict[str, Any], root: dict[str, Any] | None = None, path: str = "$") -> list[str]:
    root = root or schema
    errors: list[str] = []

    if "$ref" in schema:
        return validate_with_fallback(instance, resolve_ref(root, schema["$ref"]), root, path)

    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected constant {schema['const']!r}, got {instance!r}")
        return errors

    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: value {instance!r} not in enum {schema['enum']!r}")
        return errors

    if "type" in schema and not type_matches(schema["type"], instance):
        errors.append(f"{path}: expected type {schema['type']!r}, got {type(instance).__name__}")
        return errors

    if isinstance(instance, dict):
        required = schema.get("required", [])
        for key in required:
            if key not in instance:
                errors.append(f"{path}: missing required property {key!r}")

        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            allowed = set(properties)
            for key in instance:
                if key not in allowed:
                    errors.append(f"{path}: unexpected property {key!r}")

        for key, value in instance.items():
            if key in properties:
                errors.extend(validate_with_fallback(value, properties[key], root, f"{path}.{key}"))

    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(f"{path}: expected at least {schema['minItems']} items")
        item_schema = schema.get("items")
        if item_schema:
            for index, item in enumerate(instance):
                errors.extend(validate_with_fallback(item, item_schema, root, f"{path}[{index}]"))

    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(f"{path}: expected string length >= {schema['minLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            errors.append(f"{path}: value {instance!r} does not match pattern {schema['pattern']!r}")

    if isinstance(instance, int) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path}: value {instance!r} is less than minimum {schema['minimum']!r}")

    return errors


def validate_schema(instance: Any, schema: dict[str, Any]) -> list[str]:
    try:
        import jsonschema  # type: ignore

        validator = jsonschema.Draft202012Validator(schema)
        return [
            f"${''.join(f'[{p!r}]' if isinstance(p, int) else f'.{p}' for p in error.path)}: {error.message}"
            for error in sorted(validator.iter_errors(instance), key=lambda e: list(e.path))
        ]
    except ModuleNotFoundError:
        return validate_with_fallback(instance, schema)


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def package_version() -> str | None:
    manifest = PLUGIN_ROOT / "package-manifest.yaml"
    try:
        for line in manifest.read_text(encoding="utf-8").splitlines():
            if line.startswith("version:"):
                return line.split(":", 1)[1].strip().strip('"').strip("'")
    except OSError:
        return None
    return None


def is_datetime(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def repo_path_without_line_suffix(value: str) -> str:
    return re.sub(r":[0-9]+(?::[0-9]+)?$", "", value)


def validate_repo_relative_path_value(path: Path, location: str, value: Any) -> list[ValidationIssue]:
    if not isinstance(value, str) or not value:
        return []

    raw = repo_path_without_line_suffix(value.strip())
    if raw.startswith("${"):
        return [ValidationIssue(path, location, "path must be repository-relative, not variable-expanded")]

    candidate = Path(raw)
    if candidate.is_absolute():
        return [ValidationIssue(path, location, "path must be repository-relative, not absolute")]
    if ".." in candidate.parts:
        return [ValidationIssue(path, location, "path must not contain '..'")]
    if len(candidate.parts) >= 2 and candidate.parts[0] == "auditlanes" and candidate.parts[1] == "out":
        return [ValidationIssue(path, location, "evidence/reviewed paths must not point into auditlanes/out")]
    return []


def family_mode_issue(
    path: Path,
    location: str,
    family: Any,
    mode: Any,
    selected_profile: dict[str, Any],
) -> ValidationIssue | None:
    if not isinstance(family, str) or not isinstance(mode, str):
        return None

    lanes = selected_profile["lanes"]
    specialists = selected_profile["specialists"]
    specialist_modes = selected_profile.get("specialist_modes", {})
    expected_specialist_mode = specialist_modes.get(family)

    if family in lanes and mode in set(specialist_modes.values()):
        return ValidationIssue(path, location, "normal lanes must not run specialist modes")
    if family in specialists and expected_specialist_mode and mode != expected_specialist_mode:
        return ValidationIssue(path, location, f"specialist {family!r} must run mode {expected_specialist_mode!r}")
    if mode in set(specialist_modes.values()) and family not in specialists:
        return ValidationIssue(path, location, "specialist mode requires the matching specialist family")
    return None


def load_optional_run_metadata(run_dir: Path) -> tuple[dict[str, Any] | None, list[ValidationIssue]]:
    metadata_path = run_dir / RUNTIME_APPROVAL_PATH
    if not metadata_path.exists():
        return None, []

    issues = require_plain_file_under(run_dir, metadata_path, "run metadata")
    if issues:
        return None, issues
    try:
        metadata = load_json_or_yaml(metadata_path)
    except Exception as exc:  # noqa: BLE001
        return None, [ValidationIssue(metadata_path, "$", f"could not parse run metadata: {exc}")]
    if not isinstance(metadata, dict):
        return None, [ValidationIssue(metadata_path, "$", "run metadata must be an object")]
    return metadata, []


def require_plain_file_under(root: Path, path: Path, artifact: str) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if path.is_symlink():
        issues.append(ValidationIssue(path, "$", f"symlinked {artifact} is not allowed"))
        return issues

    try:
        resolved = path.resolve()
        resolved.relative_to(root.resolve())
    except ValueError:
        issues.append(ValidationIssue(path, "$", f"{artifact} path escapes RUN_DIR"))
        return issues
    except (OSError, RuntimeError) as exc:
        issues.append(ValidationIssue(path, "$", f"could not resolve {artifact} path: {exc}"))
        return issues

    if not path.is_file():
        issues.append(ValidationIssue(path, "$", f"{artifact} must be a regular file"))
    return issues


def is_plain_file_under(root: Path, path: Path) -> bool:
    return not require_plain_file_under(root, path, "input artifact")


def manifest_paths(run_dir: Path, batch_id: str | None = None) -> list[Path]:
    if batch_id:
        batch_dir = run_dir / "reports" / batch_id
        return [batch_dir / name for name in MANIFEST_FILENAMES if (batch_dir / name).exists()]

    paths: list[Path] = []
    for batch_dir in sorted((run_dir / "reports").glob("batch-*")):
        paths.extend(batch_dir / name for name in MANIFEST_FILENAMES if (batch_dir / name).exists())
    return sorted(paths)


def sidecar_paths(run_dir: Path, batch_id: str | None = None) -> list[Path]:
    if batch_id:
        return sorted((run_dir / "reports" / batch_id).glob("*/report.json"))
    return sorted(run_dir.glob("reports/batch-*/*/report.json"))


def collect_input_hashes(run_dir: Path, batch_id: str | None = None) -> list[dict[str, str]]:
    paths = manifest_paths(run_dir, batch_id)
    paths.extend(sidecar_paths(run_dir, batch_id))
    return [
        {
            "path": path.relative_to(run_dir).as_posix(),
            "sha256": hash_file(path)
        }
        for path in paths
        if is_plain_file_under(run_dir, path)
    ]


def load_profile(profile_id: str, profiles_dir: Path) -> dict[str, Any]:
    profile_root = profiles_dir / profile_id
    profile_path = profile_root / "profile.yaml"
    if not profile_path.exists():
        raise FileNotFoundError(f"profile does not exist: {profile_path}")

    profile = load_json_or_yaml(profile_path)
    if not isinstance(profile, dict):
        raise ValueError(f"profile file must be an object: {profile_path}")

    lane_source = profile.get("lane_source", "lanes.yaml")
    if not isinstance(lane_source, str) or not lane_source:
        raise ValueError(f"profile lane_source must be a non-empty string: {profile_path}")

    lanes_path = profile_root / lane_source
    lanes_data = load_json_or_yaml(lanes_path)
    if not isinstance(lanes_data, dict):
        raise ValueError(f"lanes file must be an object: {lanes_path}")

    lanes: set[str] = set()
    lane_order: list[str] = []
    for index, lane in enumerate(lanes_data.get("lanes", [])):
        if not isinstance(lane, dict) or not isinstance(lane.get("id"), str):
            raise ValueError(f"lane entry {index} must contain an id in {lanes_path}")
        lanes.add(lane["id"])
        lane_order.append(lane["id"])

    specialists: set[str] = set()
    specialist_modes: dict[str, str] = {}
    for index, specialist in enumerate(lanes_data.get("specialists", [])):
        if not isinstance(specialist, dict) or not isinstance(specialist.get("id"), str):
            raise ValueError(f"specialist entry {index} must contain an id in {lanes_path}")
        specialists.add(specialist["id"])
        if isinstance(specialist.get("mode"), str):
            specialist_modes[specialist["id"]] = specialist["mode"]

    if not lanes:
        raise ValueError(f"profile must define at least one lane: {lanes_path}")

    implemented = profile.get("implemented")
    if implemented is None:
        implemented = profile.get("status") in {"stable", "bundled"}

    return {
        "id": profile_id,
        "implemented": bool(implemented),
        "lanes": lanes,
        "lane_order": lane_order,
        "specialists": specialists,
        "specialist_modes": specialist_modes,
        "families": lanes | specialists,
        "profile_path": profile_path,
        "lanes_path": lanes_path,
    }


def validate_manifest_profile(manifest_path: Path, manifest: dict[str, Any], profile: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    allowed = profile["families"]

    expected_families = manifest.get("expected_families", [])
    if not isinstance(expected_families, list):
        expected_families = []
    for index, family in enumerate(expected_families):
        if isinstance(family, str) and family not in allowed:
            issues.append(ValidationIssue(manifest_path, f"$.expected_families[{index}]", f"family {family!r} is not defined by profile {profile['id']!r}"))

    family_items = manifest.get("families", [])
    if not isinstance(family_items, list):
        family_items = []
    for index, item in enumerate(family_items):
        if not isinstance(item, dict):
            continue
        family = item.get("family")
        if isinstance(family, str) and family not in allowed:
            issues.append(ValidationIssue(manifest_path, f"$.families[{index}].family", f"family {family!r} is not defined by profile {profile['id']!r}"))
        mode_issue = family_mode_issue(manifest_path, f"$.families[{index}].mode", family, item.get("mode"), profile)
        if mode_issue:
            issues.append(mode_issue)

    return issues


def validate_sidecar_profile(
    sidecar_path: Path,
    sidecar: dict[str, Any],
    selected_profile: dict[str, Any],
    run_metadata: dict[str, Any] | None,
    expected_version: str | None,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    lanes = selected_profile["lanes"]
    families = selected_profile["families"]
    profile_id = selected_profile["id"]

    if sidecar.get("profile") != profile_id:
        issues.append(ValidationIssue(sidecar_path, "$.profile", f"expected selected profile {profile_id!r}, got {sidecar.get('profile')!r}"))

    family = sidecar.get("family")
    if isinstance(family, str) and family not in families:
        issues.append(ValidationIssue(sidecar_path, "$.family", f"family {family!r} is not defined by profile {profile_id!r}"))
    if sidecar.get("mode") == "parked":
        issues.append(ValidationIssue(sidecar_path, "$.mode", "parked families must not emit fresh report sidecars"))
    mode_issue = family_mode_issue(sidecar_path, "$.mode", family, sidecar.get("mode"), selected_profile)
    if mode_issue:
        issues.append(mode_issue)

    if not is_datetime(sidecar.get("generated_at")):
        issues.append(ValidationIssue(sidecar_path, "$.generated_at", "must be an RFC3339 date-time string"))

    if expected_version and sidecar.get("profile_version") not in {None, expected_version}:
        issues.append(ValidationIssue(sidecar_path, "$.profile_version", f"must match package version {expected_version!r} when present"))

    issues.extend(validate_sidecar_repo_paths(sidecar_path, sidecar))

    has_runtime_updates = bool(sidecar.get("runtime_updates"))
    has_runtime_confirmed = any(
        isinstance(finding, dict) and finding.get("status") == "runtime-confirmed"
        for finding in sidecar.get("confirmed_findings", [])
    )
    if (has_runtime_updates or has_runtime_confirmed) and sidecar.get("mode") != "runtime-safe":
        issues.append(ValidationIssue(sidecar_path, "$.mode", "runtime_updates and runtime-confirmed findings require mode=runtime-safe"))
    if sidecar.get("mode") == "runtime-safe" and run_metadata is not None:
        approval = run_metadata.get("runtime_approval")
        approved = isinstance(approval, dict) and approval.get("enabled") is True
        if not approved:
            issues.append(ValidationIssue(sidecar_path, "$.mode", f"runtime-safe mode requires runtime_approval.enabled=true in {RUNTIME_APPROVAL_PATH}"))
    has_reswept = any(
        isinstance(finding, dict) and finding.get("status") in {"reswept-open", "reswept-closed"}
        for finding in sidecar.get("confirmed_findings", [])
    )
    if has_reswept and sidecar.get("mode") != "post-fix-resweep":
        issues.append(ValidationIssue(sidecar_path, "$.mode", "reswept-open and reswept-closed findings require mode=post-fix-resweep"))

    for index, finding in enumerate(sidecar.get("confirmed_findings", [])):
        if not isinstance(finding, dict):
            continue
        owner = finding.get("owner_family")
        if isinstance(owner, str) and owner not in lanes:
            issues.append(ValidationIssue(sidecar_path, f"$.confirmed_findings[{index}].owner_family", f"owner family {owner!r} is not a lane in profile {profile_id!r}"))
        dedupe_owner = finding.get("dedupe_key", {}).get("owner_family") if isinstance(finding.get("dedupe_key"), dict) else None
        if isinstance(dedupe_owner, str) and dedupe_owner not in lanes:
            issues.append(ValidationIssue(sidecar_path, f"$.confirmed_findings[{index}].dedupe_key.owner_family", f"owner family {dedupe_owner!r} is not a lane in profile {profile_id!r}"))
        dedupe_key = finding.get("dedupe_key") if isinstance(finding.get("dedupe_key"), dict) else {}
        for field in ("owner_family", "security_invariant", "missing_guard", "entrypoint", "impact_boundary"):
            if field in finding and field in dedupe_key and finding[field] != dedupe_key[field]:
                issues.append(ValidationIssue(sidecar_path, f"$.confirmed_findings[{index}].dedupe_key.{field}", f"must mirror confirmed_finding.{field} exactly"))
        if sidecar.get("batch_id") == "batch-01" and finding.get("introduced_after_batch_01") is True:
            issues.append(ValidationIssue(sidecar_path, f"$.confirmed_findings[{index}].introduced_after_batch_01", "batch-01 findings must not be marked introduced_after_batch_01"))

    for index, candidate in enumerate(sidecar.get("candidate_findings", [])):
        if not isinstance(candidate, dict):
            continue
        owner = candidate.get("proposed_owner_family")
        if isinstance(owner, str) and owner not in lanes:
            issues.append(ValidationIssue(sidecar_path, f"$.candidate_findings[{index}].proposed_owner_family", f"owner family {owner!r} is not a lane in profile {profile_id!r}"))
        dedupe_owner = candidate.get("candidate_dedupe_key", {}).get("proposed_owner_family") if isinstance(candidate.get("candidate_dedupe_key"), dict) else None
        if isinstance(dedupe_owner, str) and dedupe_owner not in lanes:
            issues.append(ValidationIssue(sidecar_path, f"$.candidate_findings[{index}].candidate_dedupe_key.proposed_owner_family", f"owner family {dedupe_owner!r} is not a lane in profile {profile_id!r}"))
        dedupe_key = candidate.get("candidate_dedupe_key") if isinstance(candidate.get("candidate_dedupe_key"), dict) else {}
        for field in ("proposed_owner_family", "summary", "files", "suspected_missing_guard", "impact_boundary"):
            if field in candidate and field in dedupe_key and candidate[field] != dedupe_key[field]:
                issues.append(ValidationIssue(sidecar_path, f"$.candidate_findings[{index}].candidate_dedupe_key.{field}", f"must mirror candidate_finding.{field} exactly"))

    for index, feedback in enumerate(sidecar.get("profile_feedback", [])):
        if not isinstance(feedback, dict):
            continue
        feedback_family = feedback.get("family")
        if isinstance(feedback_family, str) and feedback_family not in lanes:
            issues.append(ValidationIssue(sidecar_path, f"$.profile_feedback[{index}].family", f"family {feedback_family!r} is not a lane in profile {profile_id!r}"))
        affected = feedback.get("affected_families", [])
        if affected is None:
            affected = []
        if isinstance(affected, list):
            for affected_index, affected_family in enumerate(affected):
                if isinstance(affected_family, str) and affected_family not in lanes:
                    issues.append(ValidationIssue(sidecar_path, f"$.profile_feedback[{index}].affected_families[{affected_index}]", f"family {affected_family!r} is not a lane in profile {profile_id!r}"))

    return issues


def validate_evidence_refs(
    sidecar_path: Path,
    location: str,
    refs: Any,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if not isinstance(refs, list):
        return issues
    for index, ref in enumerate(refs):
        if not isinstance(ref, dict):
            continue
        ref_location = f"{location}[{index}]"
        issues.extend(validate_repo_relative_path_value(sidecar_path, f"{ref_location}.path", ref.get("path")))
        line_start = ref.get("line_start")
        line_end = ref.get("line_end")
        if line_start is not None and (not isinstance(line_start, int) or isinstance(line_start, bool) or line_start < 1):
            issues.append(ValidationIssue(sidecar_path, f"{ref_location}.line_start", "must be null or a 1-based line number"))
        if line_end is not None and (not isinstance(line_end, int) or isinstance(line_end, bool) or line_end < 1):
            issues.append(ValidationIssue(sidecar_path, f"{ref_location}.line_end", "must be null or a 1-based line number"))
        if isinstance(line_start, int) and isinstance(line_end, int) and line_end < line_start:
            issues.append(ValidationIssue(sidecar_path, f"{ref_location}.line_end", "must be greater than or equal to line_start"))
    return issues


def validate_path_list(sidecar_path: Path, location: str, values: Any) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if not isinstance(values, list):
        return issues
    for index, value in enumerate(values):
        issues.extend(validate_repo_relative_path_value(sidecar_path, f"{location}[{index}]", value))
    return issues


def validate_sidecar_repo_paths(sidecar_path: Path, sidecar: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for field in ("reviewed_artifacts", "reviewed_files_routes_helpers"):
        issues.extend(validate_path_list(sidecar_path, f"$.{field}", sidecar.get(field)))

    for collection_name in ("confirmed_findings", "candidate_findings"):
        collection = sidecar.get(collection_name, [])
        if not isinstance(collection, list):
            continue
        for index, item in enumerate(collection):
            if not isinstance(item, dict):
                continue
            if isinstance(item.get("files"), list):
                issues.extend(validate_path_list(sidecar_path, f"$.{collection_name}[{index}].files", item.get("files")))
            issues.extend(validate_evidence_refs(sidecar_path, f"$.{collection_name}[{index}].evidence_refs", item.get("evidence_refs")))

    for collection_name in ("runtime_updates", "profile_feedback"):
        collection = sidecar.get(collection_name, [])
        if not isinstance(collection, list):
            continue
        for index, item in enumerate(collection):
            if isinstance(item, dict):
                issues.extend(validate_evidence_refs(sidecar_path, f"$.{collection_name}[{index}].evidence_refs", item.get("evidence_refs")))

    clone_maps = sidecar.get("clone_maps", [])
    if isinstance(clone_maps, list):
        for index, clone_map in enumerate(clone_maps):
            if isinstance(clone_map, dict):
                issues.extend(validate_evidence_refs(sidecar_path, f"$.clone_maps[{index}].clone_locations", clone_map.get("clone_locations")))

    return issues


def expand_run_path(run_dir: Path, value: str, manifest_dir: Path) -> Path:
    candidate = Path(value)
    if candidate.is_absolute():
        raise ValueError("manifest paths must be run-relative")

    if value.startswith("${RUN_DIR}/"):
        raw = run_dir / value[len("${RUN_DIR}/"):]
    elif value.startswith("reports/") or value.startswith("state/") or value.startswith("final/"):
        raw = run_dir / value
    else:
        raw = manifest_dir / value

    return raw


def resolve_run_path(run_dir: Path, value: str, manifest_dir: Path) -> Path:
    raw = expand_run_path(run_dir, value, manifest_dir)
    root = run_dir.resolve()
    try:
        resolved = raw.resolve()
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"could not resolve run path: {value}: {exc}") from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path escapes RUN_DIR: {value}") from exc
    return resolved


def manifest_batch_id_from_path(run_dir: Path, manifest_path: Path) -> str | None:
    try:
        relative = manifest_path.resolve().relative_to(run_dir.resolve())
    except ValueError:
        return None
    parts = relative.parts
    if len(parts) != 3 or parts[0] != "reports" or parts[2] not in MANIFEST_FILENAMES:
        return None
    return parts[1]


def validate_manifest_outputs(
    run_dir: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
    referenced_sidecars: dict[Path, int],
    selected_profile: dict[str, Any],
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    path_batch_id = manifest_batch_id_from_path(run_dir, manifest_path)
    if path_batch_id is None:
        issues.append(ValidationIssue(manifest_path, "$", "manifest must live at reports/<batch-id>/manifest.{yaml,yml,json}"))
    elif manifest.get("batch_id") != path_batch_id:
        issues.append(ValidationIssue(manifest_path, "$.batch_id", f"does not match path batch {path_batch_id!r}"))

    if manifest.get("run_id") != run_dir.name:
        issues.append(ValidationIssue(manifest_path, "$.run_id", f"does not match run directory name {run_dir.name!r}"))
    if not is_datetime(manifest.get("generated_at")):
        issues.append(ValidationIssue(manifest_path, "$.generated_at", "must be an RFC3339 date-time string"))

    expected_items = manifest.get("expected_families", [])
    if not isinstance(expected_items, list):
        expected_items = []
    if isinstance(expected_items, list):
        expected_duplicates = sorted({family for family in expected_items if expected_items.count(family) > 1})
        for family in expected_duplicates:
            issues.append(ValidationIssue(manifest_path, "$.expected_families", f"duplicate expected family {family!r}"))
    expected = set(expected_items)

    family_items = manifest.get("families", [])
    if not isinstance(family_items, list):
        family_items = []
    seen_list = [item.get("family") for item in family_items if isinstance(item, dict)]
    seen = set(seen_list)
    for family in sorted({family for family in seen_list if seen_list.count(family) > 1}):
        issues.append(ValidationIssue(manifest_path, "$.families", f"duplicate family entry {family!r}"))
    for family in sorted(seen - expected):
        issues.append(ValidationIssue(manifest_path, "$.families", f"family {family!r} is not listed in expected_families"))
    missing = expected - seen
    for family in sorted(missing):
        issues.append(ValidationIssue(manifest_path, "$.families", f"expected family {family!r} is not represented"))

    if path_batch_id == "batch-01" and selected_profile["id"] == "security":
        lane_order = selected_profile["lane_order"]
        if set(expected_items) != set(lane_order) or len(expected_items) != len(lane_order):
            issues.append(ValidationIssue(manifest_path, "$.expected_families", "batch-01 security canonical sweep must include exactly the six security lanes"))
    if path_batch_id == "batch-04" and selected_profile["id"] == "security":
        specialists = selected_profile["specialists"]
        if set(expected_items) != set(specialists) or len(expected_items) != len(specialists):
            issues.append(ValidationIssue(manifest_path, "$.expected_families", "batch-04 security exploit synthesis must include only the exploit-synthesis specialist"))

    manifest_status = manifest.get("manifest_status")
    family_statuses = [item.get("status") for item in family_items if isinstance(item, dict)]
    has_failed_or_missing = any(status in {"failed", "missing"} for status in family_statuses)
    has_incomplete_condition = bool(missing) or any(status == "missing" for status in family_statuses)
    if manifest_status == "completed" and has_failed_or_missing:
        issues.append(ValidationIssue(manifest_path, "$.manifest_status", "completed manifest must not contain failed or missing families"))
    if manifest_status == "completed-with-failures" and not has_failed_or_missing:
        issues.append(ValidationIssue(manifest_path, "$.manifest_status", "completed-with-failures manifest must include at least one failed or missing family"))
    if manifest_status == "incomplete" and not has_incomplete_condition:
        issues.append(ValidationIssue(manifest_path, "$.manifest_status", "incomplete manifest must include a missing family or missing expected family representation"))

    for index, item in enumerate(family_items):
        if not isinstance(item, dict):
            continue
        status = item.get("status")
        if status == "parked" and not item.get("carried_forward_from"):
            issues.append(ValidationIssue(manifest_path, f"$.families[{index}].carried_forward_from", "parked family must declare carried_forward_from"))
        if status in {"failed", "missing"} and not item.get("failure_reason"):
            issues.append(ValidationIssue(manifest_path, f"$.families[{index}].failure_reason", f"{status} family must declare failure_reason"))
        family = item.get("family")
        mode = item.get("mode")
        if status == "parked":
            if mode != "parked":
                issues.append(ValidationIssue(manifest_path, f"$.families[{index}].mode", "parked family status requires mode=parked"))
            for field in ("markdown", "json"):
                if item.get(field):
                    issues.append(ValidationIssue(manifest_path, f"$.families[{index}].{field}", "parked family must not declare a fresh output path"))
        if status == "ran" and mode == "parked":
            issues.append(ValidationIssue(manifest_path, f"$.families[{index}].mode", "ran family must not use mode=parked"))
        if path_batch_id == "batch-01" and selected_profile["id"] == "security":
            if status != "ran":
                issues.append(ValidationIssue(manifest_path, f"$.families[{index}].status", "batch-01 security lanes must all run"))
            if mode != "canonical-sweep":
                issues.append(ValidationIssue(manifest_path, f"$.families[{index}].mode", "batch-01 security lanes must run canonical-sweep"))
        if path_batch_id == "batch-04" and selected_profile["id"] == "security" and status == "ran" and mode != "exploit-synthesis":
            issues.append(ValidationIssue(manifest_path, f"$.families[{index}].mode", "batch-04 security specialist must run exploit-synthesis"))
        if status != "ran":
            continue
        for field in ("markdown", "json"):
            value = item.get(field)
            if not isinstance(value, str) or not value:
                issues.append(ValidationIssue(manifest_path, f"$.families[{index}].{field}", "ran family must declare output path"))
                continue
            try:
                raw_output = expand_run_path(run_dir, value, manifest_path.parent)
                resolved = resolve_run_path(run_dir, value, manifest_path.parent)
            except ValueError as exc:
                issues.append(ValidationIssue(manifest_path, f"$.families[{index}].{field}", str(exc)))
                continue
            if not resolved.exists():
                issues.append(ValidationIssue(manifest_path, f"$.families[{index}].{field}", f"output file does not exist: {resolved}"))
                continue
            if field == "json":
                plain_file_issues = require_plain_file_under(run_dir, raw_output, "sidecar")
                if plain_file_issues:
                    issues.extend(plain_file_issues)
                    continue
                referenced_sidecars[resolved] = referenced_sidecars.get(resolved, 0) + 1
                try:
                    sidecar = load_json(raw_output)
                except Exception as exc:  # noqa: BLE001
                    issues.append(ValidationIssue(manifest_path, f"$.families[{index}].json", f"could not parse referenced sidecar: {exc}"))
                    continue
                if isinstance(sidecar, dict):
                    issues.extend(validate_manifest_sidecar_reference(run_dir, manifest_path, manifest, index, item, resolved, sidecar))
    return issues


def validate_sidecar_path(run_dir: Path, path: Path, sidecar: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    try:
        relative = path.resolve().relative_to(run_dir.resolve())
    except ValueError:
        issues.append(ValidationIssue(path, "$", "sidecar path is outside RUN_DIR"))
        return issues

    parts = relative.parts
    if len(parts) != 4 or parts[0] != "reports" or parts[3] != "report.json":
        issues.append(ValidationIssue(path, "$", "sidecar must live at reports/<batch-id>/<family>/report.json"))
        return issues

    batch_id = parts[1]
    family = parts[2]
    if sidecar.get("batch_id") != batch_id:
        issues.append(ValidationIssue(path, "$.batch_id", f"does not match path batch {batch_id!r}"))
    if sidecar.get("family") != family:
        issues.append(ValidationIssue(path, "$.family", f"does not match path family {family!r}"))
    if sidecar.get("run_id") != run_dir.name:
        issues.append(ValidationIssue(path, "$.run_id", f"does not match run directory name {run_dir.name!r}"))
    return issues


def validate_manifest_sidecar_reference(
    run_dir: Path,
    manifest_path: Path,
    manifest: dict[str, Any],
    item_index: int,
    item: dict[str, Any],
    sidecar_path: Path,
    sidecar: dict[str, Any],
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    item_family = item.get("family")
    if sidecar.get("run_id") != manifest.get("run_id") or sidecar.get("run_id") != run_dir.name:
        issues.append(ValidationIssue(manifest_path, f"$.families[{item_index}].json", "referenced sidecar run_id must match manifest and run directory"))
    if sidecar.get("batch_id") != manifest.get("batch_id"):
        issues.append(ValidationIssue(manifest_path, f"$.families[{item_index}].json", "referenced sidecar batch_id must match manifest batch_id"))
    if sidecar.get("family") != item_family:
        issues.append(ValidationIssue(manifest_path, f"$.families[{item_index}].json", f"referenced sidecar family {sidecar.get('family')!r} does not match manifest item family {item_family!r}"))
    if sidecar.get("mode") != item.get("mode"):
        issues.append(ValidationIssue(manifest_path, f"$.families[{item_index}].json", "referenced sidecar mode must match manifest item mode"))
    issues.extend(validate_sidecar_path(run_dir, sidecar_path, sidecar))
    return issues


def validate_file(path: Path, schema: dict[str, Any], loader) -> list[ValidationIssue]:
    try:
        data = loader(path)
    except Exception as exc:  # noqa: BLE001
        return [ValidationIssue(path, "$", f"could not parse file: {exc}")]

    return [
        ValidationIssue(path, message.split(":", 1)[0], message.split(":", 1)[1].strip() if ":" in message else message)
        for message in validate_schema(data, schema)
    ]


def validate_run(
    run_dir: Path,
    schemas_dir: Path,
    profile: str = DEFAULT_PROFILE,
    profiles_dir: Path = DEFAULT_PROFILES_DIR,
    allow_experimental: bool = False,
    batch_id: str | None = None,
) -> list[ValidationIssue]:
    sidecar_schema = load_json(schemas_dir / "report-sidecar.schema.json")
    manifest_schema = load_json(schemas_dir / "batch-manifest.schema.json")
    issues: list[ValidationIssue] = []

    try:
        selected_profile = load_profile(profile, profiles_dir)
    except Exception as exc:  # noqa: BLE001
        return [ValidationIssue(profiles_dir / profile, "$", f"could not load profile: {exc}")]

    if not selected_profile["implemented"] and not allow_experimental:
        issues.append(ValidationIssue(selected_profile["profile_path"], "$.implemented", f"profile {profile!r} is not implemented; pass --allow-experimental only for metadata checks"))
    expected_version = package_version()
    run_metadata, metadata_issues = load_optional_run_metadata(run_dir)
    issues.extend(metadata_issues)

    manifests = manifest_paths(run_dir, batch_id)
    sidecars = sidecar_paths(run_dir, batch_id)
    referenced_sidecars: dict[Path, int] = {}

    if not manifests:
        target = f" for {batch_id}" if batch_id else ""
        manifest_hint = " expected reports/<batch-id>/manifest.yaml to reference each family report.json"
        issues.append(ValidationIssue(run_dir, "$.reports", f"no batch manifests found{target};{manifest_hint}"))
    if not sidecars:
        issues.append(ValidationIssue(run_dir, "$.reports", "no report sidecars found"))

    for manifest_path in manifests:
        plain_file_issues = require_plain_file_under(run_dir, manifest_path, "manifest")
        if plain_file_issues:
            issues.extend(plain_file_issues)
            continue
        try:
            manifest = load_json_or_yaml(manifest_path)
        except Exception as exc:  # noqa: BLE001
            issues.append(ValidationIssue(manifest_path, "$", f"could not parse manifest: {exc}"))
            continue
        for message in validate_schema(manifest, manifest_schema):
            issues.append(ValidationIssue(manifest_path, message.split(":", 1)[0], message.split(":", 1)[1].strip() if ":" in message else message))
        if isinstance(manifest, dict):
            issues.extend(validate_manifest_profile(manifest_path, manifest, selected_profile))
            issues.extend(validate_manifest_outputs(run_dir, manifest_path, manifest, referenced_sidecars, selected_profile))

    for sidecar_path in sidecars:
        plain_file_issues = require_plain_file_under(run_dir, sidecar_path, "sidecar")
        if plain_file_issues:
            issues.extend(plain_file_issues)
            continue
        try:
            sidecar = load_json(sidecar_path)
        except Exception as exc:  # noqa: BLE001
            issues.append(ValidationIssue(sidecar_path, "$", f"could not parse sidecar: {exc}"))
            continue
        for message in validate_schema(sidecar, sidecar_schema):
            issues.append(ValidationIssue(sidecar_path, message.split(":", 1)[0], message.split(":", 1)[1].strip() if ":" in message else message))
        if isinstance(sidecar, dict):
            issues.extend(validate_sidecar_path(run_dir, sidecar_path, sidecar))
            issues.extend(validate_sidecar_profile(sidecar_path, sidecar, selected_profile, run_metadata, expected_version))

    for sidecar_path in sidecars:
        if not is_plain_file_under(run_dir, sidecar_path):
            continue
        resolved = sidecar_path.resolve()
        if resolved not in referenced_sidecars:
            issues.append(ValidationIssue(
                sidecar_path,
                "$",
                "sidecar is not referenced by any selected batch manifest; add it to reports/<batch-id>/manifest.yaml under families[].json"
            ))
    for sidecar_path, count in sorted(referenced_sidecars.items(), key=lambda item: item[0].as_posix()):
        if count > 1:
            issues.append(ValidationIssue(sidecar_path, "$", "sidecar is referenced by multiple manifest items"))

    return issues


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate AuditLanes run artifacts.")
    parser.add_argument("run_dir", type=Path, help="Path to auditlanes/out/runs/<run-id>.")
    parser.add_argument("--schemas-dir", type=Path, default=DEFAULT_SCHEMAS_DIR)
    parser.add_argument("--profile", default=DEFAULT_PROFILE, help="AuditLanes profile id to validate against.")
    parser.add_argument("--profiles-dir", type=Path, default=DEFAULT_PROFILES_DIR)
    parser.add_argument("--allow-experimental", action="store_true", help="Allow metadata-only profiles for profile-loading/catalog compatibility checks.")
    parser.add_argument("--batch-id", help="Validate only one batch, for example batch-01.")
    parser.add_argument("--print-input-hashes", action="store_true")
    args = parser.parse_args(argv)

    run_dir = args.run_dir.resolve()
    if args.print_input_hashes:
        print(json.dumps(collect_input_hashes(run_dir, args.batch_id), indent=2, sort_keys=True))

    issues = validate_run(
        run_dir,
        args.schemas_dir.resolve(),
        profile=args.profile,
        profiles_dir=args.profiles_dir.resolve(),
        allow_experimental=args.allow_experimental,
        batch_id=args.batch_id,
    )
    if issues:
        for issue in issues:
            print(issue.format(), file=sys.stderr)
        return 1

    print(f"AuditLanes validation passed: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
