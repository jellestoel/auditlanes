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
STATE_ARTIFACT_SCHEMAS = {
    "attack-surface-graph.jsonl": "attack-surface.schema.json",
    "attack-surface-inventory.jsonl": "attack-surface-inventory.schema.json",
    "authorization-matrix.jsonl": "authorization-matrix.schema.json",
    "incidental-leads.jsonl": "incidental-lead.schema.json",
    "proof-ledger.jsonl": "proof-ledger.schema.json",
    "regression-plan.jsonl": "regression-plan.schema.json",
    "relevance-plan.yaml": "relevance-plan.schema.json",
    "relevance-plan.yml": "relevance-plan.schema.json",
    "run-local-checks.jsonl": "run-local-check.schema.json",
    "risk-signals.jsonl": "risk-signal.schema.json",
    "security-invariants.jsonl": "security-invariant.schema.json",
    "security-smells.jsonl": "security-smell.schema.json",
    "scenario-observations.jsonl": "scenario-observation.schema.json",
    "unowned-surfaces.jsonl": "unowned-surface.schema.json",
    "workflow-atlas-edges.jsonl": "workflow-atlas-edge.schema.json",
    "workflow-atlas-entities.jsonl": "workflow-atlas-entity.schema.json",
    "workflow-atlas-evidence.jsonl": "workflow-atlas-evidence.schema.json",
    "workflow-score-matrix.jsonl": "workflow-score-row.schema.json",
}
STATE_LANE_FIELDS = {
    "attack-surface-graph.jsonl": ("owner_family",),
    "attack-surface-inventory.jsonl": ("owner_family",),
    "incidental-leads.jsonl": ("proposed_owner_family",),
    "risk-signals.jsonl": ("recommended_owner",),
    "security-invariants.jsonl": ("owner_family",),
    "security-smells.jsonl": ("recommended_owner",),
    "workflow-atlas-edges.jsonl": ("owner_family",),
    "workflow-atlas-entities.jsonl": ("owner_family",),
}
STATE_LANE_LIST_FIELDS = {
    "attack-surface-graph.jsonl": ("secondary_families",),
    "security-invariants.jsonl": ("secondary_families",),
}
STATE_EVIDENCE_ARTIFACTS = {
    "attack-surface-graph.jsonl",
    "attack-surface-inventory.jsonl",
    "authorization-matrix.jsonl",
    "incidental-leads.jsonl",
    "proof-ledger.jsonl",
    "risk-signals.jsonl",
    "security-invariants.jsonl",
}
SECURITY_COMPLETE_BATCHES = {
    "batch-01": {
        "families": "lanes",
        "ran_modes": {"canonical-sweep"},
        "allow_parked": False,
    },
    "batch-02": {
        "families": "lanes",
        "ran_modes": {"canonical-gap-fill", "clonehunt", "runtime-safe"},
        "allow_parked": True,
    },
    "batch-03": {
        "families": "lanes",
        "ran_modes": {"canonical-gap-fill", "clonehunt", "runtime-safe"},
        "allow_parked": True,
    },
    "batch-04": {
        "families": "specialists",
        "ran_modes": {"exploit-synthesis"},
        "allow_parked": False,
    },
}
SECURITY_PRE_FIX_FINAL_ARTIFACTS = (
    "final/pre-fix-findings.md",
    "final/pre-fix-summary.md",
)


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
        return parse_simple_yaml(text)
    except Exception as simple_exc:  # noqa: BLE001
        simple_error = simple_exc

    try:
        import yaml  # type: ignore

        return yaml.safe_load(text)
    except ModuleNotFoundError as exc:
        raise simple_error from exc


def parse_simple_yaml(text: str) -> Any:
    """Parse the small YAML subset used by AuditLanes fixtures/manifests.

    This is not a general YAML parser. It supports nested mappings, lists,
    scalar strings, integers, booleans, and nulls.
    """

    lines: list[tuple[int, str]] = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped in {"---", "..."} or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        lines.append((indent, raw.strip()))

    def split_flow_items(content: str) -> list[str]:
        items: list[str] = []
        current: list[str] = []
        quote: str | None = None
        escaped = False
        depth = 0
        for char in content:
            if quote:
                current.append(char)
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                continue
            if char in {"'", '"'}:
                quote = char
                current.append(char)
                continue
            if char in "[{":
                depth += 1
                current.append(char)
                continue
            if char in "]}":
                depth -= 1
                current.append(char)
                continue
            if char == "," and depth == 0:
                item = "".join(current).strip()
                if item:
                    items.append(item)
                current = []
                continue
            current.append(char)
        if quote or depth != 0:
            raise ValueError(f"unterminated flow collection: {content!r}")
        item = "".join(current).strip()
        if item:
            items.append(item)
        return items

    def split_flow_key_value(content: str) -> tuple[str, str]:
        quote: str | None = None
        escaped = False
        depth = 0
        for index, char in enumerate(content):
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                continue
            if char in {"'", '"'}:
                quote = char
                continue
            if char in "[{":
                depth += 1
                continue
            if char in "]}":
                depth -= 1
                continue
            if char == ":" and depth == 0:
                return content[:index].strip(), content[index + 1:].strip()
        raise ValueError(f"expected flow key/value item: {content!r}")

    def scalar(value: str) -> Any:
        value = value.strip()
        normalized = value.lower()
        if normalized in {"null", "~"}:
            return None
        if value == "[]":
            return []
        if value == "{}":
            return {}
        if normalized == "true":
            return True
        if normalized == "false":
            return False
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            return value[1:-1]
        if len(value) >= 2 and value[0] == "[" and value[-1] == "]":
            inner = value[1:-1].strip()
            if not inner:
                return []
            return [scalar(item) for item in split_flow_items(inner)]
        if len(value) >= 2 and value[0] == "{" and value[-1] == "}":
            inner = value[1:-1].strip()
            if not inner:
                return {}
            result: dict[str, Any] = {}
            for item in split_flow_items(inner):
                key, item_value = split_flow_key_value(item)
                if len(key) >= 2 and key[0] == key[-1] and key[0] in {"'", '"'}:
                    key = key[1:-1]
                result[key] = scalar(item_value)
            return result
        if re.fullmatch(r"-?[0-9]+", value):
            return int(value)
        return value

    def looks_like_list_mapping(item_text: str, index: int, indent: int) -> bool:
        if ":" not in item_text:
            return False
        key, _ = item_text.split(":", 1)
        key = key.strip()
        if not re.fullmatch(r"[a-z_][a-z0-9_]*", key):
            return False
        return index < len(lines) and lines[index][0] > indent

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
            elif looks_like_list_mapping(item_text, index, indent):
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


def is_allowed_auditlanes_run_input_path(raw: str) -> bool:
    candidate = Path(raw)
    parts = candidate.parts
    if len(parts) < 6:
        return False
    if parts[:3] != ("auditlanes", "out", "runs"):
        return False
    if "reports" not in parts[4:] and "state" not in parts[4:] and "final" not in parts[4:]:
        return False
    return candidate.name in {
        "manifest.yaml",
        "manifest.yml",
        "report.json",
        "report.md",
        "shared-context-summary.md",
        "workflow-atlas-entities.jsonl",
        "workflow-atlas-edges.jsonl",
        "workflow-atlas-evidence.jsonl",
        "scenario-observations.jsonl",
        "workflow-score-matrix.jsonl",
    }


def validate_repo_relative_path_value(
    path: Path,
    location: str,
    value: Any,
    allow_auditlanes_run_input: bool = False,
) -> list[ValidationIssue]:
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
        if allow_auditlanes_run_input and is_allowed_auditlanes_run_input_path(raw):
            return []
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


def sidecar_paths(run_dir: Path, batch_id: str | None = None, family: str | None = None) -> list[Path]:
    if batch_id and family:
        path = run_dir / "reports" / batch_id / family / "report.json"
        return [path] if path.exists() else []
    if batch_id:
        pattern = f"{family}/report.json" if family else "*/report.json"
        return sorted((run_dir / "reports" / batch_id).glob(pattern))
    if family:
        return sorted(run_dir.glob(f"reports/batch-*/{family}/report.json"))
    return sorted(run_dir.glob("reports/batch-*/*/report.json"))


def collect_input_hashes(run_dir: Path, batch_id: str | None = None, family: str | None = None) -> list[dict[str, str]]:
    paths = manifest_paths(run_dir, batch_id)
    paths.extend(sidecar_paths(run_dir, batch_id, family))
    return [
        {
            "path": path.relative_to(run_dir).as_posix(),
            "sha256": hash_file(path)
        }
        for path in paths
        if is_plain_file_under(run_dir, path)
    ]


def load_catalog_items(
    profile_root: Path,
    profile_id_or_source: str | Any,
    source_or_kind: Any,
    item_kind: str | None = None,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    if item_kind is None:
        profile_id = ""
        source = profile_id_or_source
        item_kind = source_or_kind
    else:
        profile_id = profile_id_or_source
        source = source_or_kind
    if source is None:
        return {}, []
    if not isinstance(source, str) or not source:
        raise ValueError(f"profile {item_kind}_source must be a non-empty string when present")

    source_path = profile_root / source
    if not source_path.exists():
        raise FileNotFoundError(f"{item_kind} source does not exist: {source_path}")

    if source_path.is_dir():
        paths = sorted(source_path.glob("*.yaml")) + sorted(source_path.glob("*.yml")) + sorted(source_path.glob("*.json"))
    else:
        paths = [source_path]

    items: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for path in paths:
        data = load_json_or_yaml(path)
        raw_items = data.get(item_kind, data) if isinstance(data, dict) else data
        if isinstance(raw_items, dict):
            raw_items = [raw_items]
        if not isinstance(raw_items, list):
            raise ValueError(f"{item_kind} catalog must be an object or list: {path}")
        for index, item in enumerate(raw_items):
            if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"]:
                raise ValueError(f"{item_kind} entry {index} must contain an id in {path}")
            item_id = item["id"]
            if item_id in items:
                raise ValueError(f"duplicate {item_kind} id {item_id!r} in {path}")
            declared_profile = item.get("profile")
            if profile_id and declared_profile is not None and declared_profile != profile_id:
                raise ValueError(f"{item_kind} {item_id!r} declares profile {declared_profile!r}, expected {profile_id!r} in {path}")
            normalized = dict(item)
            allowed_modes = normalized.get("allowed_modes")
            if allowed_modes is None:
                normalized["allowed_modes"] = set()
            elif isinstance(allowed_modes, list) and all(isinstance(mode, str) for mode in allowed_modes):
                normalized["allowed_modes"] = set(allowed_modes)
            else:
                raise ValueError(f"{item_kind} {item_id!r} allowed_modes must be a string list in {path}")
            anti_tunnel = normalized.get("anti_tunnel")
            if isinstance(anti_tunnel, dict) and anti_tunnel.get("universal_reportability") is False:
                raise ValueError(f"{item_kind} {item_id!r} must not disable universal_reportability in {path}")
            normalized["path"] = path
            items[item_id] = normalized
            order.append(item_id)
    return items, order


def load_cross_lane_triggers(profile_root: Path, source: Any, lanes: set[str]) -> list[dict[str, Any]]:
    if source is None:
        return []
    if not isinstance(source, str) or not source:
        raise ValueError("profile cross_lane_trigger_source must be a non-empty string when present")

    path = profile_root / source
    if not path.exists():
        raise FileNotFoundError(f"cross-lane trigger source does not exist: {path}")
    data = load_json_or_yaml(path)
    raw_triggers = data.get("triggers", data) if isinstance(data, dict) else data
    if not isinstance(raw_triggers, list):
        raise ValueError(f"cross-lane trigger catalog must contain a triggers list: {path}")

    triggers: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, trigger in enumerate(raw_triggers):
        if not isinstance(trigger, dict) or not isinstance(trigger.get("id"), str) or not trigger["id"]:
            raise ValueError(f"cross-lane trigger entry {index} must contain an id in {path}")
        trigger_id = trigger["id"]
        if trigger_id in seen:
            raise ValueError(f"duplicate cross-lane trigger id {trigger_id!r} in {path}")
        seen.add(trigger_id)
        notify = trigger.get("notify")
        if not isinstance(notify, list) or not notify or not all(isinstance(family, str) for family in notify):
            raise ValueError(f"cross-lane trigger {trigger_id!r} notify must be a non-empty string list in {path}")
        for family in notify:
            if family not in lanes:
                raise ValueError(f"cross-lane trigger {trigger_id!r} notifies unknown lane {family!r} in {path}")
        when = trigger.get("when")
        if not isinstance(when, dict):
            raise ValueError(f"cross-lane trigger {trigger_id!r} must declare a when object in {path}")
        normalized = dict(trigger)
        normalized["path"] = path
        triggers.append(normalized)
    return triggers


def load_profile(profile_id: str, profiles_dir: Path) -> dict[str, Any]:
    profile_root = profiles_dir / profile_id
    profile_path = profile_root / "profile.yaml"
    if not profile_path.exists():
        raise FileNotFoundError(f"profile does not exist: {profile_path}")

    profile = load_json_or_yaml(profile_path)
    if not isinstance(profile, dict):
        raise ValueError(f"profile file must be an object: {profile_path}")
    declared_profile_id = profile.get("id")
    if declared_profile_id is not None and declared_profile_id != profile_id:
        raise ValueError(f"profile file id {declared_profile_id!r} does not match selected profile {profile_id!r}: {profile_path}")

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
        if lane["id"] in lanes:
            raise ValueError(f"duplicate lane id {lane['id']!r} in {lanes_path}")
        lanes.add(lane["id"])
        lane_order.append(lane["id"])

    specialists: set[str] = set()
    specialist_modes: dict[str, str] = {}
    for index, specialist in enumerate(lanes_data.get("specialists", [])):
        if not isinstance(specialist, dict) or not isinstance(specialist.get("id"), str):
            raise ValueError(f"specialist entry {index} must contain an id in {lanes_path}")
        if specialist["id"] in specialists:
            raise ValueError(f"duplicate specialist id {specialist['id']!r} in {lanes_path}")
        if specialist["id"] in lanes:
            raise ValueError(f"specialist id {specialist['id']!r} conflicts with a lane id in {lanes_path}")
        specialists.add(specialist["id"])
        if isinstance(specialist.get("mode"), str):
            specialist_modes[specialist["id"]] = specialist["mode"]

    if not lanes:
        raise ValueError(f"profile must define at least one lane: {lanes_path}")

    strategies, strategy_order = load_catalog_items(profile_root, profile_id, profile.get("strategy_source"), "strategies")
    overlays, overlay_order = load_catalog_items(profile_root, profile_id, profile.get("overlay_source"), "overlays")
    cross_lane_triggers = load_cross_lane_triggers(profile_root, profile.get("cross_lane_trigger_source"), lanes)

    implemented = profile.get("implemented")
    if implemented is None:
        implemented = profile.get("status") in {"stable", "bundled"}

    return {
        "id": profile_id,
        "implemented": bool(implemented),
        "report_sidecar_schema": profile.get("report_sidecar_schema", "report-sidecar.schema.json"),
        "lanes": lanes,
        "lane_order": lane_order,
        "specialists": specialists,
        "specialist_modes": specialist_modes,
        "families": lanes | specialists,
        "strategies": strategies,
        "strategy_order": strategy_order,
        "overlays": overlays,
        "overlay_order": overlay_order,
        "default_strategy": profile.get("default_strategy"),
        "default_overlays": profile.get("default_overlays", []),
        "cross_lane_triggers": cross_lane_triggers,
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
    allow_experimental: bool = False,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    lanes = selected_profile["lanes"]
    families = selected_profile["families"]
    strategies = selected_profile.get("strategies", {})
    overlays = selected_profile.get("overlays", {})
    profile_id = selected_profile["id"]

    if sidecar.get("profile") != profile_id:
        issues.append(ValidationIssue(sidecar_path, "$.profile", f"expected selected profile {profile_id!r}, got {sidecar.get('profile')!r}"))

    strategy = sidecar.get("strategy")
    if isinstance(strategy, str):
        strategy_config = strategies.get(strategy)
        if strategy_config is None:
            issues.append(ValidationIssue(sidecar_path, "$.strategy", f"strategy {strategy!r} is not defined by profile {profile_id!r}"))
        else:
            if strategy == "auto":
                issues.append(ValidationIssue(sidecar_path, "$.strategy", "strategy 'auto' is only valid before calibration; sidecars must use the resolved concrete strategy"))
            status = strategy_config.get("status")
            if (strategy_config.get("runnable") is False or status == "planned") and not allow_experimental:
                issues.append(ValidationIssue(sidecar_path, "$.strategy", f"strategy {strategy!r} is not runnable; pass --allow-experimental only for catalog compatibility checks"))
            allowed_modes = strategy_config.get("allowed_modes", set())
            mode = sidecar.get("mode")
            if isinstance(mode, str) and allowed_modes and mode not in allowed_modes:
                issues.append(ValidationIssue(sidecar_path, "$.mode", f"mode {mode!r} is not allowed by strategy {strategy!r}"))
    elif strategy is not None:
        issues.append(ValidationIssue(sidecar_path, "$.strategy", "strategy must be a string"))

    sidecar_overlays = sidecar.get("overlays", [])
    if isinstance(sidecar_overlays, list):
        if not sidecar_overlays:
            issues.append(ValidationIssue(sidecar_path, "$.overlays", "overlays must contain at least one overlay id"))
        for index, overlay in enumerate(sidecar_overlays):
            if isinstance(overlay, str) and overlay not in overlays:
                issues.append(ValidationIssue(sidecar_path, f"$.overlays[{index}]", f"overlay {overlay!r} is not defined by profile {profile_id!r}"))
            if isinstance(overlay, str) and overlay in overlays:
                overlay_config = overlays[overlay]
                status = overlay_config.get("status")
                if (overlay_config.get("runnable") is False or status == "planned") and not allow_experimental:
                    issues.append(ValidationIssue(sidecar_path, f"$.overlays[{index}]", f"overlay {overlay!r} is not runnable; pass --allow-experimental only for catalog compatibility checks"))
    elif sidecar_overlays is not None:
        issues.append(ValidationIssue(sidecar_path, "$.overlays", "overlays must be an array of overlay ids"))

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
    if sidecar.get("mode") == "runtime-safe":
        approval = run_metadata.get("runtime_approval") if run_metadata is not None else None
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
        if profile_id == "performance":
            mirror_fields = (
                "owner_family",
                "bottleneck_class",
                "resource_dimension",
                "root_cause_location",
                "trigger_load_condition",
                "budget_dimension",
                "cardinality_driver",
                "impact_boundary",
            )
        elif profile_id == "production-integrity":
            mirror_fields = ("owner_family", "control_objective", "failure_mode", "missing_control", "impact_boundary")
        else:
            mirror_fields = ("owner_family", "security_invariant", "missing_guard", "entrypoint", "impact_boundary")
        for field in mirror_fields:
            if field in finding and field in dedupe_key and finding[field] != dedupe_key[field]:
                issues.append(ValidationIssue(sidecar_path, f"$.confirmed_findings[{index}].dedupe_key.{field}", f"must mirror confirmed_finding.{field} exactly"))
        if profile_id == "performance":
            proof_level = finding.get("proof_level")
            severity = finding.get("severity")
            static_exception = finding.get("static_proof_exception") is True
            if severity in {"critical", "high"} and proof_level in {"P0-lead", "P1-candidate", "P1-static-structural"} and not static_exception:
                issues.append(ValidationIssue(
                    sidecar_path,
                    f"$.confirmed_findings[{index}].proof_level",
                    "high/critical performance findings require P2-or-stronger proof unless static_proof_exception=true",
                ))
        if sidecar.get("batch_id") == "batch-01" and finding.get("introduced_after_batch_01") is True:
            issues.append(ValidationIssue(sidecar_path, f"$.confirmed_findings[{index}].introduced_after_batch_01", "batch-01 findings must not be marked introduced_after_batch_01"))

    for index, lead in enumerate(sidecar.get("incidental_leads", [])):
        if not isinstance(lead, dict):
            continue
        noticed_by = lead.get("noticed_by_family")
        if isinstance(noticed_by, str) and noticed_by not in families:
            issues.append(ValidationIssue(sidecar_path, f"$.incidental_leads[{index}].noticed_by_family", f"family {noticed_by!r} is not defined by profile {profile_id!r}"))
        owner = lead.get("proposed_owner_family")
        if isinstance(owner, str) and owner not in lanes:
            issues.append(ValidationIssue(sidecar_path, f"$.incidental_leads[{index}].proposed_owner_family", f"owner family {owner!r} is not a lane in profile {profile_id!r}"))

    for index, smell in enumerate(sidecar.get("security_smells", [])):
        if not isinstance(smell, dict):
            continue
        owner = smell.get("recommended_owner")
        if isinstance(owner, str) and owner not in lanes:
            issues.append(ValidationIssue(sidecar_path, f"$.security_smells[{index}].recommended_owner", f"owner family {owner!r} is not a lane in profile {profile_id!r}"))

    for index, signal in enumerate(sidecar.get("risk_signals", [])):
        if not isinstance(signal, dict):
            continue
        owner = signal.get("recommended_owner")
        if isinstance(owner, str) and owner not in lanes:
            issues.append(ValidationIssue(sidecar_path, f"$.risk_signals[{index}].recommended_owner", f"owner family {owner!r} is not a lane in profile {profile_id!r}"))

    for index, local_check in enumerate(sidecar.get("run_local_checks", [])):
        if not isinstance(local_check, dict):
            continue
        owner = local_check.get("recommended_owner_family")
        if isinstance(owner, str) and owner not in lanes:
            issues.append(ValidationIssue(sidecar_path, f"$.run_local_checks[{index}].recommended_owner_family", f"owner family {owner!r} is not a lane in profile {profile_id!r}"))

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
        if profile_id == "performance":
            mirror_fields = (
                "proposed_owner_family",
                "summary",
                "files",
                "bottleneck_class",
                "resource_dimension",
                "root_cause_location",
                "trigger_load_condition",
                "impact_boundary",
            )
        elif profile_id == "production-integrity":
            mirror_fields = ("proposed_owner_family", "summary", "files", "suspected_missing_control", "impact_boundary")
        else:
            mirror_fields = ("proposed_owner_family", "summary", "files", "suspected_missing_guard", "impact_boundary")
        for field in mirror_fields:
            if candidate.get(field) != dedupe_key.get(field):
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
        if line_end is not None and line_start is None:
            issues.append(ValidationIssue(sidecar_path, f"{ref_location}.line_end", "requires line_start when present"))
        if isinstance(line_start, int) and isinstance(line_end, int) and line_end < line_start:
            issues.append(ValidationIssue(sidecar_path, f"{ref_location}.line_end", "must be greater than or equal to line_start"))
    return issues


def validate_path_list(
    sidecar_path: Path,
    location: str,
    values: Any,
    allow_auditlanes_run_input: bool = False,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if not isinstance(values, list):
        return issues
    for index, value in enumerate(values):
        issues.extend(validate_repo_relative_path_value(
            sidecar_path,
            f"{location}[{index}]",
            value,
            allow_auditlanes_run_input=allow_auditlanes_run_input,
        ))
    return issues


def validate_sidecar_repo_paths(sidecar_path: Path, sidecar: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    allow_auditlanes_run_input = (
        sidecar.get("profile") == "workflow-evidence"
        and sidecar.get("family") == "backlog-synthesis"
        and sidecar.get("mode") == "atlas-synthesis"
    )
    for field in ("reviewed_artifacts", "reviewed_files_routes_helpers"):
        issues.extend(validate_path_list(
            sidecar_path,
            f"$.{field}",
            sidecar.get(field),
            allow_auditlanes_run_input=allow_auditlanes_run_input,
        ))

    for collection_name in ("confirmed_findings", "candidate_findings", "incidental_leads"):
        collection = sidecar.get(collection_name, [])
        if not isinstance(collection, list):
            continue
        for index, item in enumerate(collection):
            if not isinstance(item, dict):
                continue
            if isinstance(item.get("files"), list):
                issues.extend(validate_path_list(sidecar_path, f"$.{collection_name}[{index}].files", item.get("files")))
            issues.extend(validate_evidence_refs(sidecar_path, f"$.{collection_name}[{index}].evidence_refs", item.get("evidence_refs")))

    for collection_name in ("runtime_updates", "profile_feedback", "proof_updates"):
        collection = sidecar.get(collection_name, [])
        if not isinstance(collection, list):
            continue
        for index, item in enumerate(collection):
            if isinstance(item, dict):
                issues.extend(validate_evidence_refs(sidecar_path, f"$.{collection_name}[{index}].evidence_refs", item.get("evidence_refs")))

    run_local_checks = sidecar.get("run_local_checks", [])
    if isinstance(run_local_checks, list):
        for index, local_check in enumerate(run_local_checks):
            if isinstance(local_check, dict):
                issues.extend(validate_evidence_refs(sidecar_path, f"$.run_local_checks[{index}].trigger_evidence_refs", local_check.get("trigger_evidence_refs")))

    security_smells = sidecar.get("security_smells", [])
    if isinstance(security_smells, list):
        for index, smell in enumerate(security_smells):
            if not isinstance(smell, dict):
                continue
            issues.extend(validate_repo_relative_path_value(sidecar_path, f"$.security_smells[{index}].path", smell.get("path")))
            line_start = smell.get("line_start")
            if line_start is not None and (not isinstance(line_start, int) or isinstance(line_start, bool) or line_start < 1):
                issues.append(ValidationIssue(sidecar_path, f"$.security_smells[{index}].line_start", "must be null or a 1-based line number"))

    risk_signals = sidecar.get("risk_signals", [])
    if isinstance(risk_signals, list):
        for index, signal in enumerate(risk_signals):
            if not isinstance(signal, dict):
                continue
            issues.extend(validate_repo_relative_path_value(sidecar_path, f"$.risk_signals[{index}].path", signal.get("path")))
            line_start = signal.get("line_start")
            if line_start is not None and (not isinstance(line_start, int) or isinstance(line_start, bool) or line_start < 1):
                issues.append(ValidationIssue(sidecar_path, f"$.risk_signals[{index}].line_start", "must be null or a 1-based line number"))

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


def manifest_sidecar_strategy_ids(run_dir: Path, manifest_path: Path, family_items: list[Any]) -> set[str]:
    strategy_ids: set[str] = set()
    for item in family_items:
        if not isinstance(item, dict) or item.get("status") != "ran":
            continue
        value = item.get("json")
        if not isinstance(value, str) or not value:
            continue
        try:
            report_path = resolve_run_path(run_dir, value, manifest_path.parent)
            sidecar = load_json(report_path)
        except Exception:  # noqa: BLE001
            continue
        if isinstance(sidecar, dict) and isinstance(sidecar.get("strategy"), str):
            strategy_ids.add(sidecar["strategy"])
    return strategy_ids


def batch_shape_expected_families(
    batch_shape: dict[str, Any],
    selected_profile: dict[str, Any],
) -> list[str] | None:
    expected_source = batch_shape.get("expected_families")
    if expected_source == "profile_lanes":
        return list(selected_profile["lane_order"])
    if expected_source == "profile_specialists":
        return sorted(selected_profile["specialists"])
    if isinstance(expected_source, list) and all(isinstance(item, str) for item in expected_source):
        return list(expected_source)
    return None


def validate_strategy_batch_shape(
    manifest_path: Path,
    path_batch_id: str | None,
    expected_items: list[Any],
    family_items: list[Any],
    selected_profile: dict[str, Any],
    strategy_id: str,
    strategy_config: dict[str, Any],
) -> list[ValidationIssue]:
    if path_batch_id is None:
        return []
    batch_shapes = strategy_config.get("batch_shape")
    if not isinstance(batch_shapes, dict):
        return []
    batch_shape = batch_shapes.get(path_batch_id)
    if not isinstance(batch_shape, dict):
        return []

    issues: list[ValidationIssue] = []
    expected_exact = batch_shape_expected_families(batch_shape, selected_profile)
    if expected_exact is not None and (set(expected_items) != set(expected_exact) or len(expected_items) != len(expected_exact)):
        if path_batch_id == "batch-01" and selected_profile["id"] == "security" and expected_exact == selected_profile["lane_order"]:
            message = "batch-01 security canonical sweep must include exactly the six security lanes"
        else:
            message = f"{path_batch_id} strategy {strategy_id!r} must include exactly the declared batch_shape families"
        issues.append(ValidationIssue(manifest_path, "$.expected_families", message))

    required_status = batch_shape.get("status")
    if required_status == "optional":
        required_status = None
    required_mode = batch_shape.get("mode")
    modes_by_family = batch_shape.get("modes_by_family")
    if not isinstance(modes_by_family, dict):
        modes_by_family = {}
    for index, item in enumerate(family_items):
        if not isinstance(item, dict):
            continue
        family = item.get("family")
        if isinstance(required_status, str) and item.get("status") != required_status:
            if path_batch_id == "batch-01" and selected_profile["id"] == "security" and required_status == "ran":
                message = "batch-01 security lanes must all run"
            else:
                message = f"{path_batch_id} strategy {strategy_id!r} families must have status={required_status}"
            issues.append(ValidationIssue(manifest_path, f"$.families[{index}].status", message))
        item_required_mode = modes_by_family.get(family, required_mode) if isinstance(family, str) else required_mode
        if isinstance(item_required_mode, str) and item.get("mode") != item_required_mode:
            if path_batch_id == "batch-01" and selected_profile["id"] == "security" and required_mode == "canonical-sweep":
                message = "batch-01 security lanes must run canonical-sweep"
            else:
                message = f"{path_batch_id} strategy {strategy_id!r} family {family!r} must run mode={item_required_mode}"
            issues.append(ValidationIssue(manifest_path, f"$.families[{index}].mode", message))
    return issues


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
    expected_strings = [family for family in expected_items if isinstance(family, str)]
    expected_duplicates = sorted({
        family for family in expected_strings
        if expected_strings.count(family) > 1
    })
    for family in expected_duplicates:
        issues.append(ValidationIssue(manifest_path, "$.expected_families", f"duplicate expected family {family!r}"))
    expected = set(expected_strings)

    family_items = manifest.get("families", [])
    if not isinstance(family_items, list):
        family_items = []
    seen_list = [
        item.get("family")
        for item in family_items
        if isinstance(item, dict) and isinstance(item.get("family"), str)
    ]
    seen = set(seen_list)
    for family in sorted({family for family in seen_list if seen_list.count(family) > 1}):
        issues.append(ValidationIssue(manifest_path, "$.families", f"duplicate family entry {family!r}"))
    for family in sorted(seen - expected):
        issues.append(ValidationIssue(manifest_path, "$.families", f"family {family!r} is not listed in expected_families"))
    missing = expected - seen
    for family in sorted(missing):
        issues.append(ValidationIssue(manifest_path, "$.families", f"expected family {family!r} is not represented"))

    manifest_strategy_ids = manifest_sidecar_strategy_ids(run_dir, manifest_path, family_items)
    if len(manifest_strategy_ids) > 1:
        issues.append(ValidationIssue(manifest_path, "$.families", f"batch manifest references multiple sidecar strategies: {sorted(manifest_strategy_ids)!r}"))
    elif manifest_strategy_ids:
        strategy_id = next(iter(manifest_strategy_ids))
        strategy_config = selected_profile.get("strategies", {}).get(strategy_id)
        if isinstance(strategy_config, dict):
            issues.extend(validate_strategy_batch_shape(
                manifest_path,
                path_batch_id,
                expected_strings,
                family_items,
                selected_profile,
                strategy_id,
                strategy_config,
            ))
    if path_batch_id == "batch-04" and selected_profile["id"] == "security":
        specialists = selected_profile["specialists"]
        if set(expected_strings) != set(specialists) or len(expected_strings) != len(specialists):
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
            if field == "markdown":
                plain_file_issues = require_plain_file_under(run_dir, raw_output, "markdown report")
                if plain_file_issues:
                    issues.extend(plain_file_issues)
                    continue
                issues.extend(validate_markdown_report_path(run_dir, raw_output, path_batch_id, family))
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


def validate_markdown_report_path(
    run_dir: Path,
    path: Path,
    expected_batch_id: str | None,
    expected_family: Any,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    try:
        relative = path.resolve().relative_to(run_dir.resolve())
    except ValueError:
        return [ValidationIssue(path, "$", "markdown report path is outside RUN_DIR")]

    parts = relative.parts
    if len(parts) != 4 or parts[0] != "reports" or parts[3] != "report.md":
        issues.append(ValidationIssue(path, "$", "markdown report must live at reports/<batch-id>/<family>/report.md"))
        return issues
    if expected_batch_id is not None and parts[1] != expected_batch_id:
        issues.append(ValidationIssue(path, "$", f"markdown report batch path must match manifest batch {expected_batch_id!r}"))
    if isinstance(expected_family, str) and parts[2] != expected_family:
        issues.append(ValidationIssue(path, "$", f"markdown report family path must match manifest family {expected_family!r}"))
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


def validate_jsonl_file(path: Path, schema: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                text = line.strip()
                if not text:
                    continue
                try:
                    row = json.loads(text)
                except json.JSONDecodeError as exc:
                    issues.append(ValidationIssue(path, f"$[{line_number}]", f"could not parse JSONL row: {exc}"))
                    continue
                for message in validate_schema(row, schema):
                    location = message.split(":", 1)[0]
                    detail = message.split(":", 1)[1].strip() if ":" in message else message
                    issues.append(ValidationIssue(path, f"$[{line_number}]{location[1:] if location.startswith('$') else location}", detail))
    except Exception as exc:  # noqa: BLE001
        issues.append(ValidationIssue(path, "$", f"could not read JSONL file: {exc}"))
    return issues


def parsed_jsonl_rows(path: Path) -> list[tuple[int, Any]]:
    rows: list[tuple[int, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                text = line.strip()
                if not text:
                    continue
                try:
                    rows.append((line_number, json.loads(text)))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return rows
    return rows


def validate_evidence_ref_semantics(path: Path, location: str, refs: Any) -> list[ValidationIssue]:
    issues = validate_evidence_refs(path, location, refs)
    if not isinstance(refs, list):
        return issues

    required_fields = ("path", "line_start", "evidence_type", "rationale")
    for index, ref in enumerate(refs):
        if not isinstance(ref, dict):
            continue
        ref_location = f"{location}[{index}]"
        for field in required_fields:
            if field not in ref:
                issues.append(ValidationIssue(path, f"{ref_location}.{field}", "missing required evidence field"))
        if "path" in ref and (not isinstance(ref.get("path"), str) or not ref.get("path")):
            issues.append(ValidationIssue(path, f"{ref_location}.path", "must be a non-empty repository-relative path"))
        if "rationale" in ref and (not isinstance(ref.get("rationale"), str) or not ref.get("rationale")):
            issues.append(ValidationIssue(path, f"{ref_location}.rationale", "must be a non-empty string"))
    return issues


def validate_state_artifact_semantics(
    artifact_path: Path,
    artifact_name: str,
    selected_profile: dict[str, Any],
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    lanes = selected_profile["lanes"]
    profile_id = selected_profile["id"]

    for line_number, row in parsed_jsonl_rows(artifact_path):
        if not isinstance(row, dict):
            continue
        for field in STATE_LANE_FIELDS.get(artifact_name, ()):
            value = row.get(field)
            if isinstance(value, str) and value not in lanes:
                issues.append(ValidationIssue(
                    artifact_path,
                    f"$[{line_number}].{field}",
                    f"owner family {value!r} is not a lane in profile {profile_id!r}",
                ))
        for field in STATE_LANE_LIST_FIELDS.get(artifact_name, ()):
            values = row.get(field, [])
            if not isinstance(values, list):
                continue
            for index, value in enumerate(values):
                if isinstance(value, str) and value not in lanes:
                    issues.append(ValidationIssue(
                        artifact_path,
                        f"$[{line_number}].{field}[{index}]",
                        f"owner family {value!r} is not a lane in profile {profile_id!r}",
                    ))
        if artifact_name in STATE_EVIDENCE_ARTIFACTS and "evidence_refs" in row:
            issues.extend(validate_evidence_ref_semantics(
                artifact_path,
                f"$[{line_number}].evidence_refs",
                row.get("evidence_refs"),
            ))
    return issues


def validate_state_artifact(
    run_dir: Path,
    schemas_dir: Path,
    relative_artifact: str,
    origins: list[str],
    selected_profile: dict[str, Any] | None = None,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    artifact_path = run_dir / relative_artifact
    if not artifact_path.exists():
        issues.append(ValidationIssue(artifact_path, "$", f"required state artifact is missing (required by {', '.join(origins)})"))
        return issues

    plain_file_issues = require_plain_file_under(run_dir, artifact_path, "state artifact")
    if plain_file_issues:
        return plain_file_issues

    schema_name = STATE_ARTIFACT_SCHEMAS.get(Path(relative_artifact).name)
    if not schema_name:
        return issues
    schema_path = schemas_dir / schema_name
    if not schema_path.exists():
        issues.append(ValidationIssue(schema_path, "$", f"schema for state artifact {relative_artifact!r} is missing"))
        return issues
    schema = load_json(schema_path)
    if artifact_path.suffix == ".jsonl":
        issues.extend(validate_jsonl_file(artifact_path, schema))
        if selected_profile is not None:
            issues.extend(validate_state_artifact_semantics(artifact_path, artifact_path.name, selected_profile))
    else:
        issues.extend(validate_file(artifact_path, schema, load_json_or_yaml))
    return issues


def validate_present_state_artifacts(
    run_dir: Path,
    schemas_dir: Path,
    selected_profile: dict[str, Any],
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    state_dir = run_dir / "state"
    if not state_dir.exists():
        return issues
    if state_dir.is_symlink():
        return [ValidationIssue(state_dir, "$", "symlinked state directory is not allowed")]

    for artifact_name in sorted(STATE_ARTIFACT_SCHEMAS):
        artifact_path = state_dir / artifact_name
        if artifact_path.exists():
            issues.extend(validate_state_artifact(
                run_dir,
                schemas_dir,
                f"state/{artifact_name}",
                ["present-state-artifact"],
                selected_profile,
            ))
    return issues


def validate_required_state_artifacts(
    run_dir: Path,
    schemas_dir: Path,
    selected_profile: dict[str, Any],
    sidecars: list[tuple[Path, dict[str, Any]]],
) -> list[ValidationIssue]:
    requirements: dict[str, list[str]] = {}
    strategies = selected_profile.get("strategies", {})
    overlays = selected_profile.get("overlays", {})

    for _, sidecar in sidecars:
        strategy = sidecar.get("strategy")
        if isinstance(strategy, str) and isinstance(strategies.get(strategy), dict):
            for artifact in strategies[strategy].get("required_state_artifacts", []) or []:
                if isinstance(artifact, str) and artifact:
                    requirements.setdefault(artifact, []).append(f"strategy:{strategy}")
        sidecar_overlays = sidecar.get("overlays", [])
        if isinstance(sidecar_overlays, list):
            for overlay in sidecar_overlays:
                if isinstance(overlay, str) and isinstance(overlays.get(overlay), dict):
                    for artifact in overlays[overlay].get("required_artifacts", []) or []:
                        if isinstance(artifact, str) and artifact:
                            requirements.setdefault(artifact, []).append(f"overlay:{overlay}")

    issues: list[ValidationIssue] = []
    if requirements and (run_dir / "state").is_symlink():
        return [ValidationIssue(run_dir / "state", "$", "symlinked state directory is not allowed")]
    for artifact, origins in sorted(requirements.items()):
        if (run_dir / artifact).exists():
            continue
        issues.extend(validate_state_artifact(run_dir, schemas_dir, artifact, sorted(set(origins)), selected_profile))
    return issues


def validate_relevance_plan_consistency(
    run_dir: Path,
    schemas_dir: Path,
    selected_profile: dict[str, Any],
    sidecars: list[tuple[Path, dict[str, Any]]],
    allow_experimental: bool,
) -> list[ValidationIssue]:
    path = run_dir / "state" / "relevance-plan.yaml"
    if not path.exists():
        return []

    issues = require_plain_file_under(run_dir, path, "relevance plan")
    if issues:
        return issues
    try:
        plan = load_json_or_yaml(path)
    except Exception as exc:  # noqa: BLE001
        return [ValidationIssue(path, "$", f"could not parse relevance plan: {exc}")]
    if not isinstance(plan, dict):
        return [ValidationIssue(path, "$", "relevance plan must be an object")]

    profile_id = selected_profile["id"]
    if plan.get("profile") != profile_id:
        issues.append(ValidationIssue(path, "$.profile", f"expected selected profile {profile_id!r}, got {plan.get('profile')!r}"))

    strategies = selected_profile.get("strategies", {})
    overlays = selected_profile.get("overlays", {})
    resolved_strategy = plan.get("resolved_strategy")
    if isinstance(resolved_strategy, str):
        strategy_config = strategies.get(resolved_strategy)
        if strategy_config is None:
            issues.append(ValidationIssue(path, "$.resolved_strategy", f"strategy {resolved_strategy!r} is not defined by profile {profile_id!r}"))
        elif resolved_strategy == "auto":
            issues.append(ValidationIssue(path, "$.resolved_strategy", "strategy 'auto' must resolve to a concrete strategy"))
        elif (strategy_config.get("runnable") is False or strategy_config.get("status") == "planned") and not allow_experimental:
            issues.append(ValidationIssue(path, "$.resolved_strategy", f"strategy {resolved_strategy!r} is not runnable"))
    requested_strategy = plan.get("requested_strategy")
    if requested_strategy == "auto" and isinstance(resolved_strategy, str) and resolved_strategy != "auto":
        for sidecar_path, sidecar in sidecars:
            if sidecar.get("strategy") != resolved_strategy:
                issues.append(ValidationIssue(sidecar_path, "$.strategy", f"must match auto-resolved strategy {resolved_strategy!r} from state/relevance-plan.yaml"))

    resolved_overlays = plan.get("resolved_overlays", [])
    if isinstance(resolved_overlays, list):
        for index, overlay in enumerate(resolved_overlays):
            if isinstance(overlay, str) and overlay not in overlays:
                issues.append(ValidationIssue(path, f"$.resolved_overlays[{index}]", f"overlay {overlay!r} is not defined by profile {profile_id!r}"))
        if requested_strategy == "auto":
            expected_overlays = {overlay for overlay in resolved_overlays if isinstance(overlay, str)}
            for sidecar_path, sidecar in sidecars:
                sidecar_overlays = sidecar.get("overlays", [])
                actual_overlays = set(sidecar_overlays) if isinstance(sidecar_overlays, list) and all(isinstance(overlay, str) for overlay in sidecar_overlays) else set()
                if actual_overlays != expected_overlays:
                    issues.append(ValidationIssue(
                        sidecar_path,
                        "$.overlays",
                        f"must match auto-resolved overlays from state/relevance-plan.yaml: {sorted(expected_overlays)!r}",
                    ))
    return issues


def sidecar_schema_for_profile(
    schemas_dir: Path,
    selected_profile: dict[str, Any],
    profile: str,
) -> tuple[Path, dict[str, Any]] | tuple[None, None]:
    schema_name = selected_profile.get("report_sidecar_schema", "report-sidecar.schema.json")
    if not isinstance(schema_name, str) or not schema_name:
        return None, None
    sidecar_schema_path = schemas_dir / schema_name
    if not sidecar_schema_path.exists():
        return sidecar_schema_path, None
    return sidecar_schema_path, load_json(sidecar_schema_path)


def validate_sidecar_file(
    run_dir: Path,
    sidecar_path: Path,
    schemas_dir: Path,
    profile: str = DEFAULT_PROFILE,
    profiles_dir: Path = DEFAULT_PROFILES_DIR,
    allow_experimental: bool = False,
) -> list[ValidationIssue]:
    try:
        selected_profile = load_profile(profile, profiles_dir)
    except Exception as exc:  # noqa: BLE001
        return [ValidationIssue(profiles_dir / profile, "$", f"could not load profile: {exc}")]

    schema_path, sidecar_schema = sidecar_schema_for_profile(schemas_dir, selected_profile, profile)
    if schema_path is None:
        return [ValidationIssue(selected_profile["profile_path"], "$.report_sidecar_schema", "must be a non-empty schema filename")]
    if sidecar_schema is None:
        return [ValidationIssue(schema_path, "$", f"report sidecar schema for profile {profile!r} is missing")]

    path = sidecar_path if sidecar_path.is_absolute() else run_dir / sidecar_path
    path = path.resolve()
    issues = require_plain_file_under(run_dir, path, "sidecar")
    if issues:
        return issues

    try:
        sidecar = load_json(path)
    except Exception as exc:  # noqa: BLE001
        return [ValidationIssue(path, "$", f"could not parse sidecar: {exc}")]

    for message in validate_schema(sidecar, sidecar_schema):
        issues.append(ValidationIssue(path, message.split(":", 1)[0], message.split(":", 1)[1].strip() if ":" in message else message))
    if isinstance(sidecar, dict):
        expected_version = package_version()
        run_metadata, metadata_issues = load_optional_run_metadata(run_dir)
        issues.extend(metadata_issues)
        issues.extend(validate_sidecar_path(run_dir, path, sidecar))
        issues.extend(validate_sidecar_profile(path, sidecar, selected_profile, run_metadata, expected_version, allow_experimental))
    return issues


def validate_jsonl_parseable_file(path: Path) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                text = line.strip()
                if not text:
                    continue
                try:
                    json.loads(text)
                except json.JSONDecodeError as exc:
                    issues.append(ValidationIssue(path, f"$[{line_number}]", f"could not parse JSONL row: {exc}"))
    except Exception as exc:  # noqa: BLE001
        issues.append(ValidationIssue(path, "$", f"could not read JSONL file: {exc}"))
    return issues


def validate_state_only(
    run_dir: Path,
    schemas_dir: Path,
    profile: str = DEFAULT_PROFILE,
    profiles_dir: Path = DEFAULT_PROFILES_DIR,
    allow_experimental: bool = False,
    include_relevance_plan: bool = False,
) -> list[ValidationIssue]:
    del allow_experimental
    try:
        selected_profile = load_profile(profile, profiles_dir)
    except Exception as exc:  # noqa: BLE001
        return [ValidationIssue(profiles_dir / profile, "$", f"could not load profile: {exc}")]

    state_dir = run_dir / "state"
    if not state_dir.exists():
        return [ValidationIssue(state_dir, "$", "state-only validation requires reducer-owned state output")]
    if state_dir.is_symlink():
        return [ValidationIssue(state_dir, "$", "symlinked state directory is not allowed")]
    if not state_dir.is_dir():
        return [ValidationIssue(state_dir, "$", "state path exists but is not a directory")]

    issues: list[ValidationIssue] = []
    required = ("finding-inventory.jsonl", "run-events.jsonl")
    for filename in required:
        if not (state_dir / filename).exists():
            issues.append(ValidationIssue(state_dir / filename, "$", "state-only validation requires this reducer-owned artifact"))

    for artifact_path in sorted(state_dir.iterdir()):
        if artifact_path.is_dir():
            continue
        plain_file_issues = require_plain_file_under(run_dir, artifact_path, "state artifact")
        if plain_file_issues:
            issues.extend(plain_file_issues)
            continue
        artifact_name = artifact_path.name
        if artifact_name in {"relevance-plan.yaml", "relevance-plan.yml"} and not include_relevance_plan:
            continue
        if artifact_name in STATE_ARTIFACT_SCHEMAS:
            issues.extend(validate_state_artifact(
                run_dir,
                schemas_dir,
                f"state/{artifact_name}",
                ["state-only"],
                selected_profile,
            ))
        elif artifact_path.suffix == ".jsonl":
            issues.extend(validate_jsonl_parseable_file(artifact_path))
        elif artifact_path.suffix in {".json", ".yaml", ".yml"}:
            try:
                load_json_or_yaml(artifact_path)
            except Exception as exc:  # noqa: BLE001
                issues.append(ValidationIssue(artifact_path, "$", f"could not parse state artifact: {exc}"))

    summary_path = run_dir / "reducer" / "summary.json"
    if summary_path.exists():
        plain_file_issues = require_plain_file_under(run_dir, summary_path, "reducer summary")
        if plain_file_issues:
            issues.extend(plain_file_issues)
        else:
            try:
                summary = load_json(summary_path)
            except Exception as exc:  # noqa: BLE001
                issues.append(ValidationIssue(summary_path, "$", f"could not parse reducer summary: {exc}"))
            else:
                if not isinstance(summary, dict):
                    issues.append(ValidationIssue(summary_path, "$", "reducer summary must be an object"))

    return issues


def complete_batch_manifest_path(run_dir: Path, batch_id: str) -> Path:
    for name in MANIFEST_FILENAMES:
        path = run_dir / "reports" / batch_id / name
        if path.exists():
            return path
    return run_dir / "reports" / batch_id / "manifest.yaml"


def reducer_run_batches(run_dir: Path) -> set[str]:
    batches: set[str] = set()
    path = run_dir / "state" / "run-events.jsonl"
    for _, row in parsed_jsonl_rows(path):
        if not isinstance(row, dict) or row.get("event_type") != "reducer-run":
            continue
        batch_id = row.get("batch_id")
        if isinstance(batch_id, str) and batch_id:
            batches.add(batch_id)
    return batches


def validate_completed_batch(
    run_dir: Path,
    selected_profile: dict[str, Any],
    batch_id: str,
    requirement: dict[str, Any],
) -> list[ValidationIssue]:
    manifest_path = complete_batch_manifest_path(run_dir, batch_id)
    if not manifest_path.exists():
        return [ValidationIssue(manifest_path, "$", f"complete security run requires {batch_id} manifest")]

    issues = require_plain_file_under(run_dir, manifest_path, "manifest")
    if issues:
        return issues
    try:
        manifest = load_json_or_yaml(manifest_path)
    except Exception as exc:  # noqa: BLE001
        return [ValidationIssue(manifest_path, "$", f"could not parse manifest: {exc}")]
    if not isinstance(manifest, dict):
        return [ValidationIssue(manifest_path, "$", "manifest must be an object")]

    if manifest.get("manifest_status") != "completed":
        issues.append(ValidationIssue(manifest_path, "$.manifest_status", "complete security run requires completed manifests for required batches"))

    expected_source = requirement.get("families")
    if expected_source == "lanes":
        expected_families = set(selected_profile["lane_order"])
    elif expected_source == "specialists":
        expected_families = set(selected_profile["specialists"])
    else:
        expected_families = set()

    actual_items = manifest.get("families", [])
    if not isinstance(actual_items, list):
        actual_items = []
    actual_families = {
        item.get("family")
        for item in actual_items
        if isinstance(item, dict) and isinstance(item.get("family"), str)
    }
    if actual_families != expected_families:
        issues.append(ValidationIssue(
            manifest_path,
            "$.families",
            f"complete security run requires {batch_id} families {sorted(expected_families)!r}",
        ))

    ran_modes = requirement.get("ran_modes", set())
    allow_parked = bool(requirement.get("allow_parked"))
    for index, item in enumerate(actual_items):
        if not isinstance(item, dict):
            continue
        family = item.get("family")
        if family not in expected_families:
            continue
        status = item.get("status")
        mode = item.get("mode")
        if status == "ran":
            if mode not in ran_modes:
                issues.append(ValidationIssue(
                    manifest_path,
                    f"$.families[{index}].mode",
                    f"complete security run requires {batch_id} ran families to use one of {sorted(ran_modes)!r}",
                ))
        elif status == "parked" and allow_parked:
            if mode != "parked" or not item.get("carried_forward_from"):
                issues.append(ValidationIssue(
                    manifest_path,
                    f"$.families[{index}]",
                    f"complete security run requires parked {batch_id} families to use mode=parked and carried_forward_from",
                ))
        else:
            issues.append(ValidationIssue(
                manifest_path,
                f"$.families[{index}].status",
                f"complete security run does not allow status {status!r} in {batch_id}",
            ))
    return issues


def validate_final_markdown_artifact(run_dir: Path, relative_path: str) -> list[ValidationIssue]:
    path = run_dir / relative_path
    if not path.exists():
        return [ValidationIssue(path, "$", "complete security run requires final pre-fix report artifact")]
    issues = require_plain_file_under(run_dir, path, "final report")
    if issues:
        return issues
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        return [ValidationIssue(path, "$", f"could not read final report artifact: {exc}")]
    if not text.strip():
        return [ValidationIssue(path, "$", "final report artifact must not be empty")]
    return []


def validate_completion(
    run_dir: Path,
    profile: str = DEFAULT_PROFILE,
    profiles_dir: Path = DEFAULT_PROFILES_DIR,
) -> list[ValidationIssue]:
    try:
        selected_profile = load_profile(profile, profiles_dir)
    except Exception as exc:  # noqa: BLE001
        return [ValidationIssue(profiles_dir / profile, "$", f"could not load profile: {exc}")]

    if selected_profile["id"] != "security":
        return [ValidationIssue(selected_profile["profile_path"], "$.id", "completion gate is currently defined for the security profile")]

    issues: list[ValidationIssue] = []
    for batch_id, requirement in SECURITY_COMPLETE_BATCHES.items():
        issues.extend(validate_completed_batch(run_dir, selected_profile, batch_id, requirement))

    reducer_batches = reducer_run_batches(run_dir)
    for batch_id in SECURITY_COMPLETE_BATCHES:
        if batch_id not in reducer_batches:
            issues.append(ValidationIssue(
                run_dir / "state" / "run-events.jsonl",
                "$",
                f"complete security run requires a reducer-run event for {batch_id}",
            ))

    for relative_path in SECURITY_PRE_FIX_FINAL_ARTIFACTS:
        issues.extend(validate_final_markdown_artifact(run_dir, relative_path))

    return issues


def validate_run(
    run_dir: Path,
    schemas_dir: Path,
    profile: str = DEFAULT_PROFILE,
    profiles_dir: Path = DEFAULT_PROFILES_DIR,
    allow_experimental: bool = False,
    batch_id: str | None = None,
    family: str | None = None,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []

    try:
        selected_profile = load_profile(profile, profiles_dir)
    except Exception as exc:  # noqa: BLE001
        return [ValidationIssue(profiles_dir / profile, "$", f"could not load profile: {exc}")]

    sidecar_schema_path, sidecar_schema = sidecar_schema_for_profile(schemas_dir, selected_profile, profile)
    if sidecar_schema_path is None:
        return [ValidationIssue(selected_profile["profile_path"], "$.report_sidecar_schema", "must be a non-empty schema filename")]
    if sidecar_schema is None:
        return [ValidationIssue(sidecar_schema_path, "$", f"report sidecar schema for profile {profile!r} is missing")]
    manifest_schema = load_json(schemas_dir / "batch-manifest.schema.json")

    if not selected_profile["implemented"] and not allow_experimental:
        issues.append(ValidationIssue(selected_profile["profile_path"], "$.implemented", f"profile {profile!r} is not implemented; pass --allow-experimental only for metadata checks"))
    expected_version = package_version()
    run_metadata, metadata_issues = load_optional_run_metadata(run_dir)
    issues.extend(metadata_issues)

    manifests = manifest_paths(run_dir, batch_id)
    sidecars = sidecar_paths(run_dir, batch_id, family)
    referenced_sidecars: dict[Path, int] = {}
    parsed_sidecars: list[tuple[Path, dict[str, Any]]] = []

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
            parsed_sidecars.append((sidecar_path, sidecar))
            issues.extend(validate_sidecar_path(run_dir, sidecar_path, sidecar))
            issues.extend(validate_sidecar_profile(sidecar_path, sidecar, selected_profile, run_metadata, expected_version, allow_experimental))

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

    issues.extend(validate_present_state_artifacts(run_dir, schemas_dir, selected_profile))
    issues.extend(validate_required_state_artifacts(run_dir, schemas_dir, selected_profile, parsed_sidecars))
    issues.extend(validate_relevance_plan_consistency(run_dir, schemas_dir, selected_profile, parsed_sidecars, allow_experimental))

    return issues


def issue_group_key(run_dir: Path, issue: ValidationIssue) -> tuple[str, str]:
    try:
        rel = issue.path.resolve().relative_to(run_dir.resolve()).as_posix()
    except (OSError, RuntimeError, ValueError):
        rel = issue.path.as_posix()

    parts = rel.split("/")
    if len(parts) >= 4 and parts[0] == "reports" and parts[1].startswith("batch-"):
        artifact = f"{parts[1]}/{parts[2]}"
    elif parts and parts[0] in {"state", "reducer"}:
        artifact = "/".join(parts[:2]) if len(parts) > 1 else parts[0]
    else:
        artifact = rel

    location = re.sub(r"\[\d+\]", "", issue.location)
    if location.startswith("$."):
        location = location[2:]
    elif location == "$":
        location = "root"
    if location.startswith("["):
        location = f"row{location}"
    field_parts = [part for part in re.split(r"[.\[\]]", location) if part]
    if len(field_parts) >= 2:
        field = ".".join(field_parts[:2])
    else:
        field = field_parts[0] if field_parts else location
    missing_match = re.search(r"missing required property '([^']+)'", issue.message)
    if missing_match and field != "root":
        field = f"{field}.{missing_match.group(1)}"
    return artifact, field


def print_issues(issues: list[ValidationIssue], run_dir: Path, grouped: bool = False, max_per_group: int = 3) -> None:
    if not grouped:
        for issue in issues:
            print(issue.format(), file=sys.stderr)
        return

    groups: dict[tuple[str, str], list[ValidationIssue]] = {}
    for issue in issues:
        groups.setdefault(issue_group_key(run_dir, issue), []).append(issue)

    for (artifact, field), grouped_issues in sorted(groups.items(), key=lambda item: (-len(item[1]), item[0][0], item[0][1])):
        print(f"[{len(grouped_issues)}] {artifact} :: {field}", file=sys.stderr)
        for issue in grouped_issues[:max_per_group]:
            print(f"  - {issue.format()}", file=sys.stderr)
        omitted = len(grouped_issues) - max_per_group
        if omitted > 0:
            print(f"  - ... {omitted} more", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate AuditLanes run artifacts.")
    parser.add_argument("run_dir", type=Path, help="Path to auditlanes/out/runs/<run-id>.")
    parser.add_argument("--schemas-dir", type=Path, default=DEFAULT_SCHEMAS_DIR)
    parser.add_argument("--profile", default=DEFAULT_PROFILE, help="AuditLanes profile id to validate against.")
    parser.add_argument("--profiles-dir", type=Path, default=DEFAULT_PROFILES_DIR)
    parser.add_argument("--allow-experimental", action="store_true", help="Allow metadata-only profiles for profile-loading/catalog compatibility checks.")
    parser.add_argument("--batch-id", help="Validate only one batch, for example batch-01.")
    parser.add_argument("--family", help="Validate sidecars for one family/lane within the selected batch scope.")
    parser.add_argument("--sidecar", type=Path, help="Validate one report.json sidecar under the run directory without requiring a batch manifest.")
    parser.add_argument("--state-only", action="store_true", help="Validate reducer-owned state artifacts without revalidating original lane sidecars or manifests.")
    parser.add_argument("--complete", action="store_true", help="Require the full security AuditLanes protocol through batch-04, reducer passes, and pre-fix final artifacts.")
    parser.add_argument("--include-relevance-plan", action="store_true", help="With --state-only, also validate state/relevance-plan.yaml as an input planning artifact.")
    parser.add_argument("--grouped", action="store_true", help="Group validation errors by artifact and field.")
    parser.add_argument("--max-issues-per-group", type=int, default=3)
    parser.add_argument("--print-input-hashes", action="store_true")
    args = parser.parse_args(argv)

    run_dir = args.run_dir.resolve()
    if args.print_input_hashes:
        print(json.dumps(collect_input_hashes(run_dir, args.batch_id, args.family), indent=2, sort_keys=True))

    if args.sidecar and args.state_only:
        print("--sidecar and --state-only are mutually exclusive", file=sys.stderr)
        return 2
    if args.complete and (args.sidecar or args.state_only or args.batch_id or args.family):
        print("--complete validates a whole run and cannot be combined with --sidecar, --state-only, --batch-id, or --family", file=sys.stderr)
        return 2
    if args.include_relevance_plan and not args.state_only:
        print("--include-relevance-plan requires --state-only", file=sys.stderr)
        return 2

    if args.sidecar:
        issues = validate_sidecar_file(
            run_dir,
            args.sidecar,
            args.schemas_dir.resolve(),
            profile=args.profile,
            profiles_dir=args.profiles_dir.resolve(),
            allow_experimental=args.allow_experimental,
        )
    elif args.state_only:
        issues = validate_state_only(
            run_dir,
            args.schemas_dir.resolve(),
            profile=args.profile,
            profiles_dir=args.profiles_dir.resolve(),
            allow_experimental=args.allow_experimental,
            include_relevance_plan=args.include_relevance_plan,
        )
    else:
        issues = validate_run(
            run_dir,
            args.schemas_dir.resolve(),
            profile=args.profile,
            profiles_dir=args.profiles_dir.resolve(),
            allow_experimental=args.allow_experimental,
            batch_id=args.batch_id,
            family=args.family,
        )
        if args.complete:
            issues.extend(validate_completion(
                run_dir,
                profile=args.profile,
                profiles_dir=args.profiles_dir.resolve(),
            ))
    if issues:
        print_issues(issues, run_dir, args.grouped, max(1, args.max_issues_per_group))
        return 1

    print(f"AuditLanes validation passed: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
