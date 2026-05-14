#!/usr/bin/env python3
"""Static-only AuditLanes scan advisor.

The advisor is intentionally conservative: it reads file names and small text
files, infers a relevance plan, and never runs application code, tests,
installs, package scripts, containers, network calls, or runtime probes.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SMALL_REPO_LOC = 2000
MAX_FILE_BYTES = 256_000
MAX_TEXT_CHARS = 500_000

EXCLUDED_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    "target",
    "vendor",
}

LINE_COUNT_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".rs",
    ".rb",
    ".php",
    ".java",
    ".kt",
    ".cs",
    ".swift",
    ".html",
    ".jinja",
    ".jinja2",
    ".vue",
    ".svelte",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".env",
}

TEXT_EXTENSIONS = LINE_COUNT_EXTENSIONS | {
    ".txt",
    ".md",
    ".lock",
}

NON_APP_SIGNAL_DIR_NAMES = {
    "docs",
    "doc",
    "test",
    "tests",
    "fixtures",
    "examples",
}

LANGUAGE_BY_EXTENSION = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".java": "java",
    ".kt": "kotlin",
    ".cs": "dotnet",
    ".swift": "swift",
}

SIGNAL_EXTENSIONS = set(LANGUAGE_BY_EXTENSION.keys()) | {
    ".html",
    ".jinja",
    ".jinja2",
    ".vue",
    ".svelte",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
}

FRAMEWORK_PATTERNS = {
    "flask": [r"\bfrom\s+flask\s+import\b", r"\bFlask\s*\("],
    "django": [r"\bdjango\b", r"\burlpatterns\b", r"\bmodels\.Model\b"],
    "fastapi": [r"\bfrom\s+fastapi\s+import\b", r"\bFastAPI\s*\("],
    "starlette": [r"\bfrom\s+starlette\b"],
    "express": [r"\bexpress\s*\(", r"\bapp\.(get|post|put|delete|patch)\s*\("],
    "nextjs": [r"\bnext\b", r"pages/api", r"app/api"],
}

SURFACE_PATTERNS = {
    "cart": [r"['\"][^'\"]*/[^'\"]*(cart|basket)", r"\bdef\s+\w*(cart|basket)\w*\s*\(", r"\b(session|request\.(form|json|args)).{0,80}\b(cart|basket)\b"],
    "checkout": [r"['\"][^'\"]*/[^'\"]*checkout", r"\bdef\s+\w*checkout\w*\s*\(", r"\bcreate[_\.]?checkout[_\.]?session\b"],
    "order": [r"['\"][^'\"]*/[^'\"]*order", r"\bdef\s+\w*order\w*\s*\(", r"\border_id\s*[=:]"],
    "payment-session": [r"\bpayment_intent\s*[=:]", r"\bstripe\.checkout\.Session\.create\b", r"['\"][^'\"]*/[^'\"]*payment"],
    "webhook": [r"['\"][^'\"]*/[^'\"]*webhook", r"\bdef\s+\w*webhook\w*\s*\(", r"\bconstruct_event\s*\("],
    "callback": [r"['\"][^'\"]*/[^'\"]*callback", r"\bdef\s+\w*callback\w*\s*\(", r"\bredirect_uri\s*[=:]", r"\bnonce\s*[=:]"],
    "auth-session": [r"\bfrom\s+flask\s+import\b.*\bsession\b", r"\bsession\[", r"\bSECRET_KEY\s*=", r"['\"][^'\"]*/[^'\"]*(login|logout|csrf)"],
    "admin": [r"['\"][^'\"]*/[^'\"]*(admin|staff|support)", r"\bdef\s+\w*(admin|staff|support)\w*\s*\("],
    "upload": [r"['\"][^'\"]*/[^'\"]*upload", r"\brequest\.files\b", r"\bmultipart/form-data\b"],
    "download": [r"['\"][^'\"]*/[^'\"]*(download|export)", r"\bsend_file\s*\(", r"\battachment_filename\s*="],
    "database": [r"\bimport\s+sqlite3\b", r"\bfrom\s+sqlalchemy\b", r"\bexecute\s*\(\s*f?['\"].*\b(SELECT|INSERT|UPDATE|DELETE)\b"],
}

PAYMENT_PATTERNS = [
    r"\bimport\s+stripe\b",
    r"\bfrom\s+stripe\b",
    r"\bstripe\.",
    r"\bpaypalrestsdk\b",
    r"\bmollie\.api\b",
    r"\bbraintree\.",
    r"\badyen\.",
    r"\bpayment_intent\s*[=:]",
    r"\bcheckout\.Session\.create\b",
]

COMMERCE_SURFACES = {"cart", "checkout", "order"}

CONFIG_FILENAMES = {
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "poetry.lock",
    "package.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "Dockerfile",
    "docker-compose.yml",
}


def repo_relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def is_excluded(root: Path, path: Path) -> bool:
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        return True
    if len(parts) >= 2 and parts[0] == "auditlanes" and parts[1] == "out":
        return True
    if is_repo_local_auditlanes_control_file(root, path):
        return True
    return any(part in EXCLUDED_DIR_NAMES for part in parts)


def list_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if is_excluded(root, path):
            continue
        if path.is_file() and not path.is_symlink():
            files.append(path)
    return sorted(files)


def is_auditlanes_control_file(root: Path, path: Path) -> bool:
    parts = path.relative_to(root).parts
    if len(parts) < 3 or parts[0] != "plugins" or parts[1] != "auditlanes":
        return False
    if parts[2] in {"resources", "skills", "codex-skills"}:
        return True
    if parts[2] == "package-manifest.yaml":
        return True
    if parts[-1] == "scan_advisor.py":
        return True
    return False


def is_repo_local_auditlanes_control_file(root: Path, path: Path) -> bool:
    parts = path.relative_to(root).parts
    return len(parts) >= 1 and parts[0] == "auditlanes"


def is_signal_file(root: Path, path: Path) -> bool:
    if is_auditlanes_control_file(root, path):
        return False
    if is_repo_local_auditlanes_control_file(root, path):
        return False
    parts = path.relative_to(root).parts
    if any(part in NON_APP_SIGNAL_DIR_NAMES for part in parts):
        return False
    if path.name in CONFIG_FILENAMES:
        return True
    if parts and parts[0] == ".github":
        return True
    return path.suffix in SIGNAL_EXTENSIONS


def read_text_sample(path: Path) -> str:
    if path.stat().st_size > MAX_FILE_BYTES:
        return ""
    if path.suffix not in TEXT_EXTENSIONS and path.name not in CONFIG_FILENAMES:
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def collect_text(root: Path, files: list[Path]) -> tuple[str, dict[str, list[str]]]:
    parts: list[str] = []
    evidence: dict[str, list[str]] = {}
    total = 0
    for path in files:
        if not is_signal_file(root, path):
            continue
        text = read_text_sample(path)
        if not text:
            continue
        rel = repo_relative(root, path)
        evidence[rel] = text.splitlines()
        chunk = f"\n# {rel}\n{text}"
        if total + len(chunk) > MAX_TEXT_CHARS:
            break
        parts.append(chunk)
        total += len(chunk)
    return "\n".join(parts), evidence


def approximate_loc(root: Path, files: list[Path]) -> int:
    total = 0
    for path in files:
        if not is_signal_file(root, path):
            continue
        if path.suffix not in LINE_COUNT_EXTENSIONS and path.name not in CONFIG_FILENAMES:
            continue
        if path.stat().st_size > MAX_FILE_BYTES:
            continue
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                total += sum(1 for line in handle if line.strip())
        except OSError:
            continue
    return total


def detect_languages(files: list[Path]) -> list[str]:
    languages = {
        LANGUAGE_BY_EXTENSION[path.suffix]
        for path in files
        if path.suffix in LANGUAGE_BY_EXTENSION
    }
    if any(path.name == "requirements.txt" or path.name == "pyproject.toml" for path in files):
        languages.add("python")
    if any(path.name == "package.json" for path in files):
        languages.add("javascript")
    return sorted(languages)


def find_first_evidence(root: Path, evidence_text: dict[str, list[str]], patterns: list[str]) -> list[str]:
    refs: list[str] = []
    compiled = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    for rel, lines in evidence_text.items():
        for index, line in enumerate(lines, start=1):
            if any(pattern.search(line) for pattern in compiled):
                refs.append(f"{rel}:{index}")
                break
        if len(refs) >= 3:
            break
    return refs


def detect_named_patterns(text: str, patterns: dict[str, list[str]]) -> list[str]:
    found: list[str] = []
    for name, checks in patterns.items():
        if any(re.search(pattern, text, re.IGNORECASE) for pattern in checks):
            found.append(name)
    return sorted(found)


def detect_config(root: Path, files: list[Path]) -> list[str]:
    config = []
    for path in files:
        parts = path.relative_to(root).parts
        if path.name in CONFIG_FILENAMES:
            config.append(path.name)
        elif parts and parts[0] == ".github":
            config.append(repo_relative(root, path))
    return sorted(set(config))


def has_prior_runs(root: Path) -> bool:
    return (root / "auditlanes" / "out" / "runs").is_dir()


def has_strong_checkout_signal(surfaces: list[str], payment_detected: bool) -> bool:
    surface_set = set(surfaces)
    commerce_signals = surface_set & COMMERCE_SURFACES
    return "checkout" in commerce_signals and (
        payment_detected or "payment-session" in surface_set or len(commerce_signals) >= 2
    )


def archetypes(surfaces: list[str], frameworks: list[str], languages: list[str], payment_detected: bool) -> list[str]:
    result: set[str] = set()
    if set(surfaces) & COMMERCE_SURFACES:
        result.add("commerce-flow")
    if has_strong_checkout_signal(surfaces, payment_detected):
        result.add("checkout")
    if payment_detected or "payment-session" in surfaces:
        result.add("payment-flow")
    if frameworks or any(surface in surfaces for surface in ("webhook", "callback", "auth-session", "upload", "download")):
        result.add("webapp")
    if "python" in languages:
        result.add("python")
    return sorted(result)


def choose_strategy(loc: int, detected_archetypes: list[str]) -> tuple[str, str, str]:
    if loc <= SMALL_REPO_LOC:
        return (
            "small-app-invariant-audit",
            "full-read",
            f"Small codebase (~{loc} LOC); complete static review is feasible and safer than lane partitioning.",
        )
    return (
        "invariant-audit",
        "risk-ranked",
        f"Larger codebase (~{loc} LOC); risk-ranked invariant audit is more practical than full-read review.",
    )


def choose_overlays(languages: list[str], frameworks: list[str], detected_archetypes: list[str], surfaces: list[str], config: list[str]) -> list[str]:
    overlays: list[str] = []
    if "python" in languages:
        overlays.append("python")
    if "checkout" in detected_archetypes and has_strong_checkout_signal(surfaces, "payment-flow" in detected_archetypes):
        overlays.append("checkout")
    if "payment-flow" in detected_archetypes:
        overlays.append("payment-flow")
    if "webapp" in detected_archetypes:
        overlays.append("webapp")
    if any(surface in surfaces for surface in ("webhook", "callback")):
        overlays.append("integration-heavy")
    if len(config) >= 4 or any(name.startswith(".github/") for name in config):
        overlays.append("platform-heavy")
    return sorted(dict.fromkeys(overlays or ["auto"]))


def check(id_: str, status: str, reason: str, evidence: list[str] | None = None, dynamic: bool = True) -> dict[str, Any]:
    return {
        "id": id_,
        "status": status,
        "reason": reason,
        "evidence": evidence or [],
        "agent_discretion": dynamic,
    }


def selected_checks(root: Path, evidence_text: dict[str, list[str]], languages: list[str], surfaces: list[str], payment_detected: bool) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = [
        check("secrets.hardcoded", "required", "Universal security check.", dynamic=False),
        check("config.debug-posture", "required", "Universal security check for unsafe debug or local-development posture.", dynamic=False),
    ]
    if "python" in languages:
        checks.append(check("python.unsafe-apis", "recommended", "Python application detected.", find_first_evidence(root, evidence_text, [r"\b(eval|exec|pickle|yaml\.load|subprocess|os\.system)\b"])))
        checks.append(check("python.dependency-config", "recommended", "Python dependency and runtime configuration should be reviewed."))

    commerce_surfaces = sorted(set(surfaces) & COMMERCE_SURFACES)
    if commerce_surfaces:
        checks.extend([
            check("commerce.client-supplied-value-trust", "recommended", "Commerce/order-like names were detected; verify trusted server-side state before money, entitlement, or fulfillment decisions.", find_first_evidence(root, evidence_text, [r"\bcheckout\b", r"\bcart\b", r"\border\b"])),
            check("commerce.object-ownership", "recommended", "Cart/order-like operations should be checked for cross-user or cross-session access."),
            check("commerce.quantity-discount-abuse", "opportunistic", "Quantity, coupon, discount, and amount edge cases are relevant when commerce-like flows are present."),
        ])
    if payment_detected:
        checks.extend([
            check("payment.provider-secret-handling", "required", "Payment provider usage detected.", find_first_evidence(root, evidence_text, PAYMENT_PATTERNS)),
            check("payment.amount-currency-binding", "recommended", "Payment-related code should bind amount, currency, and business object identity using trusted server-side state."),
        ])
    if "webhook" in surfaces:
        checks.extend([
            check("integration.webhook-authenticity", "required", "Webhook/signature-like handler detected.", find_first_evidence(root, evidence_text, [r"\bwebhook\b", r"\bsignature\b", r"\bconstruct_event\b"])),
            check("integration.webhook-idempotency", "recommended", "Webhook handlers should tolerate duplicate or reordered events."),
        ])
    if "auth-session" in surfaces:
        checks.append(check("web.session-and-csrf", "recommended", "Auth/session/CSRF indicators detected.", find_first_evidence(root, evidence_text, [r"\bsession\b", r"\bcsrf\b", r"\blogin\b"])))
    if "admin" in surfaces:
        checks.append(check("authz.admin-surface", "recommended", "Admin/support-like surface detected; verify authentication and authorization boundaries."))
    if "database" in surfaces:
        checks.append(check("data.sql-injection", "recommended", "Database/query indicators detected; review query construction and object scoping."))
    if "upload" in surfaces or "download" in surfaces:
        checks.append(check("data.file-surface", "recommended", "File upload/download/export-like surface detected; review path traversal, authorization, and data exposure."))
    return dedupe_checks(checks)


def deprioritized_checks(surfaces: list[str], loc: int) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    if loc <= SMALL_REPO_LOC:
        checks.append(check("large-repo.agent-team", "not-applicable", "Small codebase; full-read single-session is preferred.", dynamic=False))
    if "upload" not in surfaces and "download" not in surfaces:
        checks.append(check("data.file-path-traversal", "not-applicable", "No upload, download, file-serving, or file-write surface was detected.", dynamic=False))
    if "admin" not in surfaces:
        checks.append(check("role-matrix.deep-admin-review", "deferred", "No obvious admin/support/moderation surface detected during pre-scan."))
    return checks


def dedupe_checks(checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for item in checks:
        by_id.setdefault(item["id"], item)
    return [by_id[key] for key in sorted(by_id)]


def build_plan(root: Path, requested_strategy: str = "auto") -> dict[str, Any]:
    files = list_files(root)
    text, evidence_text = collect_text(root, files)
    loc = approximate_loc(root, files)
    languages = detect_languages(files)
    frameworks = detect_named_patterns(text, FRAMEWORK_PATTERNS)
    surfaces = detect_named_patterns(text, SURFACE_PATTERNS)
    payment_detected = any(re.search(pattern, text, re.IGNORECASE) for pattern in PAYMENT_PATTERNS)
    config = detect_config(root, files)
    detected_archetypes = archetypes(surfaces, frameworks, languages, payment_detected)
    resolved_strategy, coverage_mode, reason = choose_strategy(loc, detected_archetypes)
    overlays = choose_overlays(languages, frameworks, detected_archetypes, surfaces, config)

    uncertainty: list[str] = []
    if not frameworks and surfaces:
        uncertainty.append("Security-relevant surface names were detected, but no common web framework was identified.")
    if set(surfaces) & COMMERCE_SURFACES and not payment_detected:
        uncertainty.append("Commerce/order-like names are treated as relevance cues, not proof of a checkout or payment application.")
    if payment_detected and "webhook" not in surfaces:
        uncertainty.append("Payment provider usage was detected, but no webhook surface was found during pre-scan.")

    return {
        "schema_version": 1,
        "profile": "security",
        "requested_strategy": requested_strategy,
        "resolved_strategy": resolved_strategy if requested_strategy == "auto" else requested_strategy,
        "resolved_overlays": overlays,
        "coverage_mode": coverage_mode,
        "resolution_reason": reason,
        "runtime_validation": False,
        "output_style": "compact" if coverage_mode == "full-read" else "structured",
        "repo_observations": {
            "languages": languages,
            "approximate_loc": loc,
            "detected_frameworks": frameworks,
            "detected_surfaces": surfaces,
            "inferred_archetypes": detected_archetypes,
        },
        "selected_checks": selected_checks(root, evidence_text, languages, surfaces, payment_detected),
        "deprioritized_checks": deprioritized_checks(surfaces, loc),
        "universal_checks_enabled": True,
        "agent_discretion_enabled": True,
        "uncertainty": uncertainty,
        "coverage_gaps": [],
        "advisor": {
            "target_root": root.as_posix(),
            "git_detected": (root / ".git").exists(),
            "prior_auditlanes_runs_detected": has_prior_runs(root),
            "config_files": config,
        },
    }


def print_text(plan: dict[str, Any]) -> None:
    observations = plan["repo_observations"]
    print("AuditLanes scan advisor")
    print()
    print("Detected:")
    print(f"- languages: {', '.join(observations['languages']) or 'unknown'}")
    print(f"- approximate LOC: {observations['approximate_loc']}")
    if observations["detected_frameworks"]:
        print(f"- frameworks: {', '.join(observations['detected_frameworks'])}")
    if observations["detected_surfaces"]:
        print(f"- surfaces: {', '.join(observations['detected_surfaces'])}")
    if observations["inferred_archetypes"]:
        print(f"- archetypes: {', '.join(observations['inferred_archetypes'])}")
    print()
    print("Recommended scan:")
    print("- profile: security")
    print(f"- strategy: {plan['resolved_strategy']}")
    print(f"- overlays: {', '.join(plan['resolved_overlays'])}")
    print(f"- coverage: {plan['coverage_mode']}")
    print("- runtime validation: disabled")
    print(f"- output: {plan['output_style']}")
    print()
    print("Why:")
    print(f"- {plan['resolution_reason']}")
    if plan["selected_checks"]:
        print(f"- Selected {len(plan['selected_checks'])} checks; universal checks are enabled.")
    print("- This is a starting relevance plan; agents may add checks and report serious issues outside it.")
    print()
    print("Choices:")
    print("1. Run recommended scan")
    print("2. Quick obvious-risk sweep")
    print("3. Deep invariant audit")
    print("4. Diff review")
    print("5. Customize parameters")
    print("6. Cancel")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Static-only AuditLanes scan advisor.")
    parser.add_argument("target", nargs="?", default=".", type=Path)
    parser.add_argument("--requested-strategy", default="auto")
    parser.add_argument("--format", choices=["json", "text"], default="text")
    parser.add_argument("--json", action="store_true", help="Shortcut for --format json.")
    args = parser.parse_args(argv)

    root = args.target.resolve()
    if not root.exists() or not root.is_dir():
        print(f"target root does not exist or is not a directory: {root}", file=sys.stderr)
        return 2

    plan = build_plan(root, requested_strategy=args.requested_strategy)
    if args.json or args.format == "json":
        print(json.dumps(plan, indent=2, sort_keys=True))
    else:
        print_text(plan)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
