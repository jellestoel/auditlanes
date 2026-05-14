import json
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PLUGIN_ROOT / "scripts" / "validate_run.py"
VALID_RUN = PLUGIN_ROOT / "resources" / "fixtures" / "valid" / "run-good"
PRODUCTION_INTEGRITY_RUN = PLUGIN_ROOT / "resources" / "fixtures" / "valid" / "run-production-integrity"
INVALID_RUN = PLUGIN_ROOT / "resources" / "fixtures" / "invalid" / "run-missing-evidence"


def load_validator_module():
    spec = importlib.util.spec_from_file_location("auditlanes_validate_run", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ValidateRunCliTests(unittest.TestCase):
    def run_validator(self, run_dir: Path, *args: str):
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(run_dir), *args],
            text=True,
            capture_output=True,
            check=False,
        )

    def copied_run(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        run_copy = Path(tmp.name) / "run-good"
        shutil.copytree(VALID_RUN, run_copy)
        return run_copy

    def copied_production_run(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        run_copy = Path(tmp.name) / "run-production-integrity"
        shutil.copytree(PRODUCTION_INTEGRITY_RUN, run_copy)
        return run_copy

    def test_valid_fixture_passes(self):
        result = self.run_validator(VALID_RUN)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("validation passed", result.stdout)

    def test_production_optional_batch_02_accepts_ran_families(self):
        run_copy = self.copied_production_run()
        batch_01 = run_copy / "reports" / "batch-01"
        batch_02 = run_copy / "reports" / "batch-02"
        shutil.copytree(batch_01, batch_02)
        manifest = batch_02 / "manifest.yaml"
        manifest.write_text(
            manifest.read_text(encoding="utf-8")
            .replace("batch-01", "batch-02")
            .replace("readiness-sweep", "invariant-gap-fill"),
            encoding="utf-8",
        )
        for sidecar_path in batch_02.glob("*/report.json"):
            sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
            sidecar["batch_id"] = "batch-02"
            sidecar["mode"] = "invariant-gap-fill"
            sidecar["sidecar_id"] = f"{sidecar['sidecar_id']}-batch-02"
            sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = self.run_validator(run_copy, "--profile", "production-integrity", "--batch-id", "batch-02")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_production_batch_03_accepts_synthesis_specialist_modes(self):
        run_copy = self.copied_production_run()
        batch_03 = run_copy / "reports" / "batch-03"
        batch_03.mkdir()
        base = json.loads((run_copy / "reports" / "batch-01" / "assurance-evidence" / "report.json").read_text(encoding="utf-8"))

        for family, mode in (
            ("launch-gate-synthesis", "launch-gate-synthesis"),
            ("failure-scenario-synthesis", "failure-scenario-synthesis"),
        ):
            family_dir = batch_03 / family
            family_dir.mkdir()
            sidecar = dict(base)
            sidecar.update({
                "sidecar_id": f"sidecar-{family}-001",
                "batch_id": "batch-03",
                "family": family,
                "mode": mode,
                "overlays": ["auto"],
                "reviewed_artifacts": [],
                "reviewed_files_routes_helpers": [],
                "coverage_units_touched": [],
                "next_batch_recommendations": [],
            })
            (family_dir / "report.json").write_text(json.dumps(sidecar, indent=2), encoding="utf-8")
            (family_dir / "report.md").write_text(f"# {family}\n", encoding="utf-8")

        (batch_03 / "manifest.yaml").write_text(
            "\n".join([
                "schema_version: 1",
                "run_id: run-production-integrity",
                "batch_id: batch-03",
                'generated_at: "2026-05-14T00:00:00Z"',
                "producer: orchestrator",
                "manifest_status: completed",
                "expected_families:",
                "  - launch-gate-synthesis",
                "  - failure-scenario-synthesis",
                "families:",
                "  - family: launch-gate-synthesis",
                "    status: ran",
                "    mode: launch-gate-synthesis",
                '    markdown: "${RUN_DIR}/reports/batch-03/launch-gate-synthesis/report.md"',
                '    json: "${RUN_DIR}/reports/batch-03/launch-gate-synthesis/report.json"',
                "  - family: failure-scenario-synthesis",
                "    status: ran",
                "    mode: failure-scenario-synthesis",
                '    markdown: "${RUN_DIR}/reports/batch-03/failure-scenario-synthesis/report.md"',
                '    json: "${RUN_DIR}/reports/batch-03/failure-scenario-synthesis/report.json"',
                "",
            ]),
            encoding="utf-8",
        )

        result = self.run_validator(run_copy, "--profile", "production-integrity", "--batch-id", "batch-03")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_batch_01_requires_all_security_lanes(self):
        run_copy = self.copied_run()
        manifest = run_copy / "reports" / "batch-01" / "manifest.yaml"
        text = manifest.read_text(encoding="utf-8")
        text = text.replace("  - platform-posture\n", "", 1)
        manifest.write_text(text, encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("batch-01 security canonical sweep must include exactly the six security lanes", result.stderr)

    def test_invalid_fixture_fails(self):
        result = self.run_validator(INVALID_RUN)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("evidence_refs", result.stderr)

    def test_profile_lane_validation_rejects_wrong_profile(self):
        result = self.run_validator(VALID_RUN, "--profile", "architecture", "--allow-experimental")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected selected profile 'architecture'", result.stderr)
        self.assertIn("not defined by profile 'architecture'", result.stderr)

    def test_manifest_path_traversal_is_rejected(self):
        run_copy = self.copied_run()
        manifest = run_copy / "reports" / "batch-01" / "manifest.yaml"
        text = manifest.read_text(encoding="utf-8")
        manifest.write_text(text.replace("${RUN_DIR}/reports/batch-01/session-auth/report.json", "${RUN_DIR}/../outside/report.json"), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("path escapes RUN_DIR", result.stderr)

    def test_manifest_absolute_path_is_rejected(self):
        run_copy = self.copied_run()
        manifest = run_copy / "reports" / "batch-01" / "manifest.yaml"
        text = manifest.read_text(encoding="utf-8")
        manifest.write_text(text.replace("${RUN_DIR}/reports/batch-01/session-auth/report.json", "/tmp/report.json"), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("manifest paths must be run-relative", result.stderr)

    def test_manifest_unhashable_family_values_report_errors_without_traceback(self):
        run_copy = self.copied_run()
        manifest = run_copy / "reports" / "batch-01" / "manifest.yaml"
        manifest.write_text(json.dumps({
            "schema_version": 1,
            "run_id": "run-good",
            "batch_id": "batch-01",
            "generated_at": "2026-05-11T00:00:00Z",
            "producer": "orchestrator",
            "manifest_status": "completed",
            "expected_families": ["session-auth", {"bad": "family"}],
            "families": [{
                "family": ["session-auth"],
                "status": "ran",
                "mode": "canonical-sweep",
                "markdown": "${RUN_DIR}/reports/batch-01/session-auth/report.md",
                "json": "${RUN_DIR}/reports/batch-01/session-auth/report.json",
            }],
        }), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected_families", result.stderr)
        self.assertIn("families", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_simple_yaml_parser_handles_agent_authored_relevance_plan_shapes(self):
        validator = load_validator_module()
        parsed = validator.parse_simple_yaml(
            "\n".join([
                "schema_version: 1",
                "profile: security",
                "requested_strategy: auto",
                "resolved_strategy: invariant-audit",
                "resolved_overlays: [python, webapp, \"payment-flow\"]",
                "coverage_mode: full-read",
                "resolution_reason: Small codebase: use invariant audit.",
                "uncertainty:",
                "  - Small codebase: changed-file inputs were not available.",
                "  - runtime-safe: approval was not granted.",
                "selected_checks:",
                "  - id: commerce.client-supplied-value-trust",
                "    reason: Checkout flow accepts client supplied value.",
                "advisor:",
                "  tool: scan_advisor.py",
                "  version: {major: 1, minor: 0}",
                "",
            ])
        )

        self.assertEqual(parsed["resolved_overlays"], ["python", "webapp", "payment-flow"])
        self.assertEqual(parsed["uncertainty"], [
            "Small codebase: changed-file inputs were not available.",
            "runtime-safe: approval was not granted.",
        ])
        self.assertEqual(parsed["selected_checks"][0]["id"], "commerce.client-supplied-value-trust")
        self.assertEqual(parsed["advisor"]["version"], {"major": 1, "minor": 0})

    def test_missing_manifest_message_hints_at_manifest_yaml(self):
        run_copy = self.copied_run()
        manifest = run_copy / "reports" / "batch-01" / "manifest.yaml"
        manifest.unlink()

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no batch manifests found", result.stderr)
        self.assertIn("reports/<batch-id>/manifest.yaml", result.stderr)
        self.assertIn("families[].json", result.stderr)

    def test_manifest_item_family_must_match_sidecar(self):
        run_copy = self.copied_run()
        manifest = run_copy / "reports" / "batch-01" / "manifest.yaml"
        text = manifest.read_text(encoding="utf-8")
        manifest.write_text(text.replace("  - session-auth", "  - object-auth").replace("  - family: session-auth", "  - family: object-auth"), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("referenced sidecar family 'session-auth' does not match manifest item family 'object-auth'", result.stderr)

    def test_markdown_report_path_must_use_report_layout(self):
        run_copy = self.copied_run()
        alternate = run_copy / "reports" / "batch-01" / "session-auth" / "alternate.md"
        alternate.write_text("# Alternate\n", encoding="utf-8")
        manifest = run_copy / "reports" / "batch-01" / "manifest.yaml"
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace(
                "${RUN_DIR}/reports/batch-01/session-auth/report.md",
                "${RUN_DIR}/reports/batch-01/session-auth/alternate.md",
                1,
            ),
            encoding="utf-8",
        )

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("markdown report must live at reports/<batch-id>/<family>/report.md", result.stderr)

    def test_owner_family_must_match_dedupe_owner_family(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["confirmed_findings"][0]["owner_family"] = "object-auth"
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("dedupe_key.owner_family", result.stderr)
        self.assertIn("must mirror confirmed_finding.owner_family exactly", result.stderr)

    def test_candidate_optional_fields_must_match_dedupe_key(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["candidate_findings"] = [{
            "candidate_id": "C-local-mirror-gap",
            "candidate_dedupe_key": {
                "proposed_owner_family": "session-auth",
                "summary": "Candidate with hidden key fields.",
                "files": ["src/api/session.py"],
                "suspected_missing_guard": "require_session",
                "impact_boundary": "session mutation",
            },
            "proposed_owner_family": "session-auth",
            "severity": "low",
            "confidence": "speculative",
            "summary": "Candidate with hidden key fields.",
            "blocker_to_confirmation": "needs static proof",
            "files": ["src/api/session.py"],
            "evidence_refs": [{
                "path": "src/api/session.py",
                "line_start": 1,
                "line_end": 1,
                "symbol": None,
                "evidence_type": "route-definition",
                "snippet_hash": None,
                "rationale": "Synthetic fixture evidence.",
            }],
        }]
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("candidate_dedupe_key.suspected_missing_guard", result.stderr)
        self.assertIn("must mirror candidate_finding.suspected_missing_guard exactly", result.stderr)

    def test_parked_family_requires_carried_forward_from(self):
        run_copy = self.copied_run()
        manifest = run_copy / "reports" / "batch-01" / "manifest.yaml"
        text = manifest.read_text(encoding="utf-8")
        manifest.write_text(text.replace("status: ran", "status: parked"), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("parked family must declare carried_forward_from", result.stderr)

    def test_batch_01_rejects_parked_lane_even_with_carry_forward(self):
        run_copy = self.copied_run()
        manifest = run_copy / "reports" / "batch-01" / "manifest.yaml"
        text = manifest.read_text(encoding="utf-8")
        text = text.replace(
            "  - family: session-auth\n    status: ran\n    mode: canonical-sweep",
            "  - family: session-auth\n    status: parked\n    mode: parked\n    carried_forward_from: batch-00",
            1,
        )
        text = "\n".join(line for line in text.splitlines() if "batch-01/session-auth/report." not in line) + "\n"
        manifest.write_text(text, encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("batch-01 security lanes must all run", result.stderr)

    def test_ran_family_rejects_parked_mode(self):
        run_copy = self.copied_run()
        manifest = run_copy / "reports" / "batch-01" / "manifest.yaml"
        manifest.write_text(manifest.read_text(encoding="utf-8").replace("mode: canonical-sweep", "mode: parked", 1), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ran family must not use mode=parked", result.stderr)

    def test_sidecar_rejects_parked_mode(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["mode"] = "parked"
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("parked families must not emit fresh report sidecars", result.stderr)

    def test_completed_with_failures_requires_failed_or_missing_family(self):
        run_copy = self.copied_run()
        manifest = run_copy / "reports" / "batch-01" / "manifest.yaml"
        text = manifest.read_text(encoding="utf-8")
        manifest.write_text(text.replace("manifest_status: completed", "manifest_status: completed-with-failures"), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("completed-with-failures manifest must include", result.stderr)

    def test_completed_manifest_rejects_failed_family(self):
        run_copy = self.copied_run()
        manifest = run_copy / "reports" / "batch-01" / "manifest.yaml"
        text = manifest.read_text(encoding="utf-8")
        manifest.write_text(text.replace("status: ran", "status: failed\n    failure_reason: synthetic failure"), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("completed manifest must not contain failed or missing families", result.stderr)

    def test_candidate_evidence_refs_must_be_non_empty(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["candidate_findings"] = [{
            "candidate_id": "C-local-empty-evidence",
            "candidate_dedupe_key": {
                "proposed_owner_family": "session-auth",
                "summary": "Candidate without evidence.",
                "files": ["app.py"],
                "suspected_missing_guard": "guard",
                "impact_boundary": "session",
            },
            "proposed_owner_family": "session-auth",
            "severity": "low",
            "confidence": "speculative",
            "summary": "Candidate without evidence.",
            "blocker_to_confirmation": "needs static proof",
            "files": ["app.py"],
            "evidence_refs": [],
        }]
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("candidate_findings", result.stderr)
        self.assertIn("evidence_refs", result.stderr)

    def test_confirmed_finding_files_must_be_non_empty(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["confirmed_findings"][0]["files"] = []
        sidecar["confirmed_findings"][0]["dedupe_key"]["entrypoint"] = sidecar["confirmed_findings"][0]["entrypoint"]
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("confirmed_findings", result.stderr)
        self.assertIn("files", result.stderr)

    def test_structure_evidence_may_use_null_line_start(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        evidence = sidecar["confirmed_findings"][0]["evidence_refs"][0]
        evidence["line_start"] = None
        evidence["line_end"] = None
        evidence["evidence_type"] = "repository-structure"
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_profile_feedback_evidence_refs_must_be_non_empty(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["profile_feedback"] = [{
            "profile_gap_id": "PG-empty-evidence",
            "family": "session-auth",
            "observed_issue": "Profile gap without evidence.",
            "suggested_change": "Require cited evidence.",
            "evidence_refs": [],
            "urgency": "low",
        }]
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("profile_feedback", result.stderr)
        self.assertIn("evidence_refs", result.stderr)

    def test_runtime_confirmed_requires_runtime_safe_mode(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["confirmed_findings"][0]["status"] = "runtime-confirmed"
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("runtime_updates and runtime-confirmed findings require mode=runtime-safe", result.stderr)

    def test_runtime_safe_requires_metadata_approval_when_metadata_exists(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["mode"] = "runtime-safe"
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")
        manifest = run_copy / "reports" / "batch-01" / "manifest.yaml"
        manifest.write_text(manifest.read_text(encoding="utf-8").replace("mode: canonical-sweep", "mode: runtime-safe", 1), encoding="utf-8")
        metadata = run_copy / "state" / "run-metadata.yaml"
        metadata.parent.mkdir(exist_ok=True)
        metadata.write_text("runtime_approval:\n  enabled: false\n", encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("runtime-safe mode requires runtime_approval.enabled=true", result.stderr)

    def test_runtime_safe_requires_metadata_approval_when_metadata_is_missing(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["mode"] = "runtime-safe"
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")
        manifest = run_copy / "reports" / "batch-01" / "manifest.yaml"
        manifest.write_text(manifest.read_text(encoding="utf-8").replace("mode: canonical-sweep", "mode: runtime-safe", 1), encoding="utf-8")
        metadata = run_copy / "state" / "run-metadata.yaml"
        if metadata.exists():
            metadata.unlink()

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("runtime-safe mode requires runtime_approval.enabled=true", result.stderr)

    def test_normal_lane_cannot_run_exploit_synthesis(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["mode"] = "exploit-synthesis"
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")
        manifest = run_copy / "reports" / "batch-01" / "manifest.yaml"
        manifest.write_text(manifest.read_text(encoding="utf-8").replace("mode: canonical-sweep", "mode: exploit-synthesis", 1), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("normal lanes must not run specialist modes", result.stderr)

    def test_specialist_cannot_run_normal_family_mode(self):
        run_copy = self.copied_run()
        batch = run_copy / "reports" / "batch-04"
        family_dir = batch / "exploit-synthesis"
        family_dir.mkdir(parents=True)
        (family_dir / "report.md").write_text("# Exploit Synthesis\n", encoding="utf-8")
        sidecar = json.loads((run_copy / "reports" / "batch-01" / "object-auth" / "report.json").read_text(encoding="utf-8"))
        sidecar.update({
            "sidecar_id": "sidecar-exploit-synthesis-bad-mode",
            "batch_id": "batch-04",
            "family": "exploit-synthesis",
            "mode": "canonical-sweep",
        })
        (family_dir / "report.json").write_text(json.dumps(sidecar, indent=2), encoding="utf-8")
        (batch / "manifest.yaml").write_text(
            "\n".join([
                "schema_version: 1",
                "run_id: run-good",
                "batch_id: batch-04",
                'generated_at: "2026-05-11T00:00:00Z"',
                "producer: orchestrator",
                "manifest_status: completed",
                "expected_families:",
                "  - exploit-synthesis",
                "families:",
                "  - family: exploit-synthesis",
                "    status: ran",
                "    mode: canonical-sweep",
                '    markdown: "${RUN_DIR}/reports/batch-04/exploit-synthesis/report.md"',
                '    json: "${RUN_DIR}/reports/batch-04/exploit-synthesis/report.json"',
                "",
            ]),
            encoding="utf-8",
        )

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must run mode 'exploit-synthesis'", result.stderr)

    def test_small_app_strategy_allows_exploit_synthesis_batch(self):
        run_copy = self.copied_run()
        plan_path = run_copy / "state" / "relevance-plan.yaml"
        plan_path.write_text(
            plan_path.read_text(encoding="utf-8")
            .replace("resolved_strategy: invariant-audit", "resolved_strategy: small-app-invariant-audit", 1),
            encoding="utf-8",
        )
        batch = run_copy / "reports" / "batch-04"
        family_dir = batch / "exploit-synthesis"
        family_dir.mkdir(parents=True)
        (family_dir / "report.md").write_text("# Exploit Synthesis\n", encoding="utf-8")
        sidecar = json.loads((run_copy / "reports" / "batch-01" / "object-auth" / "report.json").read_text(encoding="utf-8"))
        sidecar.update({
            "sidecar_id": "sidecar-exploit-synthesis-small-app",
            "batch_id": "batch-04",
            "family": "exploit-synthesis",
            "mode": "exploit-synthesis",
            "strategy": "small-app-invariant-audit",
        })
        sidecar["confirmed_findings"] = []
        sidecar["candidate_findings"] = []
        (family_dir / "report.json").write_text(json.dumps(sidecar, indent=2), encoding="utf-8")
        (batch / "manifest.yaml").write_text(
            "\n".join([
                "schema_version: 1",
                "run_id: run-good",
                "batch_id: batch-04",
                'generated_at: "2026-05-11T00:00:00Z"',
                "producer: orchestrator",
                "manifest_status: completed",
                "expected_families:",
                "  - exploit-synthesis",
                "families:",
                "  - family: exploit-synthesis",
                "    status: ran",
                "    mode: exploit-synthesis",
                '    markdown: "${RUN_DIR}/reports/batch-04/exploit-synthesis/report.md"',
                '    json: "${RUN_DIR}/reports/batch-04/exploit-synthesis/report.json"',
                "",
            ]),
            encoding="utf-8",
        )

        result = self.run_validator(run_copy, "--batch-id", "batch-04")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_reswept_status_requires_post_fix_resweep_mode(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["confirmed_findings"][0]["status"] = "reswept-open"
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reswept-open and reswept-closed findings require mode=post-fix-resweep", result.stderr)

    def test_evidence_paths_must_not_point_into_output(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["confirmed_findings"][0]["evidence_refs"][0]["path"] = "auditlanes/out/runs/old/report.json"
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must not point into auditlanes/out", result.stderr)

    def test_reviewed_paths_must_not_be_absolute(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["reviewed_artifacts"][0] = "/tmp/source.py"
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("path must be repository-relative, not absolute", result.stderr)

    def test_affected_families_must_be_profile_lanes(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["profile_feedback"] = [{
            "profile_gap_id": "PG-bad-family",
            "family": "session-auth",
            "affected_families": ["exploit-synthesis", "unknown-family"],
            "observed_issue": "Bad affected family.",
            "suggested_change": "Reject non-lanes.",
            "evidence_refs": [{
                "path": "routes.py",
                "line_start": 1,
                "line_end": 1,
                "symbol": None,
                "evidence_type": "route-definition",
                "snippet_hash": None,
                "rationale": "Synthetic fixture evidence."
            }],
            "urgency": "low",
        }]
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("affected_families", result.stderr)
        self.assertIn("not a lane in profile", result.stderr)

    def test_unknown_strategy_is_rejected(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["strategy"] = "unknown-strategy"
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("strategy 'unknown-strategy' is not defined by profile 'security'", result.stderr)

    def test_auto_strategy_is_rejected_in_sidecars(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["strategy"] = "auto"
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("strategy 'auto' is only valid before calibration", result.stderr)

    def test_planned_strategy_is_rejected_by_default(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["strategy"] = "asvs-baseline"
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("strategy 'asvs-baseline' is not runnable", result.stderr)

    def test_unknown_overlay_is_rejected(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["overlays"] = ["auto", "unknown-overlay"]
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("overlay 'unknown-overlay' is not defined by profile 'security'", result.stderr)

    def test_overlays_must_not_be_empty(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["overlays"] = []
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("overlays must contain at least one overlay id", result.stderr)

    def test_strategy_restricts_sidecar_mode(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["strategy"] = "runtime-validation"
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mode 'canonical-sweep' is not allowed by strategy 'runtime-validation'", result.stderr)

    def test_incidental_lead_owner_must_be_normal_lane(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["incidental_leads"] = [{
            "lead_id": "LEAD-session-auth-001",
            "noticed_by_family": "session-auth",
            "proposed_owner_family": "exploit-synthesis",
            "summary": "Synthetic out-of-lane issue.",
            "confidence": "probable",
            "severity_hint": "high",
            "blocker_to_confirmation": "Needs owner-lane confirmation.",
            "files": ["routes.py"],
            "evidence_refs": [{
                "path": "routes.py",
                "line_start": 1,
                "line_end": 1,
                "symbol": None,
                "evidence_type": "route-definition",
                "snippet_hash": None,
                "rationale": "Synthetic fixture evidence."
            }],
        }]
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("incidental_leads", result.stderr)
        self.assertIn("not a lane in profile", result.stderr)

    def test_run_local_checks_are_allowed_with_evidence(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["run_local_checks"] = [{
            "check_id": "local.custom-state-machine",
            "reason": "Repo-specific state transition needs a custom security check.",
            "trigger_evidence_refs": [{
                "path": "routes.py",
                "line_start": 1,
                "line_end": 1,
                "symbol": None,
                "evidence_type": "route-definition",
                "snippet_hash": None,
                "rationale": "Synthetic fixture evidence."
            }],
            "extends_checks": ["authz.admin-surface"],
            "recommended_owner_family": "object-auth",
            "scope_impact": "Add state-machine ownership checks to this run.",
            "regression_impact": "Add a custom static rule if confirmed.",
        }]
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_run_local_check_id_must_be_local(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["run_local_checks"] = [{
            "check_id": "checkout.custom-state-machine",
            "reason": "Bad global-looking local check id.",
            "trigger_evidence_refs": [{
                "path": "routes.py",
                "line_start": 1,
                "line_end": 1,
                "symbol": None,
                "evidence_type": "route-definition",
                "snippet_hash": None,
                "rationale": "Synthetic fixture evidence."
            }],
            "scope_impact": "Should be rejected.",
        }]
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("run_local_checks", result.stderr)
        self.assertIn("check_id", result.stderr)

    def test_batch_01_cannot_mark_late_canonical(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["confirmed_findings"][0]["introduced_after_batch_01"] = True
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("batch-01 findings must not be marked introduced_after_batch_01", result.stderr)

    def test_evidence_line_end_must_not_precede_start(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["confirmed_findings"][0]["evidence_refs"][0]["line_end"] = 1
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be greater than or equal to line_start", result.stderr)

    def test_evidence_line_end_requires_line_start(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["confirmed_findings"][0]["evidence_refs"][0]["line_start"] = None
        sidecar["confirmed_findings"][0]["evidence_refs"][0]["line_end"] = 50
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires line_start when present", result.stderr)

    def test_strategy_required_state_artifacts_are_enforced(self):
        run_copy = self.copied_run()
        (run_copy / "state" / "proof-ledger.jsonl").unlink()

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required state artifact is missing", result.stderr)
        self.assertIn("proof-ledger.jsonl", result.stderr)

    def test_required_state_artifacts_are_schema_validated(self):
        run_copy = self.copied_run()
        (run_copy / "state" / "security-invariants.jsonl").write_text(json.dumps({
            "schema_version": 1,
            "invariant_id": "INV-bad",
        }) + "\n", encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("security-invariants.jsonl", result.stderr)
        self.assertIn("missing required property", result.stderr)

    def test_present_optional_state_artifacts_are_schema_validated(self):
        run_copy = self.copied_run()
        (run_copy / "state" / "authorization-matrix.jsonl").write_text(json.dumps({
            "schema_version": 1,
            "matrix_id": "AUTHZ-bad",
            "principal": "tenant-user",
            "object": "invoice",
            "action": "export",
            "expected": "deny cross-tenant export",
            "observed_guard": "unknown",
            "status": "needs-review",
            "surface_id": "SURF-export",
            "evidence_refs": [],
        }) + "\n", encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("authorization-matrix.jsonl", result.stderr)
        self.assertIn("evidence_refs", result.stderr)

    def test_state_artifact_owner_families_must_be_profile_lanes(self):
        run_copy = self.copied_run()
        (run_copy / "state" / "attack-surface-inventory.jsonl").write_text(json.dumps({
            "schema_version": 1,
            "surface_id": "SURF-specialist-owner",
            "category": "web-route",
            "owner_family": "exploit-synthesis",
            "description": "Synthetic surface with specialist owner.",
            "paths": ["src/api/session.py"],
            "evidence_refs": [{
                "path": "src/api/session.py",
                "line_start": 1,
                "line_end": 1,
                "symbol": None,
                "evidence_type": "route-definition",
                "snippet_hash": None,
                "rationale": "Synthetic fixture evidence.",
            }],
        }) + "\n", encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("attack-surface-inventory.jsonl", result.stderr)
        self.assertIn("not a lane in profile", result.stderr)

    def test_relevance_plan_auto_overlays_must_match_sidecars(self):
        run_copy = self.copied_run()
        plan_path = run_copy / "state" / "relevance-plan.yaml"
        plan_path.write_text(
            plan_path.read_text(encoding="utf-8").replace("  - auto\n", "  - python\n  - webapp\n", 1),
            encoding="utf-8",
        )

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must match auto-resolved overlays", result.stderr)

    def test_attack_surface_inventory_uses_inventory_schema(self):
        run_copy = self.copied_run()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        profiles_dir = Path(tmp.name) / "profiles"
        shutil.copytree(PLUGIN_ROOT / "resources" / "profiles", profiles_dir)
        strategy_path = profiles_dir / "security" / "strategies" / "invariant-audit.yaml"
        strategy_path.write_text(
            strategy_path.read_text(encoding="utf-8").replace(
                "  - state/attack-surface-graph.jsonl\n",
                "  - state/attack-surface-graph.jsonl\n  - state/attack-surface-inventory.jsonl\n",
                1,
            ),
            encoding="utf-8",
        )
        (run_copy / "state" / "attack-surface-inventory.jsonl").write_text(json.dumps({
            "schema_version": 1,
            "surface_id": "surface-web-checkout",
            "category": "web-route",
            "owner_family": "object-auth",
            "description": "Checkout route accepts user input.",
            "paths": ["src/api/checkout.py"],
            "evidence_refs": [{
                "path": "src/api/checkout.py",
                "line_start": 1,
                "line_end": 1,
                "symbol": None,
                "evidence_type": "route-definition",
                "snippet_hash": None,
                "rationale": "Synthetic fixture evidence.",
            }],
        }) + "\n", encoding="utf-8")

        result = self.run_validator(run_copy, "--profiles-dir", str(profiles_dir))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_diff_review_batch_01_can_use_relevant_lane_subset(self):
        run_copy = self.copied_run()
        manifest = run_copy / "reports" / "batch-01" / "manifest.yaml"
        manifest.write_text(
            "\n".join([
                "schema_version: 1",
                "run_id: run-good",
                "batch_id: batch-01",
                'generated_at: "2026-05-11T00:00:00Z"',
                "producer: orchestrator",
                "manifest_status: completed",
                "expected_families:",
                "  - session-auth",
                "families:",
                "  - family: session-auth",
                "    status: ran",
                "    mode: canonical-sweep",
                '    markdown: "${RUN_DIR}/reports/batch-01/session-auth/report.md"',
                '    json: "${RUN_DIR}/reports/batch-01/session-auth/report.json"',
                "",
            ]),
            encoding="utf-8",
        )
        for family_dir in (run_copy / "reports" / "batch-01").iterdir():
            if family_dir.is_dir() and family_dir.name != "session-auth":
                shutil.rmtree(family_dir)
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["strategy"] = "diff-review"
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")
        plan_path = run_copy / "state" / "relevance-plan.yaml"
        plan_path.write_text(
            plan_path.read_text(encoding="utf-8")
            .replace("requested_strategy: auto", "requested_strategy: diff-review", 1)
            .replace("resolved_strategy: invariant-audit", "resolved_strategy: diff-review", 1),
            encoding="utf-8",
        )

        result = self.run_validator(run_copy)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_profile_version_must_match_package_version_when_present(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["profile_version"] = "0.0.0"
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must match package version", result.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_symlinked_manifest_is_rejected_before_read(self):
        run_copy = self.copied_run()
        manifest = run_copy / "reports" / "batch-01" / "manifest.yaml"
        outside = run_copy.parent / "outside-manifest.yaml"
        outside.write_text("not: [valid", encoding="utf-8")
        manifest.unlink()
        os.symlink(outside, manifest)

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlinked manifest is not allowed", result.stderr)
        self.assertNotIn("could not parse manifest", result.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_symlinked_sidecar_is_rejected_before_read(self):
        run_copy = self.copied_run()
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        outside = run_copy.parent / "outside-report.json"
        outside.write_text("not-json", encoding="utf-8")
        sidecar_path.unlink()
        os.symlink(outside, sidecar_path)

        result = self.run_validator(run_copy)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlinked sidecar is not allowed", result.stderr)
        self.assertNotIn("could not parse sidecar", result.stderr)

    def test_batch_id_limits_validation_scope(self):
        run_copy = self.copied_run()
        batch_02 = run_copy / "reports" / "batch-02" / "session-auth"
        batch_02.mkdir(parents=True)
        shutil.copy2(run_copy / "reports" / "batch-01" / "manifest.yaml", run_copy / "reports" / "batch-02" / "manifest.yaml")
        shutil.copy2(run_copy / "reports" / "batch-01" / "session-auth" / "report.json", batch_02 / "report.json")
        shutil.copy2(run_copy / "reports" / "batch-01" / "session-auth" / "report.md", batch_02 / "report.md")

        manifest = run_copy / "reports" / "batch-02" / "manifest.yaml"
        manifest.write_text(manifest.read_text(encoding="utf-8").replace("batch-01", "batch-02"), encoding="utf-8")
        sidecar_path = batch_02 / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["batch_id"] = "batch-02"
        del sidecar["confirmed_findings"][0]["evidence_refs"]
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        selected = self.run_validator(run_copy, "--batch-id", "batch-01")
        self.assertEqual(selected.returncode, 0, selected.stderr)

        full = self.run_validator(run_copy)
        self.assertNotEqual(full.returncode, 0)
        self.assertIn("evidence_refs", full.stderr)


if __name__ == "__main__":
    unittest.main()
