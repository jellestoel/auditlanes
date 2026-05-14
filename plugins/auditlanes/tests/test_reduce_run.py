import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PLUGIN_ROOT / "scripts" / "reduce_run.py"
VALID_RUN = PLUGIN_ROOT / "resources" / "fixtures" / "valid" / "run-good"
CANDIDATE_DUPES_RUN = PLUGIN_ROOT / "resources" / "fixtures" / "valid" / "run-candidate-dupes"


def read_jsonl(path: Path):
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def file_hash(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


class ReduceRunTests(unittest.TestCase):
    def run_reducer(self, fixture: Path, *args: str):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        run_copy = Path(tmp.name) / fixture.name
        shutil.copytree(fixture, run_copy)
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(run_copy), *args],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return run_copy, json.loads(result.stdout)

    def test_stable_ids_are_assigned(self):
        run_copy, summary = self.run_reducer(VALID_RUN)
        self.assertEqual(summary["records"], 1)
        records = read_jsonl(run_copy / "state" / "finding-inventory.jsonl")
        self.assertEqual(len(records), 1)
        self.assertRegex(records[0]["finding_id"], r"^F-session-auth-[0-9a-f]{12}$")
        self.assertRegex(records[0]["root_cause_id"], r"^RC-session-auth-[0-9a-f]{12}$")

    def test_reducer_is_idempotent_for_same_inputs(self):
        run_copy, _ = self.run_reducer(VALID_RUN)
        state_files = [
            run_copy / "state" / "finding-inventory.jsonl",
            run_copy / "state" / "run-events.jsonl",
            run_copy / "state" / "shared-context-summary.md",
        ]
        before = {path.name: file_hash(path) for path in state_files}
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(run_copy)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        after = {path.name: file_hash(path) for path in state_files}
        self.assertEqual(before, after)

    def test_candidate_dedupe_merges_sources(self):
        run_copy, summary = self.run_reducer(CANDIDATE_DUPES_RUN)
        self.assertEqual(summary["records"], 1)
        records = read_jsonl(run_copy / "state" / "finding-inventory.jsonl")
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["status"], "candidate")
        self.assertEqual(record["severity"], "high")
        self.assertEqual(len(record["provisional_ids"]), 2)
        self.assertEqual(len(record["source_reports"]), 2)

    def test_candidate_report_refs_are_preserved(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        run_copy = Path(tmp.name) / "run-candidate-dupes"
        shutil.copytree(CANDIDATE_DUPES_RUN, run_copy)
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["candidate_findings"][0]["report_refs"] = ["reports/batch-01/session-auth/report.md#candidate-order"]
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(run_copy)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        records = read_jsonl(run_copy / "state" / "finding-inventory.jsonl")
        self.assertIn("reports/batch-01/session-auth/report.md#candidate-order", records[0]["report_refs"])

    def test_same_id_status_transition_prefers_later_valid_state(self):
        run_copy, _ = self.run_reducer(VALID_RUN)
        batch_dir = run_copy / "reports" / "batch-05"
        family_dir = batch_dir / "session-auth"
        family_dir.mkdir(parents=True)
        (family_dir / "report.md").write_text("# Session Auth Post-Fix Report\n", encoding="utf-8")
        sidecar_path = family_dir / "report.json"
        source_sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(source_sidecar_path.read_text(encoding="utf-8"))
        sidecar.update({
            "sidecar_id": "sidecar-session-auth-post-fix-001",
            "generated_at": "2026-05-11T00:10:00Z",
            "batch_id": "batch-05",
            "mode": "post-fix-resweep",
        })
        sidecar["confirmed_findings"][0]["status"] = "reswept-open"
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")
        (batch_dir / "manifest.yaml").write_text(
            "\n".join([
                "schema_version: 1",
                "run_id: run-good",
                "batch_id: batch-05",
                'generated_at: "2026-05-11T00:10:00Z"',
                "producer: orchestrator",
                "manifest_status: completed",
                "expected_families:",
                "  - session-auth",
                "families:",
                "  - family: session-auth",
                "    status: ran",
                "    mode: post-fix-resweep",
                '    markdown: "${RUN_DIR}/reports/batch-05/session-auth/report.md"',
                '    json: "${RUN_DIR}/reports/batch-05/session-auth/report.json"',
                "",
            ]),
            encoding="utf-8",
        )

        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(run_copy), "--batch-id", "batch-05"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        records = read_jsonl(run_copy / "state" / "finding-inventory.jsonl")
        finding = next(record for record in records if str(record.get("finding_id", "")).startswith("F-session-auth-"))
        self.assertEqual(finding["status"], "reswept-open")

        batch_dir = run_copy / "reports" / "batch-06"
        family_dir = batch_dir / "session-auth"
        family_dir.mkdir(parents=True)
        (family_dir / "report.md").write_text("# Session Auth Closed Report\n", encoding="utf-8")
        sidecar["sidecar_id"] = "sidecar-session-auth-post-fix-002"
        sidecar["generated_at"] = "2026-05-11T00:15:00Z"
        sidecar["batch_id"] = "batch-06"
        sidecar["confirmed_findings"][0]["status"] = "reswept-closed"
        (family_dir / "report.json").write_text(json.dumps(sidecar, indent=2), encoding="utf-8")
        (batch_dir / "manifest.yaml").write_text(
            "\n".join([
                "schema_version: 1",
                "run_id: run-good",
                "batch_id: batch-06",
                'generated_at: "2026-05-11T00:15:00Z"',
                "producer: orchestrator",
                "manifest_status: completed",
                "expected_families:",
                "  - session-auth",
                "families:",
                "  - family: session-auth",
                "    status: ran",
                "    mode: post-fix-resweep",
                '    markdown: "${RUN_DIR}/reports/batch-06/session-auth/report.md"',
                '    json: "${RUN_DIR}/reports/batch-06/session-auth/report.json"',
                "",
            ]),
            encoding="utf-8",
        )

        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(run_copy), "--batch-id", "batch-06"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        records = read_jsonl(run_copy / "state" / "finding-inventory.jsonl")
        finding = next(record for record in records if str(record.get("finding_id", "")).startswith("F-session-auth-"))
        self.assertEqual(finding["status"], "reswept-closed")

    def test_profile_feedback_preserves_affected_families(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        run_copy = Path(tmp.name) / "run-good"
        shutil.copytree(VALID_RUN, run_copy)
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["profile_feedback"] = [{
            "profile_gap_id": "PG-cross-lane-001",
            "family": "session-auth",
            "affected_families": ["object-auth", "integration-trust"],
            "observed_issue": "Cross-lane scope issue.",
            "suggested_change": "Review ownership and callback scope together.",
            "evidence_refs": [{
                "path": "routes.py",
                "line_start": 1,
                "line_end": 1,
                "symbol": None,
                "evidence_type": "route-definition",
                "snippet_hash": None,
                "rationale": "Synthetic fixture evidence."
            }],
            "urgency": "medium",
        }]
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(run_copy)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        feedback = read_jsonl(run_copy / "state" / "profile-feedback.jsonl")
        self.assertEqual(feedback[0]["affected_families"], ["object-auth", "integration-trust"])

    def test_reducer_imports_incidental_leads_and_auxiliary_state(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        run_copy = Path(tmp.name) / "run-good"
        shutil.copytree(VALID_RUN, run_copy)
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["incidental_leads"] = [{
            "lead_id": "LEAD-session-auth-001",
            "noticed_by_family": "session-auth",
            "proposed_owner_family": "object-auth",
            "summary": "Export route appears to trust caller supplied org_id.",
            "confidence": "probable",
            "severity_hint": "high",
            "why_noticed": "Seen while reviewing session-bearing routes.",
            "blocker_to_confirmation": "Object policy helper was not fully reviewed by this lane.",
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
        sidecar["security_smells"] = [{
            "smell_id": "SMELL-001",
            "category": "direct-object-reference",
            "path": "routes.py",
            "line_start": 1,
            "description": "Route accepts org_id and invoice_id in the same handler.",
            "recommended_owner": "object-auth",
            "status": "needs-triage",
        }]
        sidecar["proof_updates"] = [{
            "subject_id": "LEAD-session-auth-001",
            "proof_level": "P0-lead",
            "evidence_summary": "Out-of-lane lead preserved with route evidence.",
            "runtime_validation": {
                "approved": False,
                "reason": "No runtime approval was granted.",
            },
            "regression_status": "proposed",
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
        sidecar["regression_recommendations"] = [{
            "finding_id": "PF-session-auth-001",
            "recommended_regression": "integration test",
            "test_name": "test_user_cannot_export_other_tenant_invoice",
            "guard_asserted": "require target org membership",
            "automation_status": "proposed",
            "owner_hint": "backend",
        }]
        sidecar["run_local_checks"] = [{
            "check_id": "local.invoice-export-state",
            "reason": "Invoice export has repo-specific state transitions.",
            "trigger_evidence_refs": [{
                "path": "routes.py",
                "line_start": 1,
                "line_end": 1,
                "symbol": None,
                "evidence_type": "route-definition",
                "snippet_hash": None,
                "rationale": "Synthetic fixture evidence."
            }],
            "extends_checks": ["commerce.object-ownership"],
            "recommended_owner_family": "object-auth",
            "scope_impact": "Review invoice export state and ownership together.",
            "regression_impact": "Add export state transition test if confirmed.",
        }]
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(run_copy)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual(summary["incidental_leads"], 1)
        self.assertEqual(summary["security_smells"], 1)
        self.assertEqual(summary["proof_updates"], 1)
        self.assertEqual(summary["regression_recommendations"], 1)
        self.assertEqual(summary["run_local_checks"], 1)
        self.assertGreaterEqual(summary["family_directives"], 2)

        leads = read_jsonl(run_copy / "state" / "incidental-leads.jsonl")
        self.assertEqual(leads[0]["proposed_owner_family"], "object-auth")
        smells = read_jsonl(run_copy / "state" / "security-smells.jsonl")
        self.assertEqual(smells[0]["recommended_owner"], "object-auth")
        proof = read_jsonl(run_copy / "state" / "proof-ledger.jsonl")
        self.assertEqual(proof[0]["proof_level"], "P0-lead")
        regression = read_jsonl(run_copy / "state" / "regression-plan.jsonl")
        self.assertRegex(regression[0]["regression_id"], r"^REG-[0-9a-f]{12}$")
        self.assertRegex(regression[0]["finding_id"], r"^F-session-auth-[0-9a-f]{12}$")
        local_checks = read_jsonl(run_copy / "state" / "run-local-checks.jsonl")
        self.assertEqual(local_checks[0]["check_id"], "local.invoice-export-state")
        directives_text = (run_copy / "state" / "family-directives.yaml").read_text(encoding="utf-8")
        self.assertIn("object-auth", directives_text)
        self.assertIn("data-surfaces", directives_text)
        self.assertIn("LEAD-session-auth-001", directives_text)
        self.assertIn("local.invoice-export-state", directives_text)
        events = read_jsonl(run_copy / "state" / "run-events.jsonl")
        self.assertTrue(any(event["event_type"] == "out-of-lane-lead-imported" for event in events))
        self.assertTrue(any(event["event_type"] == "run-local-check-imported" for event in events))
        self.assertTrue(any(event["event_type"] == "cross-lane-trigger-matched" for event in events))

    def test_reducer_repairs_stale_extra_fields_in_owned_state(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        run_copy = Path(tmp.name) / "run-good"
        shutil.copytree(VALID_RUN, run_copy)
        state_dir = run_copy / "state"
        state_dir.mkdir(exist_ok=True)
        (state_dir / "security-smells.jsonl").write_text(json.dumps({
            "schema_version": 1,
            "smell_id": "SMELL-stale-001",
            "category": "direct-object-reference",
            "source_family": "session-auth",
            "source_reports": [],
            "first_seen_batch": "batch-01",
            "last_touched_batch": "batch-01",
            "path": "routes.py",
            "line_start": 1,
            "description": "Stale reducer row carried an invalid merge field.",
            "recommended_owner": "object-auth",
            "status": "needs-triage",
            "files": ["routes.py"],
        }) + "\n", encoding="utf-8")
        (state_dir / "regression-plan.jsonl").write_text(json.dumps({
            "schema_version": 1,
            "regression_id": "REG-123456789abc",
            "finding_id": "F-existing-123",
            "source_family": "session-auth",
            "source_reports": [],
            "last_touched_batch": "batch-01",
            "recommended_regression": "integration test",
            "test_name": "test_existing_guard",
            "guard_asserted": "require object owner",
            "automation_status": "proposed",
            "trigger_evidence_refs": [{"path": "routes.py"}],
        }) + "\n", encoding="utf-8")
        (state_dir / "run-local-checks.jsonl").write_text(json.dumps({
            "schema_version": 1,
            "check_id": "local.stale-check",
            "source_family": "session-auth",
            "recommended_owner_family": "object-auth",
            "source_reports": [],
            "first_seen_batch": "batch-01",
            "last_touched_batch": "batch-01",
            "reason": "Run-local state had stale reducer fields.",
            "trigger_evidence_refs": [{"path": "routes.py"}],
            "extends_checks": ["commerce.object-ownership"],
            "scope_impact": "Check object ownership.",
            "regression_impact": None,
            "status": "active",
            "evidence_refs": [{"path": "routes.py"}],
        }) + "\n", encoding="utf-8")

        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(run_copy)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        smell = read_jsonl(state_dir / "security-smells.jsonl")[0]
        regression = read_jsonl(state_dir / "regression-plan.jsonl")[0]
        local_check = read_jsonl(state_dir / "run-local-checks.jsonl")[0]
        self.assertNotIn("files", smell)
        self.assertNotIn("trigger_evidence_refs", regression)
        self.assertNotIn("evidence_refs", local_check)

    def test_proof_updates_map_provisional_ids_and_keep_strongest_level(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        run_copy = Path(tmp.name) / "run-good"
        shutil.copytree(VALID_RUN, run_copy)
        sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        sidecar["proof_updates"] = [
            {
                "subject_id": "PF-session-auth-001",
                "proof_level": "P4-runtime-confirmed",
                "evidence_summary": "Runtime evidence confirmed the missing guard.",
                "evidence_refs": [{
                    "path": "src/api/session.py",
                    "line_start": 42,
                    "line_end": 58,
                    "symbol": "SessionView.post",
                    "evidence_type": "runtime-observation",
                    "snippet_hash": None,
                    "rationale": "Synthetic runtime evidence.",
                }],
            },
            {
                "subject_id": "PF-session-auth-001",
                "proof_level": "P1-candidate",
                "evidence_summary": "Weaker later proof should not replace stronger proof.",
                "evidence_refs": [{
                    "path": "src/api/session.py",
                    "line_start": 42,
                    "line_end": 58,
                    "symbol": "SessionView.post",
                    "evidence_type": "missing-authn-check",
                    "snippet_hash": None,
                    "rationale": "Synthetic static evidence.",
                }],
            },
        ]
        sidecar_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")

        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(run_copy)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        proof = read_jsonl(run_copy / "state" / "proof-ledger.jsonl")
        self.assertEqual(len(proof), 1)
        self.assertRegex(proof[0]["subject_id"], r"^F-session-auth-[0-9a-f]{12}$")
        self.assertEqual(proof[0]["proof_level"], "P4-runtime-confirmed")

    def test_runtime_updates_map_provisional_ids_and_update_existing_findings(self):
        run_copy, _ = self.run_reducer(VALID_RUN)
        batch_dir = run_copy / "reports" / "batch-02"
        family_dir = batch_dir / "session-auth"
        family_dir.mkdir(parents=True)
        (family_dir / "report.md").write_text("# Runtime Validation\n", encoding="utf-8")
        source_sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
        sidecar = json.loads(source_sidecar_path.read_text(encoding="utf-8"))
        sidecar.update({
            "sidecar_id": "sidecar-session-auth-runtime-001",
            "generated_at": "2026-05-11T00:20:00Z",
            "batch_id": "batch-02",
            "mode": "runtime-safe",
        })
        sidecar["confirmed_findings"] = []
        sidecar["runtime_updates"] = [{
            "finding_id": "PF-session-auth-001",
            "runtime_status": "confirmed-at-runtime",
            "request_posture": "approved local reproduction",
            "result": "Missing session guard was reachable at runtime.",
            "evidence_refs": [{
                "path": "src/api/session.py",
                "line_start": 42,
                "line_end": 58,
                "symbol": "login_required",
                "evidence_type": "runtime-observation",
                "snippet_hash": None,
                "rationale": "Synthetic runtime evidence."
            }],
        }]
        (family_dir / "report.json").write_text(json.dumps(sidecar, indent=2), encoding="utf-8")
        (batch_dir / "manifest.yaml").write_text(
            "\n".join([
                "schema_version: 1",
                "run_id: run-good",
                "batch_id: batch-02",
                'generated_at: "2026-05-11T00:20:00Z"',
                "producer: orchestrator",
                "manifest_status: completed",
                "expected_families:",
                "  - session-auth",
                "families:",
                "  - family: session-auth",
                "    status: ran",
                "    mode: runtime-safe",
                '    markdown: "${RUN_DIR}/reports/batch-02/session-auth/report.md"',
                '    json: "${RUN_DIR}/reports/batch-02/session-auth/report.json"',
                "",
            ]),
            encoding="utf-8",
        )
        (run_copy / "state" / "run-metadata.yaml").write_text(
            "runtime_approval:\n  enabled: true\n",
            encoding="utf-8",
        )

        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(run_copy), "--batch-id", "batch-02"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        records = read_jsonl(run_copy / "state" / "finding-inventory.jsonl")
        finding = next(record for record in records if str(record.get("finding_id", "")).startswith("F-session-auth-"))
        self.assertEqual(finding["status"], "runtime-confirmed")
        self.assertEqual(finding["runtime_status"], "confirmed-at-runtime")
        self.assertTrue(any(source["batch_id"] == "batch-02" for source in finding["source_reports"]))

    def test_cross_lane_triggers_create_directives_from_attack_surface_graph(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        run_copy = Path(tmp.name) / "run-good"
        shutil.copytree(VALID_RUN, run_copy)
        state_dir = run_copy / "state"
        state_dir.mkdir(exist_ok=True)
        with (state_dir / "attack-surface-graph.jsonl").open("w", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "schema_version": 1,
                "surface_id": "SURF-invoice-export",
                "entrypoint": "GET /orgs/:org_id/invoices/export",
                "principal_types": ["tenant-user"],
                "assets": ["invoice"],
                "actions": ["export"],
                "guards": ["require_session"],
                "trust_boundaries": ["browser", "tenant-boundary", "csv-download"],
                "risk_score": 86,
                "owner_family": "object-auth",
                "secondary_families": ["data-surfaces"],
                "evidence_refs": [{
                    "path": "routes.py",
                    "line_start": 1,
                    "line_end": 1,
                    "symbol": None,
                    "evidence_type": "route-definition",
                    "snippet_hash": None,
                    "rationale": "Synthetic fixture evidence."
                }],
            }) + "\n")

        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(run_copy)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout)
        self.assertGreaterEqual(summary["family_directives"], 2)
        directives_text = (state_dir / "family-directives.yaml").read_text(encoding="utf-8")
        self.assertIn("object-auth", directives_text)
        self.assertIn("data-surfaces", directives_text)
        self.assertIn("SURF-invoice-export", directives_text)
        events = read_jsonl(state_dir / "run-events.jsonl")
        self.assertTrue(any(event["event_type"] == "cross-lane-trigger-matched" for event in events))

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_reducer_rejects_symlinked_state_directory(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        run_copy = Path(tmp.name) / "run-good"
        shutil.copytree(VALID_RUN, run_copy)
        state_dir = run_copy / "state"
        outside_state = Path(tmp.name) / "outside-state"
        outside_state.mkdir()
        if state_dir.exists():
            shutil.rmtree(state_dir)
        os.symlink(outside_state, state_dir, target_is_directory=True)

        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(run_copy)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symlinked state directory is not allowed", result.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_reducer_does_not_write_through_predictable_temp_symlink(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        run_copy = Path(tmp.name) / "run-good"
        shutil.copytree(VALID_RUN, run_copy)
        state_dir = run_copy / "state"
        state_dir.mkdir(exist_ok=True)
        outside_target = Path(tmp.name) / "outside-temp-target"
        outside_target.write_text("unchanged", encoding="utf-8")
        os.symlink(outside_target, state_dir / ".finding-inventory.jsonl.tmp")

        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(run_copy)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(outside_target.read_text(encoding="utf-8"), "unchanged")
        self.assertTrue((state_dir / ".finding-inventory.jsonl.tmp").is_symlink())

    def test_batch_reduce_preserves_existing_state_and_leads(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        run_copy = Path(tmp.name) / "run-good"
        shutil.copytree(VALID_RUN, run_copy)
        state_dir = run_copy / "state"
        state_dir.mkdir(exist_ok=True)
        existing = {
            "schema_version": 1,
            "finding_id": "F-existing-000000000000",
            "status": "confirmed-static",
            "severity": "low",
            "summary": "Existing prior batch finding.",
            "owner_family": "object-auth",
            "record_created_at": "2026-05-11T00:00:00Z",
            "record_updated_at": "2026-05-11T00:00:00Z",
        }
        lead = {
            "schema_version": 1,
            "lead_id": "L-imported-0001",
            "status": "lead",
            "severity": "info",
            "summary": "Imported lead without reducer finding id.",
            "owner_family": "platform-posture",
        }
        with (state_dir / "finding-inventory.jsonl").open("w", encoding="utf-8") as handle:
            handle.write(json.dumps(existing) + "\n")
            handle.write(json.dumps(lead) + "\n")

        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(run_copy), "--batch-id", "batch-01"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        records = read_jsonl(state_dir / "finding-inventory.jsonl")
        ids = {record.get("finding_id") or record.get("lead_id") for record in records}
        self.assertIn("F-existing-000000000000", ids)
        self.assertIn("L-imported-0001", ids)
        self.assertTrue(any(str(record.get("finding_id", "")).startswith("F-session-auth-") for record in records))


if __name__ == "__main__":
    unittest.main()
