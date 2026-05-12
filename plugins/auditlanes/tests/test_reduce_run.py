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

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_reducer_rejects_symlinked_state_directory(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        run_copy = Path(tmp.name) / "run-good"
        shutil.copytree(VALID_RUN, run_copy)
        state_dir = run_copy / "state"
        outside_state = Path(tmp.name) / "outside-state"
        outside_state.mkdir()
        shutil.rmtree(state_dir)
        os.symlink(outside_state, state_dir, target_is_directory=True)

        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(run_copy)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing to write through symlinked state directory", result.stderr)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_reducer_does_not_write_through_predictable_temp_symlink(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        run_copy = Path(tmp.name) / "run-good"
        shutil.copytree(VALID_RUN, run_copy)
        state_dir = run_copy / "state"
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
