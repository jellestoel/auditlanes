import importlib.util
import json
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PLUGIN_ROOT / "scripts" / "validate_run.py"
SCHEMA = PLUGIN_ROOT / "resources" / "schemas" / "report-sidecar.schema.json"
WORKFLOW_EVIDENCE_SCHEMA = PLUGIN_ROOT / "resources" / "schemas" / "workflow-evidence-report-sidecar.schema.json"
SIDECAR = PLUGIN_ROOT / "resources" / "fixtures" / "valid" / "run-good" / "reports" / "batch-01" / "session-auth" / "report.json"
WORKFLOW_EVIDENCE_SIDECAR = PLUGIN_ROOT / "resources" / "fixtures" / "valid" / "run-workflow-evidence" / "reports" / "batch-01" / "static-topology" / "report.json"


def load_validator_module():
    spec = importlib.util.spec_from_file_location("auditlanes_validate_run", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class SidecarCompatibilityTests(unittest.TestCase):
    def test_valid_sidecar_matches_schema(self):
        validator = load_validator_module()
        sidecar = json.loads(SIDECAR.read_text(encoding="utf-8"))
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(validator.validate_schema(sidecar, schema), [])

    def test_missing_schema_version_is_rejected(self):
        validator = load_validator_module()
        sidecar = json.loads(SIDECAR.read_text(encoding="utf-8"))
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        sidecar.pop("schema_version")
        errors = validator.validate_schema(sidecar, schema)
        self.assertTrue(any("schema_version" in error for error in errors), errors)

    def test_workflow_evidence_intentionally_excluded_requires_objects(self):
        validator = load_validator_module()
        sidecar = json.loads(WORKFLOW_EVIDENCE_SIDECAR.read_text(encoding="utf-8"))
        schema = json.loads(WORKFLOW_EVIDENCE_SCHEMA.read_text(encoding="utf-8"))
        sidecar["intentionally_excluded"] = ["auditlanes/out"]
        errors = validator.validate_schema(sidecar, schema)
        self.assertTrue(any("intentionally_excluded" in error for error in errors), errors)

        sidecar["intentionally_excluded"] = [{
            "path": "auditlanes/out",
            "reason": "run output is control-plane data, not application evidence",
            "scope_source": None,
        }]
        self.assertEqual(validator.validate_schema(sidecar, schema), [])

    def test_specialist_mode_validation_uses_profile_catalog(self):
        validator = load_validator_module()
        profile = {
            "lanes": {"module-boundaries"},
            "specialists": {"architecture-synthesis"},
            "specialist_modes": {"architecture-synthesis": "impact-synthesis"},
        }
        wrong_specialist = validator.family_mode_issue(
            Path("manifest.yaml"),
            "$.families[0].mode",
            "architecture-synthesis",
            "canonical-sweep",
            profile,
        )
        self.assertIsNotNone(wrong_specialist)
        self.assertIn("impact-synthesis", wrong_specialist.message)

        wrong_lane = validator.family_mode_issue(
            Path("manifest.yaml"),
            "$.families[0].mode",
            "module-boundaries",
            "impact-synthesis",
            profile,
        )
        self.assertIsNotNone(wrong_lane)
        self.assertIn("normal lanes must not run specialist modes", wrong_lane.message)

    def test_security_profile_loads_auto_strategy_and_relevance_overlays(self):
        validator = load_validator_module()
        profile = validator.load_profile("security", PLUGIN_ROOT / "resources" / "profiles")
        self.assertEqual(profile["default_strategy"], "auto")
        self.assertIn("auto", profile["strategies"])
        self.assertIn("small-app-invariant-audit", profile["strategies"])
        self.assertIn("python", profile["overlays"])
        self.assertIn("checkout", profile["overlays"])
        self.assertIn("payment-flow", profile["overlays"])
        self.assertTrue(profile["cross_lane_triggers"])

    def test_production_integrity_profile_loads_as_experimental_runnable(self):
        validator = load_validator_module()
        profile = validator.load_profile("production-integrity", PLUGIN_ROOT / "resources" / "profiles")
        self.assertTrue(profile["implemented"])
        self.assertEqual(profile["report_sidecar_schema"], "production-integrity-report-sidecar.schema.json")
        self.assertEqual(profile["default_strategy"], "auto")
        self.assertEqual(
            profile["lane_order"],
            [
                "state-model-integrity",
                "workflow-atomicity",
                "derived-output-reconciliation",
                "lifecycle-recovery",
                "runtime-cutover-controls",
                "assurance-evidence",
            ],
        )
        self.assertIn("production-gate", profile["strategies"])
        self.assertIn("control-clonehunt", profile["strategies"]["production-gate"]["allowed_modes"])
        self.assertIn("auto", profile["overlays"])
        self.assertIn("money-documents-workflows", profile["overlays"])
        self.assertTrue(profile["cross_lane_triggers"])

    def test_performance_profile_loads_as_experimental_runnable(self):
        validator = load_validator_module()
        profile = validator.load_profile("performance", PLUGIN_ROOT / "resources" / "profiles")
        self.assertTrue(profile["implemented"])
        self.assertEqual(profile["report_sidecar_schema"], "performance-report-sidecar.schema.json")
        self.assertEqual(profile["default_strategy"], "static-capacity-sweep")
        self.assertEqual(
            profile["lane_order"],
            [
                "workload-budget-model",
                "synchronous-hot-paths",
                "data-access-scaling",
                "async-throughput-backlog",
                "resource-saturation-degradation",
                "client-edge-performance",
                "performance-assurance",
            ],
        )
        self.assertIn("capacity-gate-synthesis", profile["specialists"])
        self.assertIn("bottleneck-chain-synthesis", profile["specialists"])
        self.assertIn("static-capacity-sweep", profile["strategies"])
        self.assertIn("db-heavy", profile["overlays"])
        self.assertTrue(profile["cross_lane_triggers"])

    def test_workflow_evidence_profile_loads_as_experimental_runnable(self):
        validator = load_validator_module()
        profile = validator.load_profile("workflow-evidence", PLUGIN_ROOT / "resources" / "profiles")
        self.assertTrue(profile["implemented"])
        self.assertEqual(profile["report_sidecar_schema"], "workflow-evidence-report-sidecar.schema.json")
        self.assertEqual(profile["default_strategy"], "static-atlas")
        self.assertEqual(
            profile["lane_order"],
            [
                "static-topology",
                "tenant-segmentation",
                "business-completion",
                "runtime-side-effects",
                "fixture-readiness",
                "backlog-synthesis",
            ],
        )
        self.assertIn("evidence-atlas-synthesis", profile["specialists"])
        self.assertIn("release-test-selection", profile["specialists"])
        self.assertIn("static-atlas", profile["strategies"])
        self.assertIn("read-only-enrichment", profile["strategies"])
        self.assertIn("multi-tenant-workflow-atlas", profile["overlays"])
        self.assertIn("django-legacy-gae", profile["overlays"])
        self.assertTrue(profile["cross_lane_triggers"])


if __name__ == "__main__":
    unittest.main()
