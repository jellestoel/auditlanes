import importlib.util
import os
import shutil
import tempfile
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PLUGIN_ROOT / "scripts" / "validate_run.py"
VALID_RUN = PLUGIN_ROOT / "resources" / "fixtures" / "valid" / "run-good"


def load_validator_module():
    spec = importlib.util.spec_from_file_location("auditlanes_validate_run", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ReducerIdempotencyContractTests(unittest.TestCase):
    def test_input_hash_collection_is_deterministic(self):
        validator = load_validator_module()
        first = validator.collect_input_hashes(VALID_RUN)
        second = validator.collect_input_hashes(VALID_RUN)
        self.assertEqual(first, second)
        self.assertGreaterEqual(len(first), 2)

    def test_validation_does_not_mutate_run_inputs(self):
        validator = load_validator_module()
        with tempfile.TemporaryDirectory() as tmp:
            run_copy = Path(tmp) / "run-good"
            shutil.copytree(VALID_RUN, run_copy)
            before = validator.collect_input_hashes(run_copy)
            self.assertEqual(validator.validate_run(run_copy, PLUGIN_ROOT / "resources" / "schemas"), [])
            after = validator.collect_input_hashes(run_copy)
            self.assertEqual(before, after)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_input_hash_collection_skips_symlinked_artifacts(self):
        validator = load_validator_module()
        with tempfile.TemporaryDirectory() as tmp:
            run_copy = Path(tmp) / "run-good"
            shutil.copytree(VALID_RUN, run_copy)
            sidecar_path = run_copy / "reports" / "batch-01" / "session-auth" / "report.json"
            outside = Path(tmp) / "outside-report.json"
            outside.write_text("not-json", encoding="utf-8")
            sidecar_path.unlink()
            os.symlink(outside, sidecar_path)

            hashes = validator.collect_input_hashes(run_copy)
            hashed_paths = {item["path"] for item in hashes}
            self.assertNotIn("reports/batch-01/session-auth/report.json", hashed_paths)


if __name__ == "__main__":
    unittest.main()
