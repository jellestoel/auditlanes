import importlib.util
import json
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PLUGIN_ROOT / "scripts" / "validate_run.py"
SCAFFOLD_ROOT = PLUGIN_ROOT / "resources" / "repo-scaffold" / "auditlanes"
SCHEMAS_ROOT = PLUGIN_ROOT / "resources" / "schemas"


def load_validator_module():
    spec = importlib.util.spec_from_file_location("auditlanes_validate_run", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ScaffoldYamlTests(unittest.TestCase):
    def test_scaffold_control_yaml_parses(self):
        validator = load_validator_module()
        files = sorted(SCAFFOLD_ROOT.glob("*.yaml"))
        self.assertGreaterEqual(len(files), 1)
        for path in files:
            with self.subTest(path=path.name):
                data = validator.load_json_or_yaml(path)
                self.assertIsNotNone(data)

    def test_package_manifest_plugin_files_exist(self):
        validator = load_validator_module()
        manifest = validator.load_json_or_yaml(PLUGIN_ROOT / "package-manifest.yaml")
        for relative in manifest["plugin_files"]:
            with self.subTest(path=relative):
                self.assertTrue((PLUGIN_ROOT / relative).exists(), relative)

    def test_state_artifact_schemas_are_packaged(self):
        validator = load_validator_module()
        manifest = validator.load_json_or_yaml(PLUGIN_ROOT / "package-manifest.yaml")
        packaged_files = set(manifest["plugin_files"])
        executable_schemas = set(manifest["validator_status"]["executable_schemas"])
        for schema in sorted(set(validator.STATE_ARTIFACT_SCHEMAS.values())):
            relative = f"resources/schemas/{schema}"
            with self.subTest(schema=schema):
                self.assertIn(relative, packaged_files)
                self.assertIn(relative, executable_schemas)

    def test_guidance_yaml_core_enums_match_json_schema(self):
        validator = load_validator_module()
        guidance = validator.load_json_or_yaml(SCAFFOLD_ROOT / "report-sidecar-schema.yaml")
        schema = json.loads((SCHEMAS_ROOT / "report-sidecar.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(guidance["enums"]["mode"], schema["$defs"]["mode"]["enum"])
        self.assertEqual(guidance["enums"]["confirmed_finding_status"], schema["$defs"]["confirmedStatus"]["enum"])
        self.assertEqual(guidance["enums"]["runtime_status"], schema["$defs"]["runtimeStatus"]["enum"])
        self.assertEqual(guidance["enums"]["evidence_type"], schema["$defs"]["evidenceType"]["enum"])

        manifest_guidance = validator.load_json_or_yaml(SCAFFOLD_ROOT / "batch-manifest-schema.yaml")
        manifest_schema = json.loads((SCHEMAS_ROOT / "batch-manifest.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest_guidance["family_modes"], manifest_schema["$defs"]["mode"]["enum"])
        self.assertEqual(manifest_guidance["family_status_values"], manifest_schema["$defs"]["status"]["enum"])


if __name__ == "__main__":
    unittest.main()
