import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PLUGIN_ROOT / "scripts" / "scan_advisor.py"
VALIDATOR_SCRIPT = PLUGIN_ROOT / "scripts" / "validate_run.py"
SCHEMA = PLUGIN_ROOT / "resources" / "schemas" / "relevance-plan.schema.json"


def load_validator_module():
    spec = importlib.util.spec_from_file_location("auditlanes_validate_run", VALIDATOR_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ScanAdvisorTests(unittest.TestCase):
    def run_advisor_json(self, root: Path, *args: str):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(root), "--json", *args],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def small_checkout_repo(self) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name) / "checkout-app"
        root.mkdir()
        (root / ".git").mkdir()
        (root / "requirements.txt").write_text("flask\nstripe\n", encoding="utf-8")
        (root / "app.py").write_text(
            "\n".join([
                "from flask import Flask, request, session",
                "import stripe",
                "",
                "app = Flask(__name__)",
                "app.secret_key = 'dev'",
                "",
                "@app.post('/cart')",
                "def cart():",
                "    session['cart'] = request.form.get('product_id')",
                "    return 'ok'",
                "",
                "@app.post('/checkout')",
                "def checkout():",
                "    amount = request.form.get('amount')",
                "    return stripe.checkout.Session.create(line_items=[], mode='payment')",
                "",
                "@app.post('/webhook')",
                "def webhook():",
                "    signature = request.headers.get('Stripe-Signature')",
                "    return 'ok'",
                "",
            ]),
            encoding="utf-8",
        )
        return root

    def test_small_python_commerce_payment_signals_stay_generic(self):
        root = self.small_checkout_repo()
        plan = self.run_advisor_json(root)

        self.assertEqual(plan["profile"], "security")
        self.assertEqual(plan["requested_strategy"], "auto")
        self.assertEqual(plan["resolved_strategy"], "small-app-invariant-audit")
        self.assertEqual(plan["coverage_mode"], "full-read")
        self.assertFalse(plan["runtime_validation"])
        self.assertTrue(plan["agent_discretion_enabled"])
        self.assertIn("python", plan["resolved_overlays"])
        self.assertIn("checkout", plan["resolved_overlays"])
        self.assertIn("payment-flow", plan["resolved_overlays"])
        self.assertIn("webapp", plan["resolved_overlays"])
        self.assertIn("commerce-flow", plan["repo_observations"]["inferred_archetypes"])

        check_ids = {check["id"] for check in plan["selected_checks"]}
        self.assertIn("commerce.client-supplied-value-trust", check_ids)
        self.assertIn("payment.amount-currency-binding", check_ids)
        self.assertIn("integration.webhook-authenticity", check_ids)
        self.assertIn("python.unsafe-apis", check_ids)
        self.assertIn("secrets.hardcoded", check_ids)
        self.assertFalse(any(check_id.startswith("checkout.") for check_id in check_ids))
        by_id = {check["id"]: check for check in plan["selected_checks"]}
        self.assertFalse(by_id["secrets.hardcoded"]["agent_discretion"])
        self.assertTrue(by_id["commerce.client-supplied-value-trust"]["agent_discretion"])

    def test_generic_python_app_does_not_get_commerce_or_payment_checks(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name) / "api-app"
        root.mkdir()
        (root / "requirements.txt").write_text("fastapi\n", encoding="utf-8")
        (root / "app.py").write_text(
            "\n".join([
                "from fastapi import FastAPI",
                "",
                "app = FastAPI()",
                "",
                "@app.get('/health')",
                "def health():",
                "    return {'ok': True}",
            ]),
            encoding="utf-8",
        )

        plan = self.run_advisor_json(root)
        self.assertIn("python", plan["resolved_overlays"])
        self.assertIn("webapp", plan["resolved_overlays"])
        self.assertNotIn("checkout", plan["resolved_overlays"])
        self.assertNotIn("payment-flow", plan["resolved_overlays"])

        check_ids = {check["id"] for check in plan["selected_checks"]}
        self.assertFalse(any(check_id.startswith("commerce.") for check_id in check_ids))
        self.assertFalse(any(check_id.startswith("payment.") for check_id in check_ids))
        self.assertIn("python.unsafe-apis", check_ids)

    def test_relevance_plan_matches_schema(self):
        root = self.small_checkout_repo()
        plan = self.run_advisor_json(root)
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        validator = load_validator_module()
        self.assertEqual(validator.validate_schema(plan, schema), [])

    def test_large_repo_resolves_risk_ranked_invariant_audit(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name) / "large-app"
        root.mkdir()
        (root / ".git").mkdir()
        (root / "app.py").write_text(
            "\n".join(["from fastapi import FastAPI", "app = FastAPI()"] + [f"def handler_{i}(): return {i}" for i in range(2200)]),
            encoding="utf-8",
        )

        plan = self.run_advisor_json(root)
        self.assertEqual(plan["resolved_strategy"], "invariant-audit")
        self.assertEqual(plan["coverage_mode"], "risk-ranked")
        self.assertIn("webapp", plan["resolved_overlays"])

    def test_explicit_requested_strategy_is_preserved(self):
        root = self.small_checkout_repo()
        plan = self.run_advisor_json(root, "--requested-strategy", "diff-review")
        self.assertEqual(plan["requested_strategy"], "diff-review")
        self.assertEqual(plan["resolved_strategy"], "diff-review")
        self.assertEqual(plan["coverage_mode"], "full-read")


if __name__ == "__main__":
    unittest.main()
