import importlib.util
import json
import shutil
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
        self.assertIn("api", plan["resolved_overlays"])
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
        self.assertIn("api", plan["resolved_overlays"])
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
        self.assertIn("api", plan["resolved_overlays"])

    @unittest.skipUnless(shutil.which("git"), "git required")
    def test_git_and_docker_ignored_trees_do_not_drive_detection(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name) / "ignored-noise-app"
        root.mkdir()
        subprocess.run(["git", "init"], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        (root / ".gitignore").write_text("git-ignored/\n", encoding="utf-8")
        (root / ".dockerignore").write_text("docker-ignored/\n", encoding="utf-8")
        (root / "app.py").write_text(
            "\n".join([
                "from fastapi import FastAPI",
                "app = FastAPI()",
                "@app.get('/health')",
                "def health():",
                "    return {'ok': True}",
            ]),
            encoding="utf-8",
        )
        (root / "git-ignored").mkdir()
        (root / "git-ignored" / "legacy.py").write_text(
            "\n".join(["import django", "urlpatterns = []"] + [f"def ignored_{i}(): return {i}" for i in range(3000)]),
            encoding="utf-8",
        )
        (root / "docker-ignored").mkdir()
        (root / "docker-ignored" / "page.tsx").write_text(
            "\n".join(["import React from 'react'", "export default function Page() { return <div /> }"] + ["// next"] * 3000),
            encoding="utf-8",
        )

        plan = self.run_advisor_json(root)
        observations = plan["repo_observations"]
        self.assertLess(observations["approximate_loc"], 20)
        self.assertIn("fastapi", observations["detected_frameworks"])
        self.assertNotIn("django", observations["detected_frameworks"])
        self.assertNotIn("nextjs", observations["detected_frameworks"])
        self.assertNotIn("javascript-typescript", plan["resolved_overlays"])

    def test_developer_tool_overlay_for_repo_scanner_shape(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name) / "repo-scanner"
        root.mkdir()
        (root / ".git").mkdir()
        (root / ".codex-plugin").mkdir()
        (root / ".codex-plugin" / "plugin.json").write_text('{"name": "repo-scanner"}\n', encoding="utf-8")
        scripts = root / "scripts"
        scripts.mkdir()
        (scripts / "validate_run.py").write_text(
            "\n".join([
                "from pathlib import Path",
                "import yaml",
                "",
                "def validate(target_root, run_dir):",
                "    # untrusted repo inputs must not become control-plane instructions",
                "    resolved = Path(target_root).resolve()",
                "    return yaml.safe_load((Path(run_dir) / 'manifest.yaml').read_text())",
            ]),
            encoding="utf-8",
        )

        plan = self.run_advisor_json(root)
        self.assertIn("developer-tool", plan["resolved_overlays"])
        self.assertIn("developer-tool", plan["repo_observations"]["inferred_archetypes"])
        check_ids = {check["id"] for check in plan["selected_checks"]}
        self.assertIn("tool.untrusted-repo-boundaries", check_ids)

    def test_javascript_browser_graphql_realtime_and_jobs_overlays(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name) / "next-platform"
        root.mkdir()
        (root / ".git").mkdir()
        (root / "package.json").write_text(
            json.dumps({
                "dependencies": {
                    "next": "latest",
                    "react": "latest",
                    "@apollo/server": "latest",
                    "socket.io": "latest",
                    "bullmq": "latest",
                }
            }),
            encoding="utf-8",
        )
        app_dir = root / "app"
        app_dir.mkdir()
        (app_dir / "page.tsx").write_text(
            "\n".join([
                "import React from 'react'",
                "export default function Page() {",
                "  return <div dangerouslySetInnerHTML={{__html: window.localStorage.getItem('html') || ''}} />",
                "}",
            ]),
            encoding="utf-8",
        )
        (root / "server.ts").write_text(
            "\n".join([
                "import { ApolloServer } from '@apollo/server'",
                "import { Server } from 'socket.io'",
                "import { Queue } from 'bullmq'",
                "const typeDefs = `type Query { invoice(id: ID!): Invoice }`",
                "const resolvers = { Query: { invoice: (_: unknown, args: any) => args.id } }",
                "new Server().to('tenant-room').emit('invoice', {})",
                "new Queue('fulfillment').add('ship', { orderId: 'ord_1' })",
            ]),
            encoding="utf-8",
        )

        plan = self.run_advisor_json(root)
        for overlay in (
            "javascript-typescript",
            "browser-client",
            "webapp",
            "api",
            "graphql",
            "realtime-messaging",
            "background-jobs",
        ):
            self.assertIn(overlay, plan["resolved_overlays"])

        check_ids = {check["id"] for check in plan["selected_checks"]}
        self.assertIn("graphql.resolver-authorization", check_ids)
        self.assertIn("realtime.channel-authorization", check_ids)
        self.assertIn("jobs.payload-trust-transfer", check_ids)

    def test_dormant_and_project_shape_overlays_are_selected(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name) / "platform-monorepo"
        root.mkdir()
        (root / ".git").mkdir()
        (root / "pnpm-workspace.yaml").write_text("packages:\n  - apps/*\n  - packages/*\n  - services/*\n", encoding="utf-8")
        (root / "docker-compose.yml").write_text("services:\n  api:\n    build: ./services/api\n  worker:\n    build: ./services/worker\n", encoding="utf-8")
        for directory in ("apps/admin", "packages/auth", "services/api", "services/worker"):
            (root / directory).mkdir(parents=True)
        (root / "services/api/app.py").write_text(
            "\n".join([
                "from fastapi import FastAPI",
                "import openai",
                "app = FastAPI()",
                "@app.get('/admin/export')",
                "def admin_export(tenant_id: str, organization_id: str):",
                "    prompt = 'summarize customer data'",
                "    device_token = 'fcm-token'",
                "    redirect_uri = 'https://example.test/callback'",
                "    oauth_state_nonce = 'state nonce'",
                "    internal_api = 'service-to-service mtls api gateway shared secret'",
                "    return {'tenant': tenant_id, 'prompt': prompt, 'device_token': device_token, 'redirect_uri': redirect_uri, 'internal_api': internal_api}",
            ]),
            encoding="utf-8",
        )

        plan = self.run_advisor_json(root)
        for overlay in (
            "multi-tenant-saas",
            "admin-backoffice",
            "identity-federation",
            "ai-agent-app",
            "mobile-backend",
            "monorepo",
            "microservices",
            "platform-heavy",
        ):
            self.assertIn(overlay, plan["resolved_overlays"])

    def test_explicit_requested_strategy_is_preserved(self):
        root = self.small_checkout_repo()
        plan = self.run_advisor_json(root, "--requested-strategy", "diff-review")
        self.assertEqual(plan["requested_strategy"], "diff-review")
        self.assertEqual(plan["resolved_strategy"], "diff-review")
        self.assertEqual(plan["coverage_mode"], "focused-lanes")
        self.assertIn("diff inputs unavailable", plan["coverage_gaps"])
        self.assertTrue(any("changed files were not available" in item for item in plan["uncertainty"]))

    def test_repo_local_auditlanes_control_files_do_not_drive_detection(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name) / "plain-app"
        root.mkdir()
        (root / "app.py").write_text("def health():\n    return 'ok'\n", encoding="utf-8")
        control_dir = root / "auditlanes"
        control_dir.mkdir()
        (control_dir / "orchestrator.yaml").write_text(
            "\n".join([
                "notes:",
                "  - from flask import Flask, request, session",
                "  - stripe.checkout.Session.create(line_items=[], mode='payment')",
                "  - /checkout",
                "  - /webhook",
            ]),
            encoding="utf-8",
        )
        profiles_dir = control_dir / "profiles"
        profiles_dir.mkdir()
        (profiles_dir / "project.yaml").write_text(
            "\n".join([
                "notes:",
                "  - from flask import Flask, request, session",
                "  - stripe.checkout.Session.create(line_items=[], mode='payment')",
                "  - /checkout",
                "  - /webhook",
            ]),
            encoding="utf-8",
        )

        plan = self.run_advisor_json(root)
        self.assertNotIn("checkout", plan["repo_observations"]["detected_surfaces"])
        self.assertNotIn("payment-flow", plan["resolved_overlays"])
        check_ids = {check["id"] for check in plan["selected_checks"]}
        self.assertFalse(any(check_id.startswith("payment.") for check_id in check_ids))


if __name__ == "__main__":
    unittest.main()
