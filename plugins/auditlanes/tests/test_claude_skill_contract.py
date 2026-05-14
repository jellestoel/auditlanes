import unittest
import json
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SKILL = PLUGIN_ROOT / "skills" / "scan" / "SKILL.md"
CODEX_SKILL = PLUGIN_ROOT / "codex-skills" / "auditlanes" / "SKILL.md"


class ClaudeSkillContractTests(unittest.TestCase):
    def test_skill_uses_plugin_root_for_resources(self):
        text = SKILL.read_text(encoding="utf-8")
        self.assertIn("${CLAUDE_PLUGIN_ROOT}/resources/repo-scaffold/auditlanes", text)
        self.assertIn("${CLAUDE_PLUGIN_ROOT}/scripts/validate_run.py", text)
        self.assertNotIn("skills/scan/resources", text)

    def test_skill_discourages_prompt_spam_command_patterns(self):
        text = SKILL.read_text(encoding="utf-8")
        self.assertIn("do not prefix Bash commands", text)
        self.assertIn("2>/dev/null", text)
        self.assertIn("Avoid shell pipelines", text)
        self.assertIn("rg -n -m 50", text)

    def test_skill_allows_required_markdown_report_artifacts(self):
        text = SKILL.read_text(encoding="utf-8")
        self.assertIn("report.md", text)
        self.assertIn("required AuditLanes artifacts", text)
        self.assertIn("not optional summary files", text)

    def test_agent_team_mode_requires_native_team(self):
        text = SKILL.read_text(encoding="utf-8")
        self.assertIn("activate a native", text)
        self.assertIn("Claude Code agent team", text)
        self.assertIn("agent-team-first execution", text)
        self.assertIn("fallback reason", text)
        self.assertIn("subagent", text)
        self.assertIn("shared task list", text)
        self.assertIn("direct teammate messaging", text)
        self.assertIn("Agent-team activation gate", text)
        self.assertIn("before any run work", text)
        self.assertIn("native team roster", text)
        self.assertIn("A lead-session", text)
        self.assertIn("six-worker cap applies to primary AuditLanes lane owners", text)
        self.assertIn("Helper agents are not independent", text)
        self.assertIn("teammate-spawned teams", text)
        self.assertIn("more than six total", text)
        self.assertIn("orchestrator may improvise", text)

    def test_skill_presents_profile_choice_before_strategy_choice(self):
        text = SKILL.read_text(encoding="utf-8")
        self.assertIn("profile choice before strategy choices", text)
        self.assertIn("`security` - stable runnable profile", text)
        self.assertIn("`production-integrity` - experimental runnable profile", text)
        self.assertIn("After the profile is selected, present strategy choices", text)

    def test_codex_manifest_uses_codex_specific_skill_entrypoint(self):
        manifest = json.loads((PLUGIN_ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["skills"], "./codex-skills/")

        text = CODEX_SKILL.read_text(encoding="utf-8")
        self.assertIn("AUDITLANES_PLUGIN_ROOT", text)
        self.assertIn("`agent-team` is a Claude Code native-team mode", text)
        self.assertIn("not a Codex mode", text)
        self.assertIn("continue with `subagent` mode", text)
        self.assertNotIn("CLAUDE_PLUGIN_ROOT", text)
        self.assertNotIn("/auditlanes:scan", text)


if __name__ == "__main__":
    unittest.main()
