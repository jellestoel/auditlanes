# Release Checklist

This file is for maintainers preparing a Git-backed marketplace release.

## Pre-Publish Checks

```bash
python3 -m unittest discover -s plugins/auditlanes/tests
python3 plugins/auditlanes/scripts/validate_run.py plugins/auditlanes/resources/fixtures/valid/run-good
python3 plugins/auditlanes/scripts/validate_run.py plugins/auditlanes/resources/fixtures/valid/run-candidate-dupes
python3 -m json.tool .agents/plugins/marketplace.json >/dev/null
python3 -m json.tool .claude-plugin/marketplace.json >/dev/null
python3 -m json.tool plugins/auditlanes/.codex-plugin/plugin.json >/dev/null
python3 -m json.tool plugins/auditlanes/.claude-plugin/plugin.json >/dev/null
find plugins/auditlanes/resources/schemas -name '*.json' -exec python3 -m json.tool {} \; >/dev/null
claude plugin validate .
```

Codex currently has no `codex plugin validate` equivalent. The JSON checks above
cover the Codex marketplace and plugin manifests; use the local install smoke
test below for end-to-end Codex verification.

Also smoke test local installs before announcing a release:

```text
Claude Code:
  /plugin marketplace add .
  /plugin install auditlanes@auditlanes
  /reload-plugins
  /auditlanes:scan show profiles

Codex:
  codex plugin marketplace add .
  codex
  /plugins
```

## Versioning

Keep these version fields aligned and bump them for every marketplace release:

```text
.claude-plugin/marketplace.json
plugins/auditlanes/package-manifest.yaml
plugins/auditlanes/.claude-plugin/plugin.json
plugins/auditlanes/.codex-plugin/plugin.json
```

## Tagging

```bash
git status
git add .
git commit -m "Release AuditLanes v0.4.8"
git tag -a v0.4.8 -m "AuditLanes v0.4.8"
git push origin main
git push origin v0.4.8
```

## Claude Team Onboarding

A consuming repository can advertise and enable the marketplace through
`.claude/settings.json`:

```json
{
  "extraKnownMarketplaces": {
    "auditlanes": {
      "source": {
        "source": "github",
        "repo": "OWNER/REPO",
        "ref": "v0.4.8"
      }
    }
  },
  "enabledPlugins": {
    "auditlanes@auditlanes": true
  }
}
```
