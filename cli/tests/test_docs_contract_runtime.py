# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Runtime coverage claims follow the installed connector and deployment mode."""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs-site/content/docs"


def flat(name):
    return " ".join((DOCS / name).read_text().split())


def test_kiro_v2_does_not_add_a_prompt_result():
    text = flat("reference/connectors/kiro.mdx")
    assert "CLI 2.x agent has no prompt hook" in text
    assert "each prompt carries two results" not in text
    assert "two `UserPromptSubmit` audit rows" not in text


def test_mcp_arguments_do_not_inherit_a_shell_path_rule():
    text = flat("how-to/guardrail/stop-a-secret-upload.mdx")
    assert "`PATH-SSH-KEY` needs a recognized read or copy operation" in text
    assert "MCP arguments alone does not trigger it" in text
    assert "A literal `id_rsa` path matches" not in text


@pytest.mark.parametrize("name", ["connectors/codex.mdx", "reference/connectors/codex.mdx", "how-to/guardrail/catch-prompt-injection.mdx"])
def test_codex_notify_is_scoped_to_secure_client(name):
    text = flat(name)
    assert "Secure Client" in text
    assert "Per-user and standalone" in text or "per-user and standalone" in text
    assert "do not register" in text
    if name == "reference/connectors/codex.mdx":
        assert '<Node id="notify"' not in text
        row = next(line for line in (DOCS / name).read_text().splitlines() if line.startswith("| Notify entry"))
        assert "Secure Client only" in row


def test_hermes_verification_discloses_snapshot_and_checks_current_files():
    text = flat("reference/connectors/hermes.mdx")
    assert "last reconcile" in text
    assert "enterprise hooks verify --json" in text
    assert "current hook files" in text
    assert "Managed Hermes hook coverage is reported as unknown" in text
    assert "cannot certify a session-only `HERMES_HOME`" in text
    assert "#managed-verification" in flat("connectors/hermes.mdx")


def test_windows_hermes_gateway_failure_is_distinct_from_vendor_timeout():
    text = flat("appendix/windows-security-model.mdx")
    assert "Hermes never fails closed" not in text
    assert "Hermes blocks on DefenseClaw's valid block answer" in text
    assert "times out or cannot start" in text


def test_prompt_findings_follow_the_configured_threshold():
    text = flat("how-to/guardrail/catch-prompt-injection.mdx")
    assert "configured block threshold" in text
    assert "HIGH prompt findings can block" in text
    assert "A non-CRITICAL prompt finding is demoted" not in text


def test_site_description_qualifies_runtime_coverage():
    text = (ROOT / "docs-site/lib/site.ts").read_text()
    assert "Inspect the runtime events each connector sends." in text
    assert "Inspect prompts, completions, and tool calls at runtime." not in text


CODEX_SANDBOX_NOTIFY_PAGES = [
    "connectors/codex.mdx",
    "reference/connectors/codex.mdx",
    "how-to/guardrail/catch-prompt-injection.mdx",
]


@pytest.mark.parametrize("name", CODEX_SANDBOX_NOTIFY_PAGES)
def test_codex_no_notify_claim_names_the_openshell_exception(name):
    text = flat(name)
    assert "OpenShell sandbox" in text
    if name != "reference/connectors/codex.mdx":
        assert "On an ordinary host install" in text
    else:
        assert "installs on the host do not register" in text


def test_codex_sandbox_reference_describes_its_notify_bridge():
    text = (DOCS / "reference/connectors/codex.mdx").read_text()
    section = text.split("### OpenShell sandbox", 1)[1].split("\n## ", 1)[0]
    row = next(line for line in section.splitlines() if line.startswith("| Notify bridge"))
    assert "codex-notify.sh" in row and "managed_config.toml" in row
    assert "/api/v1/codex/notify" in row
    assert "never blocks" in row and "process list" in row


def test_codex_guide_warns_when_command_fields_are_removed():
    text = flat("connectors/codex.mdx")
    assert "may start and run without DefenseClaw hooks" in text
    assert "Codex will not start" not in text


def test_codex_notify_privacy_residual_includes_the_sandbox():
    text = (DOCS / "enterprise/plan/threat-model.mdx").read_text()
    row = next(line for line in text.splitlines() if line.startswith("| **Codex passes each turn"))
    assert "Secure Client" in row and "OpenShell sandbox" in row and "codex-notify.sh" in row
