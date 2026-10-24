# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Connector recipes must work with the single connector they set up."""

import re
from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parents[2] / "docs-site/content/docs"
PAGES = sorted(p for p in (DOCS / "connectors").glob("*.mdx") if "## Turn it off" in p.read_text() and "guardrail disable" in p.read_text())


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.stem)
def test_turn_off_explains_single_and_multi_connector_scope(page):
    from defenseclaw.platform_support import is_proxy_connector

    section = page.read_text().split("## Turn it off", 1)[1].split("\n## ", 1)[0]
    assert "single-connector" in section
    assert "defenseclaw guardrail disable --yes" in section
    assert "`defenseclaw guardrail enable`" in section
    if is_proxy_connector(page.stem):
        # A proxy connector runs alone: setup refuses it next to hook
        # connectors, and enable needs guardrail.model (GAP-0667).
        assert "cannot run next to hook connectors" in section
        assert f"`defenseclaw setup {page.stem} --replace`" in section
        assert "Turn it back on by running the Set up command again" in section
        return
    assert "multi-connector" in section
    assert f"--connector {page.stem}" in section


@pytest.mark.parametrize("connector", ("openclaw", "zeptoclaw"))
def test_proxy_recovery_keeps_the_saved_mode(connector):
    section = (DOCS / "connectors" / f"{connector}.mdx").read_text().split("## Turn it off", 1)[1]
    recovery = section.split("Turn it back on by running the Set up command again", 1)[1].split("\n", 1)[0]
    commands = re.findall(rf"`(defenseclaw setup {connector}[^`]+)`", recovery)
    assert commands == [f"defenseclaw setup {connector} --restart"]


def test_hitl_selector_requires_multiple_connectors():
    text = (DOCS / "how-to/guardrail/ask-before-risky-calls.mdx").read_text()
    assert "multi-connector install" in text
    assert "single connector, omit `--connector`" in text


TURN_OFF_PAGES = sorted(p for p in (DOCS / "connectors").glob("*.mdx") if "## Turn it off" in p.read_text())


@pytest.mark.parametrize("page", TURN_OFF_PAGES, ids=lambda p: p.stem)
def test_turn_off_lists_only_commands_the_cli_runs(page):
    """GAP-0563: every command in "Turn it off" is a real command the CLI does not refuse."""
    import click
    from defenseclaw.commands.cmd_plugin import _MANAGED_BRIDGES
    from defenseclaw.main import cli

    section = page.read_text().split("## Turn it off", 1)[1].split("\n## ", 1)[0]
    commands = re.findall(r"`(defenseclaw [^`]+)`", section) + re.findall(r"^(defenseclaw .+)$", section, re.M)
    assert commands
    for command in commands:
        words = command.split()[1:]
        group, path = cli, []
        while isinstance(group, click.Group) and words and not words[0].startswith("-"):
            sub = group.get_command(click.Context(group), words[0])
            assert sub is not None, f"{page.name}: {command!r} is not a defenseclaw command"
            group, path, words = sub, [*path, words[0]], words[1:]
        assert not isinstance(group, click.Group), f"{page.name}: {command!r} names a group, not a command"
        if path[:1] == ["plugin"] and words[:1] == ["defenseclaw"]:
            connector = words[words.index("--connector") + 1] if "--connector" in words else ""
            assert connector not in _MANAGED_BRIDGES, (
                f"{page.name}: {command!r} is refused by the CLI (managed {connector} bridge)"
            )


def test_kiro_setup_discloses_the_cli_setting_it_writes(capsys):
    from defenseclaw.commands import cmd_setup

    source = (DOCS.parents[2] / "internal/gateway/connector/kiro.go").read_text()
    assert "patchKiroDefaultAgentSetting(settingsPath" in source
    cmd_setup._print_connector_mutation_notice("kiro")
    notice = capsys.readouterr().out
    assert "~/.kiro/settings/cli.json" in notice
    assert "chat.defaultAgent" in notice
    assert "~/.kiro/settings/mcp.json is discovery-only" in notice
    assert "cli.json and ~/.kiro/settings/mcp.json are discovery-only" not in notice

    page = (DOCS / "connectors/kiro.mdx").read_text().split("## Files it changes", 1)[1].split("## Limits", 1)[0]
    assert "~/.kiro/settings/cli.json" in page and "chat.defaultAgent" in page
    assert "unset or built-in" in page and "custom default" in page
