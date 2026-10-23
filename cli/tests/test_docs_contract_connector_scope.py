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
    section = page.read_text().split("## Turn it off", 1)[1].split("\n## ", 1)[0]
    assert "single-connector" in section
    assert "defenseclaw guardrail disable --yes" in section
    assert "`defenseclaw guardrail enable`" in section
    assert "multi-connector" in section
    assert f"--connector {page.stem}" in section


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
