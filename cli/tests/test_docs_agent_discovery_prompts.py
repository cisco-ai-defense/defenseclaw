"""The discovery how-to must show the confirmations the CLI actually asks."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "cli/defenseclaw/commands/cmd_agent.py"
PAGE = ROOT / "docs-site/content/docs/ai-discovery.mdx"


def test_discovery_howto_names_both_confirmation_prompts_and_unattended_flags() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    assert source.count('click.confirm("  Proceed?", default=True)') >= 2
    page = PAGE.read_text(encoding="utf-8")
    enable = page.split("2. Turn on continuous discovery and scan now.", 1)[1].split("3. Read the inventory.", 1)[0]
    disable = page.split("## Turn it off", 1)[1].split("## Next", 1)[0]
    for section in (enable, disable):
        assert "`Proceed? [Y/n]`" in section
    assert "defenseclaw agent discovery enable --restart --scan --yes" in enable
    assert "defenseclaw agent discovery disable --yes" in disable
