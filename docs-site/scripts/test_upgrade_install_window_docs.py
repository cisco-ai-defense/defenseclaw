"""Keep upgrade guidance accurate for plugins loaded before an install."""

import re
from pathlib import Path

UPGRADE_GUIDE = Path(__file__).resolve().parents[1] / "content/docs/get-started/upgrade.mdx"


def test_upgrade_requires_fresh_agent_processes_after_gateway_restart() -> None:
    guide = " ".join(UPGRADE_GUIDE.read_text(encoding="utf-8").split())
    upgrade = guide.split("## Upgrade", 1)[1].split("## Update notices", 1)[0]

    assert re.search(r"end (?:all|every) (?:running )?agent sessions? before (?:an |the )?upgrad", upgrade, re.I)
    assert re.search(r"quit OpenCode and Amp processes completely", upgrade, re.I)
    assert re.search(r"start (?:a )?(?:new|fresh) agent process(?:es)? after .*gateway.*healthy", upgrade, re.I)
    assert "OpenCode" in upgrade and "Amp" in upgrade
    assert re.search(r"(?:OpenCode|Amp).*load.*plugin.*once", upgrade, re.I)
    assert re.search(
        r"previous release.s plugin.*hook_fail_mode: open.*may allow tool calls.*gateway is stopped", upgrade, re.I
    )
    assert re.search(
        r"installer checks for running OpenCode and Amp processes.*before stopping the gateway.*refuses", upgrade, re.I
    )
    assert not re.search(r"agent hooks on a per-user install block.*hook_fail_mode: open", upgrade, re.I)
