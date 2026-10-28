"""Keep upgrade guidance accurate for plugins loaded before an install."""

import re
import unittest
from pathlib import Path

UPGRADE_GUIDE = Path(__file__).resolve().parents[1] / "content/docs/get-started/upgrade.mdx"
INSTALL_GUIDE = Path(__file__).resolve().parents[1] / "content/docs/get-started/install.mdx"


# unittest form so `npm run test:docs-py` (stdlib only) runs it (GAP-0011).
class UpgradeInstallWindowDocsTest(unittest.TestCase):
    def test_upgrade_requires_fresh_agent_processes_after_gateway_restart(self) -> None:
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


    def test_first_install_requires_agents_to_restart_for_plugin_loading(self) -> None:
        guide = " ".join(INSTALL_GUIDE.read_text(encoding="utf-8").split())
        install = guide.split("## Install", 1)[1].split("## Prerequisites for source builds", 1)[0]
        assert re.search(r"first install.*quit OpenCode and Amp", install, re.I)
        assert re.search(r"plugin.*load.*process start", install, re.I)
        assert re.search(r"installer refuses.*running", install, re.I)
        assert re.search(r"start (?:a )?new agent process.*gateway.*healthy", install, re.I)


if __name__ == "__main__":
    unittest.main()
