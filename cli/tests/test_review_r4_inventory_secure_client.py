"""Focused regressions for inventory and Secure Client Python CLI behavior."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import patch

from click.testing import CliRunner
from defenseclaw.commands.cmd_agent import agent
from defenseclaw.commands.cmd_aibom import aibom
from defenseclaw.commands.cmd_alerts import alerts
from defenseclaw.config import default_config
from defenseclaw.inventory.claw_inventory import attach_ide_plugins, build_claw_aibom
from defenseclaw.models import Event

from tests.helpers import cleanup_app, make_app_context


def test_ide_page_cap_is_partial() -> None:
    inv = {"summary": {}}
    attach_ide_plugins(inv, {"plugins": [{}], "next_cursor": "more"})
    assert inv["summary"]["ide_plugins"]["count"] == 1
    assert inv["summary"]["ide_plugins"]["partial"] is True

def test_secure_client_aibom_skips_ide_gateway_and_output() -> None:
    app, tmp_dir, db_path = make_app_context()
    try:
        app.cfg.active_connectors = lambda: ["codex"]
        with patch("defenseclaw.commands.cmd_status._enterprise_profile", return_value="secure_client"), \
             patch("defenseclaw.commands.cmd_aibom._fetch_ide_plugins") as fetch, \
             patch("defenseclaw.commands.cmd_aibom._scan_one_connector",
                   return_value=({"connector": "codex"}, None)):
            result = CliRunner().invoke(aibom, ["scan", "--json"], obj=app, catch_exceptions=False)
        assert result.exit_code == 0, result.output
        assert json.loads(result.output) == {"connector": "codex"}
        fetch.assert_not_called()
    finally:
        cleanup_app(app, db_path, tmp_dir)

