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

