# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-0658: finding decisions use one vocabulary across hook connectors."""

from __future__ import annotations

import pytest
from defenseclaw.commands import cmd_alerts
from defenseclaw.tui.panels import alerts as alerts_panel


@pytest.mark.parametrize("connector", ["amp", "antigravity", "cursor", "devin", "kiro"])
def test_allowed_action_finding_is_alert_for_each_connector(connector: str) -> None:
    row = f"connector={connector} action=allow raw_action=allow mode=action would_block=false"
    target = f"{connector}:PreToolUse"
    assert cmd_alerts._hook_decision([row], target) == "alert"
    assert alerts_panel._hook_decision_from_rows([row], target) == "alert"


@pytest.mark.parametrize("connector", ["amp", "antigravity", "cursor", "devin", "kiro"])
def test_observe_mode_allow_finding_keeps_allow_decision(connector: str) -> None:
    row = f"connector={connector} action=allow raw_action=allow mode=observe would_block=false"
    target = f"{connector}:PreToolUse"
    assert cmd_alerts._hook_decision([row], target) == "allow"
    assert alerts_panel._hook_decision_from_rows([row], target) == "allowed"
