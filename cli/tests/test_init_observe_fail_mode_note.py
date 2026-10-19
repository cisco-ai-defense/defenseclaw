# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""GAP-0003: init says why an observe-mode connector's hooks are fail-open
while guardrail.hook_fail_mode (the action-mode value) is closed."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch


def test_init_says_why_an_observe_connector_is_fail_open() -> None:
    from defenseclaw import bootstrap

    guardrail = SimpleNamespace(
        effective_mode=lambda _name: "observe", effective_hook_fail_mode=lambda _name: "open", hook_fail_mode="closed"
    )
    cfg = SimpleNamespace(guardrail=guardrail, claw=SimpleNamespace(workspace_dir=""))
    with patch("defenseclaw.commands.cmd_setup.execute_guardrail_setup", return_value=(True, [])):
        step = bootstrap._quiet_guardrail_setup(SimpleNamespace(cfg=cfg), "codex", verbose=False)
    assert step.status == "pass"
    assert (
        "fail mode=open (observe mode keeps hooks fail-open; guardrail.hook_fail_mode=closed applies in action mode)"
        in (step.detail)
    )
