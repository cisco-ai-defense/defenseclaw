# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Init reports the effective hook mode without attributing it to observe mode."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch


def test_init_reports_effective_mode_without_a_stale_observe_explanation() -> None:
    from defenseclaw import bootstrap

    guardrail = SimpleNamespace(
        effective_mode=lambda _name: "observe", effective_hook_fail_mode=lambda _name: "open", hook_fail_mode="closed"
    )
    cfg = SimpleNamespace(guardrail=guardrail, claw=SimpleNamespace(workspace_dir=""))
    with patch("defenseclaw.commands.cmd_setup.execute_guardrail_setup", return_value=(True, [])):
        step = bootstrap._quiet_guardrail_setup(SimpleNamespace(cfg=cfg), "codex", verbose=False)
    assert step.status == "pass"
    assert "fail mode=open" in step.detail
    assert "observe mode keeps hooks fail-open" not in step.detail
