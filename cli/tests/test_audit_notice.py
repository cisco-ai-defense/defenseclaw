# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""A stopped gateway skips only the audit event of an applied change (GAP-1811, GAP-1823)."""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands import cmd_judge, cmd_setup
from defenseclaw.commands.cmd_skill import skill
from defenseclaw.enforce.policy import PolicyEngine
from defenseclaw.logger import CanonicalObservabilityError, CanonicalObservabilityUnavailableError

from tests.helpers import cleanup_app, make_app_context, make_separate_stderr_runner
from tests.test_cmd_judge import make_ctx


@pytest.fixture(autouse=True)
def _fresh_notice():
    with patch("defenseclaw.commands._audit_notice._NOTED", False):
        yield


def test_skill_block_with_gateway_down_warns_once_and_exits_zero() -> None:
    app, tmp_dir, db_path = make_app_context()
    try:
        app.logger.log_action = MagicMock(side_effect=CanonicalObservabilityUnavailableError("down"))
        result = make_separate_stderr_runner().invoke(skill, ["block", "demo"], obj=app)
        assert result.exit_code == 0, result.output
        assert PolicyEngine(app.store).is_blocked("skill", "demo")
        assert result.stderr.count("audit event was not recorded") == 1
        assert "run the command again" not in result.stderr
    finally:
        cleanup_app(app, db_path, tmp_dir)


@patch.object(cmd_setup, "_restart_services")
def test_judge_add_with_gateway_down_warns_and_exits_zero(_restart) -> None:
    app = make_ctx()
    app.logger.log_config_change = MagicMock(side_effect=CanonicalObservabilityUnavailableError("down"))
    result = make_separate_stderr_runner().invoke(cmd_judge.judge, ["add", "hermes"], obj=app)
    assert result.exit_code == 0, result.output
    assert app.cfg.guardrail.judge.hook_connectors == ["hermes"]
    assert "audit event was not recorded" in result.stderr


@patch.object(cmd_setup, "_restart_services")
def test_refused_audit_event_still_fails(_restart) -> None:
    app = make_ctx()
    app.logger.log_config_change = MagicMock(side_effect=CanonicalObservabilityError("refused"))
    result = make_separate_stderr_runner().invoke(cmd_judge.judge, ["add", "hermes"], obj=app)
    assert isinstance(result.exception, CanonicalObservabilityError)
