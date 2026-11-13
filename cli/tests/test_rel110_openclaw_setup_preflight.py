# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""rel-1-0-10 GAP-0075 and GAP-0047: setup openclaw runs the OpenClaw
preflight before it saves anything, and native OpenClaw (Windows) shows no
guardrail port and no PATH shims."""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner
from defenseclaw.commands import cmd_setup
from defenseclaw.commands.cmd_setup import setup as setup_group

from tests.helpers import cleanup_app, make_app_context


def test_setup_openclaw_refuses_a_failing_preflight_before_saving():
    app, root, db_path = make_app_context()
    try:
        refusal = "OpenClaw preflight: the plugin folder is not owned by this account."
        with (
            patch.object(cmd_setup, "_ensure_connector_available"),
            patch.object(cmd_setup, "_agent_settings_refusal", return_value=refusal) as check,
            patch.object(cmd_setup, "execute_guardrail_setup") as execute,
        ):
            result = CliRunner().invoke(setup_group, ["openclaw", "--non-interactive", "--no-restart"], obj=app)
        assert result.exit_code == 1, result.output
        assert refusal in result.output
        assert check.call_args.args[1] == "openclaw"
        execute.assert_not_called()
    finally:
        cleanup_app(app, db_path, root)


def test_native_openclaw_shows_no_shims_and_no_port():
    meta = {"subprocess_policy": "PATH shims"}
    with patch("defenseclaw.platform_support.host_os", return_value="windows"):
        assert cmd_setup._openclaw_native_here("openclaw")
        assert cmd_setup._subprocess_policy_display("openclaw", meta) == "none (native plugin hooks)"
        assert cmd_setup._subprocess_policy_display("codex", meta) == "PATH shims"
    with patch("defenseclaw.platform_support.host_os", return_value="linux"):
        assert not cmd_setup._openclaw_native_here("openclaw")
        assert cmd_setup._subprocess_policy_display("openclaw", meta) == "PATH shims"
