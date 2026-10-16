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

"""A setup that saves a new gateway token without a restart audits with the old one (GAP-0464).

``setup openclaw --replace --no-restart`` adopted OpenClaw's gateway token,
saved the change, then sent its own setup audit event with the new token to
the gateway that was still running on the old one: 401, and the command
exited nonzero after the change was saved. ``setup gateway --token`` did the
same before the restart that follows it.
"""

from __future__ import annotations

import json
import os
import unittest
from unittest.mock import patch

import click
import requests
from click.testing import CliRunner
from defenseclaw.commands import cmd_setup
from defenseclaw.commands.cmd_setup import setup as setup_group
from defenseclaw.file_permissions import atomic_write_private_bytes
from defenseclaw.logger import Logger

from tests.helpers import cleanup_app, make_app_context

_RUNNING = "running-gateway-token"
_OPENCLAW = "openclaw-side-token"


class _Gateway:
    """The gateway API: it admits facts sent with the token it loaded at start."""

    def __init__(self, token: str) -> None:
        self.token = token
        self.tokens: list[str] = []
        self.admitted: list[dict] = []

    def client(self, **kwargs):
        gateway, token = self, kwargs["token"]

        class _Client:
            def emit_cli_observability(self, payload) -> None:
                gateway.tokens.append(token)
                if token != gateway.token:
                    response = requests.Response()
                    response.status_code = 401
                    raise requests.HTTPError("401 Client Error: Unauthorized", response=response)
                gateway.admitted.append(dict(payload))

            def close(self) -> None:
                return

        return _Client()


class SetupAuditUsesTheRunningGatewayTokenTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.cfg_path = os.path.join(self.tmp_dir, "config.yaml")
        self.app.cfg.save = lambda: atomic_write_private_bytes(self.cfg_path, b"x\n")  # type: ignore[assignment]
        self.app.cfg.gateway.token = ""
        self.app.cfg.gateway.token_env = ""
        openclaw = os.path.join(self.tmp_dir, "openclaw.json")
        with open(openclaw, "w", encoding="utf-8") as handle:
            json.dump({"gateway": {"auth": {"token": _OPENCLAW}}}, handle)
        self.app.cfg.claw.config_file = openclaw
        env = patch.dict(os.environ, {"DEFENSECLAW_GATEWAY_TOKEN": _RUNNING})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("OPENCLAW_GATEWAY_TOKEN", None)

    def tearDown(self) -> None:
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _adopt_and_audit(self, gateway: _Gateway, *, alive: bool = True) -> None:
        with (
            patch("defenseclaw.process_liveness.pid_file_alive", return_value=alive),
            patch("defenseclaw.logger.OrchestratorClient", side_effect=gateway.client),
            click.Context(click.Command("openclaw")),
        ):
            self.app.logger = Logger.from_config(self.app.cfg)
            cmd_setup._adopt_openclaw_gateway_token(self.app, restart=False)
            self.assertEqual(self.app.cfg.gateway.resolved_token(), _OPENCLAW)
            cmd_setup._log_setup_action(self.app, "setup-guardrail", "connector=openclaw", allow_offline=True)

    def test_no_restart_openclaw_token_swap_audits_on_the_running_gateway(self) -> None:
        gateway = _Gateway(_RUNNING)
        self._adopt_and_audit(gateway)
        self.assertEqual(gateway.tokens, [_RUNNING])
        self.assertEqual(len(gateway.admitted), 1)
        with open(os.path.join(self.app.cfg.data_dir, ".env"), encoding="utf-8") as handle:
            self.assertIn(f"DEFENSECLAW_GATEWAY_TOKEN={_OPENCLAW}", handle.read())

    def test_a_gateway_restarted_on_the_new_token_still_admits_the_event(self) -> None:
        gateway = _Gateway(_OPENCLAW)
        self._adopt_and_audit(gateway)
        self.assertEqual(gateway.tokens, [_RUNNING, _OPENCLAW])
        self.assertEqual(len(gateway.admitted), 1)

    def test_a_stopped_gateway_gets_the_new_token_without_a_rejected_try(self) -> None:
        gateway = _Gateway(_OPENCLAW)
        self._adopt_and_audit(gateway, alive=False)
        self.assertEqual(gateway.tokens, [_OPENCLAW])

    def test_setup_gateway_new_token_exits_zero_and_audits_with_the_running_token(self) -> None:
        gateway = _Gateway(_RUNNING)
        self.app.logger = Logger.from_config(self.app.cfg)
        with (
            patch("defenseclaw.process_liveness.pid_file_alive", return_value=True),
            patch.object(cmd_setup, "_restart_defense_gateway", return_value=True),
            patch.object(cmd_setup, "_restart_services", return_value=None),
            patch("defenseclaw.logger.OrchestratorClient", side_effect=gateway.client),
        ):
            result = CliRunner().invoke(
                setup_group,
                ["gateway", "--token", "new-openclaw-token", "--non-interactive", "--no-verify"],
                obj=self.app,
                catch_exceptions=False,
            )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn("did not accept its setup audit event", result.output)
        self.assertEqual(gateway.tokens, [_RUNNING])
        self.assertEqual(self.app.cfg.gateway.resolved_token(), "new-openclaw-token")


if __name__ == "__main__":
    unittest.main()
