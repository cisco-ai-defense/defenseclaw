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

"""An init re-run that adopts the OpenClaw token audits with the running gateway's (GAP-0490).

``defenseclaw init`` on an existing install with OpenClaw active saved the
token from openclaw.json to .env, switched token_env, then sent its
init-gateway audit event with the new token to the gateway still running on
the old one: 401, a retry with the same new value from .env, and init exited 1
halfway with .env already changed. The guided first run (bootstrap) made the
same change and lost its audit row.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest
import requests
from click.testing import CliRunner
from defenseclaw.commands import cmd_init
from defenseclaw.config import Config
from defenseclaw.context import AppContext
from defenseclaw.logger import Logger

from tests.helpers import cleanup_app, make_app_context

pytestmark = pytest.mark.supported_connector_host

_RUNNING = "running-gateway-token"
_OPENCLAW = "openclaw-side-token"


class _Gateway:
    """The gateway API: it admits facts sent with the token it loaded at start."""

    def __init__(self, token: str) -> None:
        self.token = token
        self.tokens: list[str] = []
        self.admitted: list[str] = []

    def client(self, **kwargs):
        gateway, token = self, kwargs["token"]

        class _Client:
            def emit_cli_observability(self, payload) -> None:
                gateway.tokens.append(token)
                if token != gateway.token:
                    response = requests.Response()
                    response.status_code = 401
                    raise requests.HTTPError("401 Client Error: Unauthorized", response=response)
                gateway.admitted.append(str((payload.get("action") or {}).get("name", "")))

            def close(self) -> None:
                return

        return _Client()


def _openclaw_active():
    """OpenClaw is active and its openclaw.json holds a token the running gateway never loaded."""

    return (
        patch.object(Config, "active_connectors", lambda self: ["openclaw"]),
        patch.object(
            cmd_init,
            "_resolve_gateway_for_connector",
            lambda cfg: {"host": "127.0.0.1", "port": 18789, "token": _OPENCLAW},
        ),
    )


def _gateway_running(data_dir: str) -> None:
    # This test process stands in for the gateway that loaded the old token.
    Path(data_dir, "gateway.pid").write_text(str(os.getpid()), encoding="utf-8")


class _TokenSwapCase(unittest.TestCase):
    def setUp(self) -> None:
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.cfg = self.app.cfg
        self.cfg.gateway.token = ""
        self.cfg.gateway.token_env = ""
        env = patch.dict(os.environ, {"DEFENSECLAW_GATEWAY_TOKEN": _RUNNING})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("OPENCLAW_GATEWAY_TOKEN", None)
        for patcher in _openclaw_active():
            patcher.start()
            self.addCleanup(patcher.stop)

    def tearDown(self) -> None:
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _saved_token(self) -> str:
        with open(os.path.join(self.cfg.data_dir, ".env"), encoding="utf-8") as handle:
            return handle.read()


class InitGatewayDefaultsTests(_TokenSwapCase):
    def _run(self, gateway: _Gateway) -> None:
        with patch("defenseclaw.logger.OrchestratorClient", side_effect=gateway.client):
            logger = Logger.from_config(self.cfg)
            cmd_init._setup_gateway_defaults(self.cfg, logger, is_new_config=False)
            # A later init step (guardrail, notifications) audits through the same logger.
            logger.log_action("install-dep", "guardrail", "builtin")

    def test_rerun_with_a_running_gateway_audits_with_its_token(self) -> None:
        _gateway_running(self.cfg.data_dir)
        gateway = _Gateway(_RUNNING)
        self._run(gateway)
        self.assertEqual(gateway.tokens, [_RUNNING, _RUNNING])
        self.assertEqual(gateway.admitted, ["init-gateway", "install-dep"])
        self.assertEqual(self.cfg.gateway.token_env, "OPENCLAW_GATEWAY_TOKEN")
        self.assertEqual(self.cfg.gateway.resolved_token(), _OPENCLAW)
        self.assertIn(f"OPENCLAW_GATEWAY_TOKEN={_OPENCLAW}", self._saved_token())

    def test_a_stopped_gateway_gets_the_new_token_without_a_rejected_try(self) -> None:
        gateway = _Gateway(_OPENCLAW)
        self._run(gateway)
        self.assertEqual(gateway.tokens, [_OPENCLAW, _OPENCLAW])

    def test_the_same_token_changes_nothing(self) -> None:
        _gateway_running(self.cfg.data_dir)
        os.environ["DEFENSECLAW_GATEWAY_TOKEN"] = _OPENCLAW
        gateway = _Gateway(_OPENCLAW)
        self._run(gateway)
        self.assertEqual(gateway.tokens, [_OPENCLAW, _OPENCLAW])


class BootstrapGatewayDefaultsTests(_TokenSwapCase):
    def test_guided_first_run_rerun_keeps_its_bootstrap_audit_row(self) -> None:
        # bootstrap_env swallowed the 401, so the row was lost and the later
        # first-run steps' audits failed the same way.
        from defenseclaw.bootstrap import bootstrap_env

        _gateway_running(self.cfg.data_dir)
        gateway = _Gateway(_RUNNING)
        with (
            patch("defenseclaw.config.config_path", return_value=Path(self.tmp_dir, "config.yaml")),
            patch("defenseclaw.logger.OrchestratorClient", side_effect=gateway.client),
        ):
            Path(self.tmp_dir, "config.yaml").write_text("x\n", encoding="utf-8")
            logger = Logger.from_config(self.cfg)
            report = bootstrap_env(self.cfg, logger)
            logger.log_action("setup-guardrail", "config", "connector=openclaw")
        self.assertTrue(report.openclaw_token_detected)
        self.assertEqual(gateway.tokens, [_RUNNING, _RUNNING])
        self.assertEqual(gateway.admitted, ["bootstrap", "setup-guardrail"])
        self.assertIn(f"OPENCLAW_GATEWAY_TOKEN={_OPENCLAW}", self._saved_token())


class InitRerunCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = os.path.realpath(tempfile.mkdtemp(prefix="dclaw-init-token-"))
        self.addCleanup(shutil.rmtree, self.tmp_dir, True)
        env = patch.dict(os.environ, {"DEFENSECLAW_GATEWAY_TOKEN": _RUNNING})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("OPENCLAW_GATEWAY_TOKEN", None)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_rerun_exits_zero_and_audits_with_the_running_token(
        self, mock_path, _env, _scanners, _guardrail, _which
    ) -> None:
        mock_path.return_value = Path(self.tmp_dir)
        runner = CliRunner()
        first = runner.invoke(cmd_init.init_cmd, ["--skip-install"], obj=AppContext())
        self.assertEqual(first.exit_code, 0, first.output)

        _gateway_running(self.tmp_dir)
        gateway = _Gateway(_RUNNING)
        active, resolve = _openclaw_active()
        with active, resolve, patch("defenseclaw.logger.OrchestratorClient", side_effect=gateway.client):
            result = runner.invoke(cmd_init.init_cmd, ["--skip-install"], obj=AppContext())
        self.assertEqual(result.exit_code, 0, result.output + repr(result.exception))
        self.assertIn("init-gateway", gateway.admitted)
        self.assertEqual(set(gateway.tokens), {_RUNNING})
        with open(os.path.join(self.tmp_dir, ".env"), encoding="utf-8") as handle:
            self.assertIn(f"OPENCLAW_GATEWAY_TOKEN={_OPENCLAW}", handle.read())


if __name__ == "__main__":
    unittest.main()
