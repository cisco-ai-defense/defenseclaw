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

"""Every command that changes the gateway token audits with a token the gateway accepts (GAP-0490).

A new gateway token takes effect when the gateway starts again; until then the
running gateway admits only the token it loaded. ``setup openclaw
--no-restart``, ``setup gateway --token`` (GAP-0464), an ``init`` re-run and
the guided first run (GAP-0490, tests in test_setup_audit_running_token.py and
test_init_audit_running_token.py) sent their own audit event with the new
token, got 401 and failed after the change was saved. These are the other
commands that write the token while the gateway runs: ``keys set`` (it had
the same failure), ``config set gateway.token_env``, ``setup <connector>
--replace``, a ``quickstart`` re-run and ``setup rotate-token`` (which restarts
the gateway on the new token itself).
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import requests
from click.testing import CliRunner
from defenseclaw import config as config_module
from defenseclaw.commands import cmd_init, cmd_setup
from defenseclaw.commands.cmd_config import config_cmd
from defenseclaw.commands.cmd_keys import keys_cmd
from defenseclaw.commands.cmd_quickstart import quickstart_cmd
from defenseclaw.commands.cmd_setup import setup as setup_group
from defenseclaw.config import PerConnectorGuardrailConfig
from defenseclaw.context import AppContext
from defenseclaw.file_permissions import atomic_write_private_bytes
from defenseclaw.logger import Logger

from tests.helpers import cleanup_app, make_app_context, record_test_setup_agent_selections
from tests.test_cmd_setup_multi_connector import _setup_patches
from tests.test_cmd_setup_rotate_token import _make_rotate_ctx

_RUNNING = "running-gateway-token"
_NEW = "new-gateway-token"


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


def _gateway_running(data_dir: str) -> None:
    # This test process stands in for the gateway that loaded the old token.
    Path(data_dir, "gateway.pid").write_text(str(os.getpid()), encoding="utf-8")


def _dotenv(data_dir: str) -> str:
    path = Path(data_dir, ".env")
    return path.read_text(encoding="utf-8") if path.exists() else ""


class _RunningTokenCase(unittest.TestCase):
    def setUp(self) -> None:
        env = patch.dict(os.environ, {"DEFENSECLAW_GATEWAY_TOKEN": _RUNNING})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("OPENCLAW_GATEWAY_TOKEN", None)


class KeysSetGatewayTokenTests(_RunningTokenCase):
    def setUp(self) -> None:
        super().setUp()
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.app.cfg.gateway.token = ""
        self.app.cfg.gateway.token_env = ""

    def tearDown(self) -> None:
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _set(self, gateway: _Gateway, name: str = "DEFENSECLAW_GATEWAY_TOKEN"):
        with patch("defenseclaw.logger.OrchestratorClient", side_effect=gateway.client):
            self.app.logger = Logger.from_config(self.app.cfg)
            return CliRunner().invoke(keys_cmd, ["set", name, "--value", _NEW], obj=self.app)

    def test_a_new_gateway_token_audits_on_the_running_gateway(self) -> None:
        # Before the fix: 401, the same value from .env, then a traceback, exit 1.
        _gateway_running(self.app.cfg.data_dir)
        gateway = _Gateway(_RUNNING)
        result = self._set(gateway)
        self.assertEqual(result.exit_code, 0, result.output + repr(result.exception))
        self.assertEqual(gateway.tokens, [_RUNNING])
        self.assertEqual(len(gateway.admitted), 1)
        self.assertIn(f"DEFENSECLAW_GATEWAY_TOKEN={_NEW}", _dotenv(self.app.cfg.data_dir))
        self.assertIn("defenseclaw-gateway restart", result.output)
        self.assertNotIn(_NEW, result.output)

    def test_a_stopped_gateway_gets_the_new_token_without_a_rejected_try(self) -> None:
        gateway = _Gateway(_NEW)
        result = self._set(gateway)
        self.assertEqual(result.exit_code, 0, result.output + repr(result.exception))
        self.assertEqual(gateway.tokens, [_NEW])

    def test_another_key_keeps_the_token_it_had(self) -> None:
        _gateway_running(self.app.cfg.data_dir)
        gateway = _Gateway(_RUNNING)
        result = self._set(gateway, "OPENAI_API_KEY")
        self.assertEqual(result.exit_code, 0, result.output + repr(result.exception))
        self.assertEqual(gateway.tokens, [_RUNNING])


class ConfigSetTokenEnvTests(_RunningTokenCase):
    def test_config_set_audits_with_the_token_the_running_gateway_loaded(self) -> None:
        tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="dclaw-config-token-")))
        self.addCleanup(shutil.rmtree, tmp, True)
        path = tmp / "config.yaml"
        path.write_text(f"config_version: 9\ndata_dir: {tmp}\nobservability: {{}}\n", encoding="utf-8")
        _gateway_running(str(tmp))
        gateway = _Gateway(_RUNNING)
        with (
            patch.dict(os.environ, {"DEFENSECLAW_HOME": str(tmp), "DC_D10_NEW_TOKEN": _NEW}),
            patch.object(config_module, "config_path", return_value=path),
            patch("defenseclaw.gateway.local_policy_digest", return_value=None),
            patch("defenseclaw.logger.OrchestratorClient", side_effect=gateway.client),
        ):
            os.environ.pop("DEFENSECLAW_DEPLOYMENT_MODE", None)
            app = AppContext()
            app.cfg = config_module.load()
            app.logger = Logger.from_config(app.cfg)
            result = CliRunner().invoke(config_cmd, ["set", "gateway.token_env", "DC_D10_NEW_TOKEN"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output + repr(result.exception))
        self.assertIn("token_env: DC_D10_NEW_TOKEN", path.read_text(encoding="utf-8"))
        # The gateway loads the new token setting when it restarts; this
        # command's own audit event goes to the gateway that runs now.
        self.assertEqual(gateway.tokens, [_RUNNING])
        self.assertEqual(len(gateway.admitted), 1)


class SetupReplaceTests(_RunningTokenCase):
    def setUp(self) -> None:
        super().setUp()
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.app.cfg.save = lambda: atomic_write_private_bytes(  # type: ignore[assignment]
            os.path.join(self.tmp_dir, "config.yaml"), b"x\n"
        )
        self.app.cfg.gateway.token = ""
        self.app.cfg.gateway.token_env = ""
        openclaw = os.path.join(self.tmp_dir, "openclaw.json")
        with open(openclaw, "w", encoding="utf-8") as handle:
            json.dump({"gateway": {"auth": {"token": _NEW}}}, handle)
        self.app.cfg.claw.config_file = openclaw
        self.app.cfg.guardrail.connectors = {c: PerConnectorGuardrailConfig() for c in ("codex", "cursor")}
        self.app.cfg.guardrail.connector = "codex"
        self.app.cfg.claw.mode = "codex"

    def tearDown(self) -> None:
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def test_replace_with_openclaw_no_restart_audits_on_the_running_gateway(self) -> None:
        _gateway_running(self.app.cfg.data_dir)
        gateway = _Gateway(_RUNNING)

        def backend(*_args, **_kwargs) -> None:
            # The guardrail backend's own setup audit event.
            cmd_setup._log_setup_action(self.app, "setup-guardrail", "connector=openclaw", allow_offline=True)

        with (
            _setup_patches(),
            # setup openclaw is refused on a Windows host (hook-only); pin the OS.
            patch("defenseclaw.commands.cmd_setup.platform_support.host_os", return_value="linux"),
            patch("defenseclaw.commands.cmd_setup.setup_guardrail", side_effect=backend),
            patch("defenseclaw.logger.OrchestratorClient", side_effect=gateway.client),
        ):
            self.app.logger = Logger.from_config(self.app.cfg)
            result = CliRunner().invoke(
                setup_group, ["openclaw", "--replace", "--yes", "--no-restart"], obj=self.app, catch_exceptions=False
            )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(self.app.cfg.gateway.resolved_token(), _NEW)
        self.assertTrue(gateway.tokens)
        self.assertEqual(set(gateway.tokens), {_RUNNING})


class QuickstartRerunTests(_RunningTokenCase):
    def setUp(self) -> None:
        super().setUp()
        self.tmp_dir = os.path.realpath(tempfile.mkdtemp(prefix="dclaw-quickstart-token-"))
        self.addCleanup(shutil.rmtree, self.tmp_dir, True)
        self.home_dir = os.path.join(self.tmp_dir, "home")
        self.empty_path = os.path.join(self.tmp_dir, "empty-bin")
        os.makedirs(self.home_dir)
        os.makedirs(self.empty_path)
        selection = patch(
            "defenseclaw.agent_selection.record_setup_agent_selections",
            side_effect=record_test_setup_agent_selections,
        )
        selection.start()
        self.addCleanup(selection.stop)

    def _invoke(self):
        return CliRunner().invoke(
            quickstart_cmd,
            ["--connector", "hermes", "--skip-gateway", "--json-summary"],
            env={
                "DEFENSECLAW_HOME": self.tmp_dir,
                "HOME": self.home_dir,
                "USERPROFILE": self.home_dir,
                "PATH": self.empty_path,
            },
        )

    @patch("defenseclaw.commands.cmd_setup._check_connector_version_supported_for_setup", return_value=True)
    def test_rerun_that_adopts_the_openclaw_token_audits_on_the_running_gateway(self, _gate) -> None:
        first = self._invoke()
        self.assertEqual(first.exit_code, 0, first.output)
        _gateway_running(self.tmp_dir)
        gateway = _Gateway(_RUNNING)
        with (
            patch.object(
                cmd_init,
                "_resolve_gateway_for_connector",
                lambda cfg: {"host": "127.0.0.1", "port": 18789, "token": _NEW},
            ),
            patch("defenseclaw.logger.OrchestratorClient", side_effect=gateway.client),
        ):
            result = self._invoke()
        self.assertEqual(result.exit_code, 0, result.output + repr(result.exception))
        self.assertIn("bootstrap", gateway.admitted)
        self.assertEqual(set(gateway.tokens), {_RUNNING})
        self.assertIn(f"OPENCLAW_GATEWAY_TOKEN={_NEW}", _dotenv(self.tmp_dir))


class RotateTokenTests(_RunningTokenCase):
    def test_rotation_audits_once_with_the_new_token_on_the_restarted_gateway(self) -> None:
        # rotate-token stops the gateway, saves the new token and starts it
        # again before its audit event, so the event carries the new token.
        new = "b" * 64
        with tempfile.TemporaryDirectory() as td:
            app = _make_rotate_ctx(td, ["codex"])
            app.cfg.gateway.api_port = 18970
            app.cfg.gateway.token = ""
            app.cfg.gateway.resolved_token = lambda: os.environ.get("DEFENSECLAW_GATEWAY_TOKEN", "")
            Path(td, ".env").write_text(f"DEFENSECLAW_GATEWAY_TOKEN={_RUNNING}\n", encoding="utf-8")
            gateway = _Gateway(_RUNNING)

            def lifecycle(_data_dir: str, action: str, *, token: str, **_kwargs) -> None:
                if action == "start":
                    gateway.token = token

            with (
                patch.object(cmd_setup, "_run_rotate_token_lifecycle", side_effect=lifecycle),
                patch.object(cmd_setup.secrets, "token_hex", return_value=new),
                patch("defenseclaw.logger.OrchestratorClient", side_effect=gateway.client),
            ):
                app.logger = Logger.from_config(app.cfg)
                result = CliRunner().invoke(cmd_setup.rotate_token_cmd, ["--yes"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output + repr(result.exception))
        self.assertEqual(gateway.tokens, [new])
        self.assertEqual(len(gateway.admitted), 1)


if __name__ == "__main__":
    unittest.main()
