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

"""End-to-end wiring tests for ``--refresh-bundle``.

Asserts that ``defenseclaw setup splunk --logs`` and
``defenseclaw setup local-observability up`` both invoke the
bundle-refresh helper before bringing the stack up, and that the
running-stack detector is consulted so a stop → refresh → start cycle
happens when Docker shows the project running.

We mock at the boundary between the CLI and Docker / disk so these
tests don't need a real Docker daemon or filesystem-resident bundle.
"""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
import uuid
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

pytestmark = pytest.mark.supported_connector_host
from defenseclaw import config
from defenseclaw.context import AppContext

from tests.permissions import assert_owner_only_file


def _make_app() -> tuple[AppContext, str]:
    """Build a Click context backed by a throwaway data dir."""
    tmp_dir = tempfile.mkdtemp(prefix="dclaw-refresh-wiring-")
    cfg = config.Config(data_dir=tmp_dir)
    app = AppContext()
    app.cfg = cfg
    return app, tmp_dir


def _bridge_env_file(data_dir: str) -> str:
    return os.path.join(data_dir, "splunk-bridge", "env", ".env")


def _read_dotenv(path: str) -> dict[str, str]:
    entries: dict[str, str] = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            entries[key] = value
    return entries


def _bridge_up_args(mock_run: MagicMock) -> list[str]:
    """Return the Splunk bridge `up` argv from mocked subprocess calls."""

    for call in mock_run.call_args_list:
        args = call.args[0]
        if len(args) >= 2 and args[1] == "up":
            return args
    raise AssertionError("Splunk bridge up command was not invoked")


class TestSetupSplunkRefreshWiring(unittest.TestCase):
    def setUp(self) -> None:
        self._local_stack_support = patch(
            "defenseclaw.commands.cmd_setup.local_shell_stacks_supported",
            return_value=True,
        )
        self._local_stack_support.start()
        self.addCleanup(self._local_stack_support.stop)
        self._native_local_splunk = patch(
            "defenseclaw.commands.cmd_setup._native_windows_local_splunk",
            return_value=False,
        )
        self._native_local_splunk.start()
        self.addCleanup(self._native_local_splunk.stop)
        self.runner = CliRunner()
        self.app, self.tmp_dir = _make_app()

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @patch(
        "defenseclaw.commands.cmd_setup._refresh_and_maybe_restart_splunk_bridge",
    )
    @patch("defenseclaw.commands.cmd_setup._preflight_docker", return_value=(True, ""))
    @patch("defenseclaw.commands.cmd_setup.subprocess.run")
    @patch(
        "defenseclaw.commands.cmd_setup.splunk_bridge_bin",
        return_value="/tmp/fake-splunk-claw-bridge",
    )
    def test_setup_splunk_logs_default_refreshes_bundle(
        self,
        _bridge_bin: MagicMock,
        mock_run: MagicMock,
        _preflight: MagicMock,
        mock_refresh: MagicMock,
    ) -> None:
        from defenseclaw.bundle_refresh import RefreshResult
        from defenseclaw.commands.cmd_setup import setup

        mock_refresh.return_value = RefreshResult(
            bundle_kind="splunk-bridge",
            seeded_dest=os.path.join(self.tmp_dir, "splunk-bridge"),
            bundle_source="/dummy/bundle",
            refreshed=True,
            refreshed_paths=["compose/docker-compose.local.yml"],
        )
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(
                {
                    "splunk_web_url": "http://127.0.0.1:8000",
                    "hec_url": "http://127.0.0.1:8088/services/collector/event",
                    "hec_token": "bootstrap-token",
                    "license_group": "Free",
                    "web_login_required": False,
                    "index": "defenseclaw_local",
                    "source": "defenseclaw",
                    "sourcetype": "defenseclaw:json",
                }
            ),
            stderr="",
        )

        result = self.runner.invoke(
            setup,
            ["splunk", "--logs", "--non-interactive", "--accept-splunk-license"],
            obj=self.app,
            catch_exceptions=False,
        )

        self.assertEqual(result.exit_code, 0, result.output)
        env_file = _bridge_env_file(self.tmp_dir)
        mock_refresh.assert_called_once_with(self.tmp_dir, env_file=env_file)
        self.assertEqual(
            _bridge_up_args(mock_run),
            ["/tmp/fake-splunk-claw-bridge", "up", "--env-file", env_file, "--output", "json"],
        )

        assert_owner_only_file(env_file)
        entries = _read_dotenv(env_file)
        self.assertEqual(entries["SPLUNK_HEC_TOKEN"], entries["DEFENSECLAW_HEC_TOKEN"])
        uuid.UUID(entries["SPLUNK_HEC_TOKEN"])
        self.assertEqual(entries["DEFENSECLAW_INTEGRATION_ENABLED"], "true")
        self.assertTrue(entries["SPLUNK_PASSWORD"].startswith("DefenseClawLocal-"))
        self.assertTrue(entries["SPLUNK_PASSWORD"].endswith("!"))

    @patch(
        "defenseclaw.commands.cmd_setup._refresh_and_maybe_restart_splunk_bridge",
    )
    @patch("defenseclaw.commands.cmd_setup._preflight_docker", return_value=(True, ""))
    @patch("defenseclaw.commands.cmd_setup.subprocess.run")
    @patch(
        "defenseclaw.commands.cmd_setup.splunk_bridge_bin",
        return_value="/tmp/fake-splunk-claw-bridge",
    )
    def test_setup_splunk_logs_no_refresh_bundle_skips_refresh(
        self,
        _bridge_bin: MagicMock,
        mock_run: MagicMock,
        _preflight: MagicMock,
        mock_refresh: MagicMock,
    ) -> None:
        from defenseclaw.commands.cmd_setup import setup

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(
                {
                    "splunk_web_url": "http://127.0.0.1:8000",
                    "hec_url": "http://127.0.0.1:8088/services/collector/event",
                    "hec_token": "bootstrap-token",
                    "license_group": "Free",
                    "web_login_required": False,
                    "index": "defenseclaw_local",
                    "source": "defenseclaw",
                    "sourcetype": "defenseclaw:json",
                }
            ),
            stderr="",
        )

        result = self.runner.invoke(
            setup,
            [
                "splunk",
                "--logs",
                "--non-interactive",
                "--accept-splunk-license",
                "--no-refresh-bundle",
            ],
            obj=self.app,
            catch_exceptions=False,
        )

        self.assertEqual(result.exit_code, 0, result.output)
        mock_refresh.assert_not_called()
        env_file = _bridge_env_file(self.tmp_dir)
        self.assertEqual(
            _bridge_up_args(mock_run),
            ["/tmp/fake-splunk-claw-bridge", "up", "--env-file", env_file, "--output", "json"],
        )


class TestRefreshAndMaybeRestartSplunkBridge(unittest.TestCase):
    """Direct coverage of the stop → refresh decision logic."""

    @patch(
        "defenseclaw.commands.cmd_setup.refresh_splunk_bridge",
    )
    @patch(
        "defenseclaw.commands.cmd_setup.is_compose_project_running",
        return_value=True,
    )
    @patch(
        "defenseclaw.commands.cmd_setup._resolve_bridge_bin",
        return_value="/fake/bin/splunk-claw-bridge",
    )
    @patch("defenseclaw.commands.cmd_setup.subprocess.run")
    def test_running_stack_is_stopped_before_refresh(
        self,
        mock_run: MagicMock,
        _resolve: MagicMock,
        _running: MagicMock,
        mock_refresh: MagicMock,
    ) -> None:
        from defenseclaw.bundle_refresh import RefreshResult
        from defenseclaw.commands.cmd_setup import (
            _refresh_and_maybe_restart_splunk_bridge,
        )

        mock_refresh.return_value = RefreshResult(
            bundle_kind="splunk-bridge",
            seeded_dest="/dest",
            bundle_source="/src",
            refreshed=True,
            refreshed_paths=["compose/docker-compose.local.yml"],
        )
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        env_file = "/data/splunk-bridge/env/.env"
        result = _refresh_and_maybe_restart_splunk_bridge("/data", env_file=env_file)

        self.assertTrue(result.was_running)
        self.assertTrue(result.stopped)
        # The down call must precede the refresh call. Pull the
        # subprocess args to confirm we asked the bridge for `down`.
        self.assertTrue(
            any(
                call.args[0] == ["/fake/bin/splunk-claw-bridge", "down", "--env-file", env_file]
                for call in mock_run.call_args_list
            )
        )
        mock_refresh.assert_called_once_with("/data")

    @patch(
        "defenseclaw.commands.cmd_setup.refresh_splunk_bridge",
    )
    @patch(
        "defenseclaw.commands.cmd_setup.is_compose_project_running",
        return_value=False,
    )
    @patch("defenseclaw.commands.cmd_setup.subprocess.run")
    def test_no_running_stack_skips_stop_step(
        self,
        mock_run: MagicMock,
        _running: MagicMock,
        mock_refresh: MagicMock,
    ) -> None:
        from defenseclaw.bundle_refresh import RefreshResult
        from defenseclaw.commands.cmd_setup import (
            _refresh_and_maybe_restart_splunk_bridge,
        )

        mock_refresh.return_value = RefreshResult(
            bundle_kind="splunk-bridge",
            seeded_dest="/dest",
            bundle_source="/src",
            refreshed=False,
        )

        result = _refresh_and_maybe_restart_splunk_bridge("/data")

        self.assertFalse(result.was_running)
        self.assertFalse(result.stopped)
        mock_run.assert_not_called()
        mock_refresh.assert_called_once_with("/data")


class LegacySetupLocalObservabilityRefreshWiring:
    def setUp(self) -> None:
        self._local_stack_support = patch(
            "defenseclaw.commands.cmd_setup_local_observability.local_shell_stacks_supported",
            return_value=True,
        )
        self._local_stack_support.start()
        self.addCleanup(self._local_stack_support.stop)
        self.runner = CliRunner()
        self.app, self.tmp_dir = _make_app()

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @patch(
        "defenseclaw.commands.cmd_setup_local_observability._refresh_and_maybe_restart_local_observability",
    )
    @patch(
        "defenseclaw.commands.cmd_setup_local_observability._preflight_docker",
        return_value=True,
    )
    @patch(
        "defenseclaw.commands.cmd_setup_local_observability._run_bridge_up",
    )
    @patch(
        "defenseclaw.commands.cmd_setup_local_observability._resolve_bridge",
        return_value="/fake/bin/openclaw-observability-bridge",
    )
    @patch(
        "defenseclaw.commands.cmd_setup_local_observability._apply_local_otlp_config",
    )
    @patch(
        "defenseclaw.commands.cmd_setup_local_observability._apply_local_otlp_audit_sink",
    )
    def test_up_default_calls_refresh_helper(
        self,
        _audit: MagicMock,
        _otlp: MagicMock,
        _resolve: MagicMock,
        mock_run_up: MagicMock,
        _preflight: MagicMock,
        mock_refresh: MagicMock,
    ) -> None:
        from defenseclaw.commands.cmd_setup_local_observability import (
            local_observability,
        )

        mock_run_up.return_value = {
            "otlp_endpoint": "127.0.0.1:4317",
            "otlp_protocol": "grpc",
            "grafana_url": "http://localhost:3000",
            "prometheus_url": "http://localhost:9090",
            "tempo_url": "http://localhost:3200",
            "loki_url": "http://localhost:3100",
            "otlp_http_endpoint": "127.0.0.1:4318",
        }

        result = self.runner.invoke(
            local_observability,
            ["up", "--no-wait"],
            obj=self.app,
            catch_exceptions=False,
        )

        self.assertEqual(result.exit_code, 0, result.output)
        mock_refresh.assert_called_once()
        # The standard setup path should bring host-mounted dashboards,
        # rules, and collector config up to the latest bundled version.
        self.assertTrue(mock_refresh.call_args.kwargs["refresh_config"])

    @patch(
        "defenseclaw.commands.cmd_setup_local_observability._refresh_and_maybe_restart_local_observability",
    )
    @patch(
        "defenseclaw.commands.cmd_setup_local_observability._preflight_docker",
        return_value=True,
    )
    @patch(
        "defenseclaw.commands.cmd_setup_local_observability._run_bridge_up",
    )
    @patch(
        "defenseclaw.commands.cmd_setup_local_observability._resolve_bridge",
        return_value="/fake/bin/openclaw-observability-bridge",
    )
    @patch(
        "defenseclaw.commands.cmd_setup_local_observability._apply_local_otlp_config",
    )
    @patch(
        "defenseclaw.commands.cmd_setup_local_observability._apply_local_otlp_audit_sink",
    )
    def test_up_no_refresh_bundle_skips_refresh(
        self,
        _audit: MagicMock,
        _otlp: MagicMock,
        _resolve: MagicMock,
        mock_run_up: MagicMock,
        _preflight: MagicMock,
        mock_refresh: MagicMock,
    ) -> None:
        from defenseclaw.commands.cmd_setup_local_observability import (
            local_observability,
        )

        mock_run_up.return_value = {
            "otlp_endpoint": "127.0.0.1:4317",
            "otlp_protocol": "grpc",
        }

        result = self.runner.invoke(
            local_observability,
            ["up", "--no-wait", "--no-refresh-bundle"],
            obj=self.app,
            catch_exceptions=False,
        )

        self.assertEqual(result.exit_code, 0, result.output)
        mock_refresh.assert_not_called()

    @patch(
        "defenseclaw.commands.cmd_setup_local_observability._refresh_and_maybe_restart_local_observability",
    )
    @patch(
        "defenseclaw.commands.cmd_setup_local_observability._preflight_docker",
        return_value=True,
    )
    @patch(
        "defenseclaw.commands.cmd_setup_local_observability._run_bridge_up",
    )
    @patch(
        "defenseclaw.commands.cmd_setup_local_observability._resolve_bridge",
        return_value="/fake/bin/openclaw-observability-bridge",
    )
    @patch(
        "defenseclaw.commands.cmd_setup_local_observability._apply_local_otlp_config",
    )
    @patch(
        "defenseclaw.commands.cmd_setup_local_observability._apply_local_otlp_audit_sink",
    )
    def test_up_refresh_config_propagates_flag(
        self,
        _audit: MagicMock,
        _otlp: MagicMock,
        _resolve: MagicMock,
        mock_run_up: MagicMock,
        _preflight: MagicMock,
        mock_refresh: MagicMock,
    ) -> None:
        from defenseclaw.commands.cmd_setup_local_observability import (
            local_observability,
        )

        mock_run_up.return_value = {
            "otlp_endpoint": "127.0.0.1:4317",
            "otlp_protocol": "grpc",
        }

        result = self.runner.invoke(
            local_observability,
            ["up", "--no-wait", "--refresh-config"],
            obj=self.app,
            catch_exceptions=False,
        )

        self.assertEqual(result.exit_code, 0, result.output)
        mock_refresh.assert_called_once()
        self.assertTrue(mock_refresh.call_args.kwargs["refresh_config"])

    @patch(
        "defenseclaw.commands.cmd_setup_local_observability._refresh_and_maybe_restart_local_observability",
    )
    @patch(
        "defenseclaw.commands.cmd_setup_local_observability._preflight_docker",
        return_value=True,
    )
    @patch(
        "defenseclaw.commands.cmd_setup_local_observability._run_bridge_up",
    )
    @patch(
        "defenseclaw.commands.cmd_setup_local_observability._resolve_bridge",
        return_value="/fake/bin/openclaw-observability-bridge",
    )
    @patch(
        "defenseclaw.commands.cmd_setup_local_observability._apply_local_otlp_config",
    )
    @patch(
        "defenseclaw.commands.cmd_setup_local_observability._apply_local_otlp_audit_sink",
    )
    def test_up_no_refresh_config_preserves_local_config(
        self,
        _audit: MagicMock,
        _otlp: MagicMock,
        _resolve: MagicMock,
        mock_run_up: MagicMock,
        _preflight: MagicMock,
        mock_refresh: MagicMock,
    ) -> None:
        from defenseclaw.commands.cmd_setup_local_observability import (
            local_observability,
        )

        mock_run_up.return_value = {
            "otlp_endpoint": "127.0.0.1:4317",
            "otlp_protocol": "grpc",
        }

        result = self.runner.invoke(
            local_observability,
            ["up", "--no-wait", "--no-refresh-config"],
            obj=self.app,
            catch_exceptions=False,
        )

        self.assertEqual(result.exit_code, 0, result.output)
        mock_refresh.assert_called_once()
        self.assertFalse(mock_refresh.call_args.kwargs["refresh_config"])


class LegacyRefreshAndMaybeRestartLocalObservability:
    """Direct coverage for local-observability refresh messaging."""

    @patch(
        "defenseclaw.commands.cmd_setup_local_observability.refresh_local_observability_stack",
    )
    @patch(
        "defenseclaw.commands.cmd_setup_local_observability.is_compose_project_running",
        return_value=False,
    )
    def test_preserved_config_hint_is_printed(
        self,
        _running: MagicMock,
        mock_refresh: MagicMock,
    ) -> None:
        from defenseclaw.bundle_refresh import RefreshResult
        from defenseclaw.commands.cmd_setup_local_observability import (
            _refresh_and_maybe_restart_local_observability,
        )

        mock_refresh.return_value = RefreshResult(
            bundle_kind="observability-stack",
            seeded_dest="/dest",
            bundle_source="/src",
            refreshed=False,
            preserved_paths=["grafana", "prometheus"],
        )

        output = io.StringIO()
        with redirect_stdout(output):
            _refresh_and_maybe_restart_local_observability(
                "/data",
                refresh_config=False,
            )

        self.assertIn("Preserved local observability config", output.getvalue())
        self.assertIn("--refresh-config", output.getvalue())
        self.assertIn("--no-refresh-config", output.getvalue())


class TestPythonControllerRefreshWiring(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = CliRunner()
        self.app, self.tmp_dir = _make_app()

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_up_refreshes_before_shared_controller_start(self) -> None:
        from defenseclaw.bundle_refresh import RefreshResult
        from defenseclaw.commands.cmd_setup_local_observability import local_observability
        from defenseclaw.observability.local_stack import CONTRACT, UpResult

        controller = MagicMock()
        controller.up.return_value = UpResult(dict(CONTRACT), readiness_verified=False)
        refresh = RefreshResult(
            bundle_kind="observability-stack",
            seeded_dest=os.path.join(self.tmp_dir, "observability-stack"),
            bundle_source="/bundle",
        )
        with (
            patch(
                "defenseclaw.commands.cmd_setup_local_observability._resolve_controller",
                return_value=controller,
            ),
            patch(
                "defenseclaw.commands.cmd_setup_local_observability._refresh_and_maybe_restart_local_observability",
                return_value=refresh,
            ) as refresh_call,
        ):
            result = self.runner.invoke(
                local_observability,
                ["up", "--no-wait", "--no-config"],
                obj=self.app,
                catch_exceptions=False,
            )

        self.assertEqual(result.exit_code, 0, result.output)
        controller.preflight.assert_called_once_with()
        controller.up.assert_called_once_with(timeout=180, wait=False)
        refresh_call.assert_called_once()
        self.assertTrue(refresh_call.call_args.kwargs["refresh_config"])

    def test_no_refresh_bundle_skips_refresh(self) -> None:
        from defenseclaw.commands.cmd_setup_local_observability import local_observability
        from defenseclaw.observability.local_stack import CONTRACT, UpResult

        controller = MagicMock()
        controller.up.return_value = UpResult(dict(CONTRACT), readiness_verified=False)
        with (
            patch(
                "defenseclaw.commands.cmd_setup_local_observability._resolve_controller",
                return_value=controller,
            ),
            patch(
                "defenseclaw.commands.cmd_setup_local_observability._refresh_and_maybe_restart_local_observability"
            ) as refresh_call,
        ):
            result = self.runner.invoke(
                local_observability,
                ["up", "--no-wait", "--no-config", "--no-refresh-bundle"],
                obj=self.app,
                catch_exceptions=False,
            )

        self.assertEqual(result.exit_code, 0, result.output)
        refresh_call.assert_not_called()

    def test_refresh_stop_uses_controller_and_preserves_config_hint(self) -> None:
        from defenseclaw.bundle_refresh import RefreshResult
        from defenseclaw.commands.cmd_setup_local_observability import (
            _refresh_and_maybe_restart_local_observability,
        )

        controller = MagicMock()
        controller.is_running.return_value = True
        refreshed = RefreshResult(
            bundle_kind="observability-stack",
            seeded_dest="/dest",
            bundle_source="/src",
            preserved_paths=["grafana", "prometheus"],
        )
        with patch(
            "defenseclaw.commands.cmd_setup_local_observability.refresh_local_observability_stack",
            return_value=refreshed,
        ):
            output = io.StringIO()
            with redirect_stdout(output):
                result = _refresh_and_maybe_restart_local_observability(
                    "/data", refresh_config=False, controller=controller
                )

        self.assertTrue(result.was_running)
        self.assertTrue(result.stopped)
        controller.down.assert_called_once_with()
        self.assertIn("Preserved local observability config", output.getvalue())

    def test_refresh_failure_restores_previously_running_stack(self) -> None:
        from defenseclaw.bundle_refresh import RefreshResult
        from defenseclaw.commands.cmd_setup_local_observability import (
            _refresh_and_maybe_restart_local_observability,
        )

        controller = MagicMock()
        controller.is_running.return_value = True
        failed = RefreshResult(
            bundle_kind="observability-stack",
            seeded_dest="/dest",
            bundle_source="/src",
            errors=["copy failed"],
        )
        with patch(
            "defenseclaw.commands.cmd_setup_local_observability.refresh_local_observability_stack",
            return_value=failed,
        ):
            result = _refresh_and_maybe_restart_local_observability(
                "/data", refresh_config=False, controller=controller
            )

        self.assertEqual(result.errors, ["copy failed"])
        controller.down.assert_called_once_with()
        controller.up.assert_called_once_with(timeout=180, wait=False)


if __name__ == "__main__":
    unittest.main()
