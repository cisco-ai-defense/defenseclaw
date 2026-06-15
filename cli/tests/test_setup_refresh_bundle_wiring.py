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

import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from click.testing import CliRunner
from defenseclaw import config
from defenseclaw.context import AppContext


def _make_app() -> tuple[AppContext, str]:
    """Build a Click context backed by a throwaway data dir."""
    tmp_dir = tempfile.mkdtemp(prefix="dclaw-refresh-wiring-")
    cfg = config.Config(data_dir=tmp_dir)
    app = AppContext()
    app.cfg = cfg
    return app, tmp_dir


class TestSetupSplunkRefreshWiring(unittest.TestCase):
    def setUp(self) -> None:
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
            stdout=json.dumps({
                "splunk_web_url": "http://127.0.0.1:8000",
                "hec_url": "http://127.0.0.1:8088/services/collector/event",
                "hec_token": "bootstrap-token",
                "license_group": "Free",
                "web_login_required": False,
                "index": "defenseclaw_local",
                "source": "defenseclaw",
                "sourcetype": "defenseclaw:json",
            }),
            stderr="",
        )

        result = self.runner.invoke(
            setup,
            ["splunk", "--logs", "--non-interactive", "--accept-splunk-license"],
            obj=self.app,
            catch_exceptions=False,
        )

        self.assertEqual(result.exit_code, 0, result.output)
        mock_refresh.assert_called_once_with(self.tmp_dir)

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
            stdout=json.dumps({
                "splunk_web_url": "http://127.0.0.1:8000",
                "hec_url": "http://127.0.0.1:8088/services/collector/event",
                "hec_token": "bootstrap-token",
                "license_group": "Free",
                "web_login_required": False,
                "index": "defenseclaw_local",
                "source": "defenseclaw",
                "sourcetype": "defenseclaw:json",
            }),
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

        result = _refresh_and_maybe_restart_splunk_bridge("/data")

        self.assertTrue(result.was_running)
        self.assertTrue(result.stopped)
        # The down call must precede the refresh call. Pull the
        # subprocess args to confirm we asked the bridge for `down`.
        self.assertTrue(any(
            call.args[0] == ["/fake/bin/splunk-claw-bridge", "down"]
            for call in mock_run.call_args_list
        ))
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


class TestSetupLocalObservabilityRefreshWiring(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = CliRunner()
        self.app, self.tmp_dir = _make_app()

    def tearDown(self) -> None:
        import shutil

        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @patch(
        "defenseclaw.commands.cmd_setup_local_observability"
        "._refresh_and_maybe_restart_local_observability",
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
        "defenseclaw.commands.cmd_setup_local_observability"
        "._apply_local_otlp_audit_sink",
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
        # The wiring should pass refresh_config=False unless the user
        # opts in.
        self.assertFalse(mock_refresh.call_args.kwargs["refresh_config"])

    @patch(
        "defenseclaw.commands.cmd_setup_local_observability"
        "._refresh_and_maybe_restart_local_observability",
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
        "defenseclaw.commands.cmd_setup_local_observability"
        "._apply_local_otlp_audit_sink",
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
        "defenseclaw.commands.cmd_setup_local_observability"
        "._refresh_and_maybe_restart_local_observability",
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
        "defenseclaw.commands.cmd_setup_local_observability"
        "._apply_local_otlp_audit_sink",
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


if __name__ == "__main__":
    unittest.main()
