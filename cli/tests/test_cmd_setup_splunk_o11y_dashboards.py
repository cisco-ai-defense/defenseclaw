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

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner

from defenseclaw.commands.cmd_setup_splunk_o11y_dashboards import (
    _api_url_from_ingest_endpoint,
    splunk_o11y_dashboards,
)


class SplunkO11yDashboardCommandTests(unittest.TestCase):
    def test_apply_runs_terraform_with_secret_in_env_not_args(self) -> None:
        calls = []

        def fake_run(cmd, cwd, env, text, capture_output, timeout):
            calls.append(
                {
                    "cmd": cmd,
                    "cwd": cwd,
                    "env": env,
                    "text": text,
                    "capture_output": capture_output,
                    "timeout": timeout,
                }
            )
            if cmd[1] == "output":
                return subprocess.CompletedProcess(
                    cmd,
                    0,
                    stdout='{"executive":"https://app.signalfx.com/#/dashboard/abc"}',
                )
            return subprocess.CompletedProcess(cmd, 0, stdout="")

        with tempfile.TemporaryDirectory() as td, patch(
            "defenseclaw.commands.cmd_setup_splunk_o11y_dashboards.subprocess.run",
            side_effect=fake_run,
        ):
            tmp_path = Path(td)
            work_dir = tmp_path / "tf-work"
            state_path = tmp_path / "state" / "terraform.tfstate"

            result = CliRunner().invoke(
                splunk_o11y_dashboards,
                [
                    "apply",
                    "--api-url",
                    "https://api.realm.signalfx.com",
                    "--auth-token",
                    "secret-token",
                    "--name-prefix",
                    "Smoke",
                    "--work-dir",
                    str(work_dir),
                    "--state",
                    str(state_path),
                    "--skip-init",
                    "--skip-validate",
                    "--yes",
                ],
            )

            self.assertEqual(result.exit_code, 0, result.output)
            self.assertTrue((work_dir / "main.tf").is_file())

        self.assertEqual([call["cmd"][1] for call in calls], ["plan", "apply", "output"])
        self.assertTrue(all("secret-token" not in " ".join(call["cmd"]) for call in calls))
        self.assertEqual(calls[0]["env"]["TF_VAR_signalfx_auth_token"], "secret-token")
        self.assertEqual(calls[0]["env"]["TF_VAR_signalfx_api_url"], "https://api.realm.signalfx.com")
        self.assertEqual(calls[0]["env"]["TF_VAR_name_prefix"], "Smoke")
        self.assertEqual(calls[0]["env"]["TF_VAR_create_detectors"], "false")
        self.assertEqual(calls[0]["env"]["TF_VAR_detectors_disabled"], "true")
        self.assertIn(f"-state={state_path}", calls[0]["cmd"])
        self.assertIn(f"-state={state_path}", calls[2]["cmd"])
        self.assertIn("executive: https://app.signalfx.com/#/dashboard/abc", result.output)

    def test_plan_initializes_with_optional_plugin_dir(self) -> None:
        calls = []

        def fake_run(cmd, cwd, env, text, capture_output, timeout):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, stdout="")

        with tempfile.TemporaryDirectory() as td, patch(
            "defenseclaw.commands.cmd_setup_splunk_o11y_dashboards.subprocess.run",
            side_effect=fake_run,
        ):
            tmp_path = Path(td)
            plugin_dir = tmp_path / "plugins"
            plugin_dir.mkdir()

            result = CliRunner().invoke(
                splunk_o11y_dashboards,
                [
                    "plan",
                    "--api-url",
                    "https://api.realm.signalfx.com",
                    "--auth-token",
                    "secret-token",
                    "--work-dir",
                    str(tmp_path / "tf-work"),
                    "--state",
                    str(tmp_path / "terraform.tfstate"),
                    "--plugin-dir",
                    str(plugin_dir),
                ],
            )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(calls[0][1:], ["init", "-input=false", f"-plugin-dir={plugin_dir}"])
        self.assertEqual(calls[1][1:], ["validate"])
        self.assertEqual(calls[2][1], "plan")

    def test_missing_token_reports_actionable_error(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {}, clear=True):
            result = CliRunner().invoke(
                splunk_o11y_dashboards,
                [
                    "plan",
                    "--api-url",
                    "https://api.realm.signalfx.com",
                    "--work-dir",
                    str(Path(td) / "tf-work"),
                ],
            )

        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Splunk O11y token not found. Pass --auth-token.", result.output)

    def test_api_url_derives_from_ingest_realm(self) -> None:
        self.assertEqual(
            _api_url_from_ingest_endpoint("https://ingest.realm.observability.splunkcloud.com/v1/metrics"),
            "https://api.realm.signalfx.com",
        )
        self.assertEqual(
            _api_url_from_ingest_endpoint("ingest.realm2.signalfx.com:443"),
            "https://api.realm2.signalfx.com",
        )
        self.assertEqual(
            _api_url_from_ingest_endpoint("https://api.realm.signalfx.com"),
            "https://api.realm.signalfx.com",
        )


if __name__ == "__main__":
    unittest.main()
