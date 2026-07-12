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

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw.commands.cmd_setup_splunk_o11y_dashboards import (
    _api_url_from_ingest_endpoint,
    _resolve_api_url,
    splunk_o11y_dashboards,
)


class SplunkO11yDashboardCommandTests(unittest.TestCase):
    def test_api_url_falls_back_to_canonical_v8_destination(self) -> None:
        app = SimpleNamespace(cfg=SimpleNamespace(data_dir="/tmp/defenseclaw"))
        status = SimpleNamespace(
            destinations=(
                SimpleNamespace(
                    kind="otlp",
                    endpoint="https://ingest.us1.signalfx.com/v2/datapoint",
                ),
            ),
        )
        with patch(
            "defenseclaw.commands.cmd_setup_observability._require_v8_operator_status",
            return_value=status,
        ):
            self.assertEqual(_resolve_api_url(None, app), "https://api.us1.signalfx.com")

    def test_apply_runs_terraform_with_secret_in_env_not_args(self) -> None:
        calls = []
        console_payload = {"single": {}, "time": {}, "table": {}, "layouts": {}, "detectors": {}}

        class FakeResponse:
            def __init__(self, payload):
                self._payload = payload
                self.status_code = 200

            def raise_for_status(self):
                return None

            def json(self):
                return self._payload

        def fake_get(url, headers=None, params=None, timeout=None):
            return FakeResponse({"results": []})

        def fake_run(cmd, cwd, env, text, capture_output, timeout, input=None):
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
            if cmd[1] == "console":
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(json.dumps(console_payload)))
            if cmd[1] == "state":
                return subprocess.CompletedProcess(cmd, 0, stdout="")
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
        ), patch(
            "defenseclaw.commands.cmd_setup_splunk_o11y_dashboards.requests.get",
            side_effect=fake_get,
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
                    "--o11y-api-token",
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

        self.assertEqual([call["cmd"][1] for call in calls], ["console", "state", "plan", "apply", "output"])
        self.assertTrue(all("secret-token" not in " ".join(call["cmd"]) for call in calls))
        self.assertEqual(calls[2]["env"]["TF_VAR_signalfx_auth_token"], "secret-token")
        self.assertEqual(calls[2]["env"]["TF_VAR_signalfx_api_url"], "https://api.realm.signalfx.com")
        self.assertEqual(calls[2]["env"]["TF_VAR_name_prefix"], "Smoke")
        self.assertEqual(calls[2]["env"]["TF_VAR_create_detectors"], "false")
        self.assertEqual(calls[2]["env"]["TF_VAR_detectors_disabled"], "true")
        self.assertIn(f"-state={state_path}", calls[1]["cmd"])
        self.assertIn(f"-state={state_path}", calls[2]["cmd"])
        self.assertIn("executive: https://app.signalfx.com/#/dashboard/abc", result.output)

    def test_apply_adopts_existing_dashboards_before_apply(self) -> None:
        calls = []

        console_payload = {
            "single": {
                "executive_verdicts_31d": {
                    "name": "Verdicts",
                    "description": "All DefenseClaw gateway verdicts in the selected time range.",
                }
            },
            "time": {},
            "table": {},
            "layouts": {
                "executive": [
                    {"type": "single", "key": "executive_verdicts_31d", "row": 0, "column": 0, "width": 2, "height": 1}
                ],
                "guardrail_inspection": [],
                "connector_ingest": [],
                "security_policy": [],
                "token_economics": [],
                "runtime_reliability": [],
                "scanners_findings": [],
            },
            "detectors": {},
        }

        class FakeResponse:
            def __init__(self, payload):
                self._payload = payload
                self.status_code = 200

            def raise_for_status(self):
                return None

            def json(self):
                return self._payload

        def fake_get(url, headers=None, params=None, timeout=None):
            if url.endswith("/v2/dashboardgroup"):
                return FakeResponse({"results": [{"id": "dg-1", "name": "Smoke DefenseClaw O11y"}]})
            if url.endswith("/v2/dashboard"):
                return FakeResponse(
                    {
                        "results": [
                            {
                                "id": "db-1",
                                "name": "Executive Agent Watch (Smoke)",
                                "dashboardGroupId": "dg-1",
                            }
                        ]
                    }
                )
            if url.endswith("/v2/dashboard/db-1"):
                return FakeResponse(
                    {
                        "charts": [
                            {
                                "id": "chart-1",
                                "name": "Verdicts",
                                "description": "All DefenseClaw gateway verdicts in the selected time range.",
                            }
                        ]
                    }
                )
            raise AssertionError(f"unexpected API url: {url}")

        def fake_run(*args, **kwargs):
            cmd = args[0]
            calls.append({"cmd": cmd, "kwargs": kwargs})
            if cmd[1] == "console":
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(json.dumps(console_payload)))
            if cmd[1] == "state":
                return subprocess.CompletedProcess(cmd, 0, stdout="")
            if cmd[1] == "import":
                return subprocess.CompletedProcess(cmd, 0, stdout="")
            if cmd[1] in {"plan", "apply", "output", "validate", "init"}:
                if cmd[1] == "output":
                    return subprocess.CompletedProcess(cmd, 0, stdout='{"executive":"https://app.signalfx.com/#/dashboard/abc"}')
                return subprocess.CompletedProcess(cmd, 0, stdout="")
            raise AssertionError(f"unexpected terraform cmd: {cmd}")

        with tempfile.TemporaryDirectory() as td, patch(
            "defenseclaw.commands.cmd_setup_splunk_o11y_dashboards.subprocess.run",
            side_effect=fake_run,
        ), patch(
            "defenseclaw.commands.cmd_setup_splunk_o11y_dashboards.requests.get",
            side_effect=fake_get,
        ):
            tmp_path = Path(td)
            result = CliRunner().invoke(
                splunk_o11y_dashboards,
                [
                    "apply",
                    "--api-url",
                    "https://api.realm.signalfx.com",
                    "--o11y-api-token",
                    "secret-token",
                    "--name-prefix",
                    "Smoke",
                    "--work-dir",
                    str(tmp_path / "tf-work"),
                    "--state",
                    str(tmp_path / "state" / "terraform.tfstate"),
                    "--skip-init",
                    "--skip-validate",
                    "--yes",
                ],
            )

        self.assertEqual(result.exit_code, 0, result.output)
        import_cmds = [call["cmd"] for call in calls if call["cmd"][1] == "import"]
        self.assertEqual(
            import_cmds,
            [
                [
                    "terraform",
                    "import",
                    "-input=false",
                    f"-state={tmp_path / 'state' / 'terraform.tfstate'}",
                    "signalfx_dashboard_group.defenseclaw_o11y",
                    "dg-1",
                ],
                [
                    "terraform",
                    "import",
                    "-input=false",
                    f"-state={tmp_path / 'state' / 'terraform.tfstate'}",
                    "signalfx_dashboard.executive",
                    "db-1",
                ],
            ],
        )

    def test_apply_adopts_best_matching_dashboard_group(self) -> None:
        calls = []

        console_payload = {
            "single": {},
            "time": {},
            "table": {},
            "layouts": {
                "executive": [],
                "guardrail_inspection": [],
                "connector_ingest": [],
                "security_policy": [],
                "token_economics": [],
                "runtime_reliability": [],
                "scanners_findings": [],
            },
            "detectors": {},
        }

        class FakeResponse:
            def __init__(self, payload):
                self._payload = payload
                self.status_code = 200

            def raise_for_status(self):
                return None

            def json(self):
                return self._payload

        def fake_get(url, headers=None, params=None, timeout=None):
            if url.endswith("/v2/dashboardgroup"):
                return FakeResponse(
                    {
                        "results": [
                            {"id": "dg-stale", "name": "Smoke DefenseClaw O11y"},
                            {"id": "dg-best", "name": "Smoke DefenseClaw O11y"},
                        ]
                    }
                )
            if url.endswith("/v2/dashboard"):
                return FakeResponse(
                    {
                        "results": [
                            {
                                "id": "db-stale",
                                "name": "Executive Agent Watch (Smoke)",
                                "dashboardGroupId": "dg-stale",
                            },
                            {
                                "id": "db-best",
                                "name": "Executive Agent Watch (Smoke)",
                                "dashboardGroupId": "dg-best",
                            },
                        ]
                    }
                )
            if url.endswith("/v2/dashboard/db-stale"):
                return FakeResponse({"charts": []})
            if url.endswith("/v2/dashboard/db-best"):
                return FakeResponse({"charts": []})
            raise AssertionError(f"unexpected API url: {url}")

        def fake_run(*args, **kwargs):
            cmd = args[0]
            calls.append({"cmd": cmd, "kwargs": kwargs})
            if cmd[1] == "console":
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(json.dumps(console_payload)))
            if cmd[1] == "state":
                return subprocess.CompletedProcess(cmd, 0, stdout="")
            if cmd[1] == "import":
                return subprocess.CompletedProcess(cmd, 0, stdout="")
            if cmd[1] in {"plan", "apply", "output", "validate", "init"}:
                if cmd[1] == "output":
                    return subprocess.CompletedProcess(cmd, 0, stdout='{"executive":"https://app.signalfx.com/#/dashboard/abc"}')
                return subprocess.CompletedProcess(cmd, 0, stdout="")
            raise AssertionError(f"unexpected terraform cmd: {cmd}")

        with tempfile.TemporaryDirectory() as td, patch(
            "defenseclaw.commands.cmd_setup_splunk_o11y_dashboards.subprocess.run",
            side_effect=fake_run,
        ), patch(
            "defenseclaw.commands.cmd_setup_splunk_o11y_dashboards.requests.get",
            side_effect=fake_get,
        ):
            tmp_path = Path(td)
            result = CliRunner().invoke(
                splunk_o11y_dashboards,
                [
                    "apply",
                    "--api-url",
                    "https://api.realm.signalfx.com",
                    "--o11y-api-token",
                    "secret-token",
                    "--name-prefix",
                    "Smoke",
                    "--work-dir",
                    str(tmp_path / "tf-work"),
                    "--state",
                    str(tmp_path / "state" / "terraform.tfstate"),
                    "--skip-init",
                    "--skip-validate",
                    "--yes",
                ],
            )

        self.assertEqual(result.exit_code, 0, result.output)
        import_cmds = [call["cmd"] for call in calls if call["cmd"][1] == "import"]
        self.assertIn(
            [
                "terraform",
                "import",
                "-input=false",
                f"-state={tmp_path / 'state' / 'terraform.tfstate'}",
                "signalfx_dashboard_group.defenseclaw_o11y",
                "dg-best",
            ],
            import_cmds,
        )

    def test_plan_initializes_with_optional_plugin_dir(self) -> None:
        calls = []
        console_payload = {"single": {}, "time": {}, "table": {}, "layouts": {}, "detectors": {}}

        class FakeResponse:
            def __init__(self, payload):
                self._payload = payload
                self.status_code = 200

            def raise_for_status(self):
                return None

            def json(self):
                return self._payload

        def fake_get(url, headers=None, params=None, timeout=None):
            return FakeResponse({"results": []})

        def fake_run(cmd, cwd, env, text, capture_output, timeout, input=None):
            calls.append(cmd)
            if cmd[1] == "console":
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(json.dumps(console_payload)))
            if cmd[1] == "state":
                return subprocess.CompletedProcess(cmd, 0, stdout="")
            return subprocess.CompletedProcess(cmd, 0, stdout="")

        with tempfile.TemporaryDirectory() as td, patch(
            "defenseclaw.commands.cmd_setup_splunk_o11y_dashboards.subprocess.run",
            side_effect=fake_run,
        ), patch(
            "defenseclaw.commands.cmd_setup_splunk_o11y_dashboards.requests.get",
            side_effect=fake_get,
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
                    "--o11y-api-token",
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
        self.assertEqual(calls[2][1], "console")
        self.assertEqual(calls[3][1], "state")
        self.assertEqual(calls[4][1], "plan")

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
        self.assertIn("Splunk O11y token not found.", result.output)
        self.assertIn("SFX_AUTH_TOKEN", result.output)

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
