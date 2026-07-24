# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Scanner executable resolution for installed CLI virtual environments."""

from __future__ import annotations

import json
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import call, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw.commands.cmd_doctor import _check_scanners, _DoctorResult
from defenseclaw.commands.cmd_status import status as status_cmd
from defenseclaw.scanner_binary import resolve_scanner_binary

from tests.helpers import cleanup_app, make_app_context


class ScannerBinaryResolverTests(unittest.TestCase):
    @patch("defenseclaw.scanner_binary.shutil.which")
    @patch("defenseclaw.scanner_binary.sysconfig.get_path", return_value=r"C:\managed\.venv\Scripts")
    def test_managed_scripts_directory_precedes_path(self, _get_path, mock_which):
        managed = r"C:\managed\.venv\Scripts\skill-scanner.EXE"
        mock_which.return_value = managed

        self.assertEqual(resolve_scanner_binary("skill-scanner"), managed)
        self.assertEqual(
            mock_which.call_args_list,
            [call("skill-scanner", path=r"C:\managed\.venv\Scripts")],
        )

    @patch("defenseclaw.scanner_binary.shutil.which")
    @patch("defenseclaw.scanner_binary.sysconfig.get_path", return_value="/managed/.venv/bin")
    def test_path_fallback_is_preserved_on_unix(self, _get_path, mock_which):
        mock_which.side_effect = [None, "/usr/local/bin/mcp-scanner"]

        self.assertEqual(resolve_scanner_binary("mcp-scanner"), "/usr/local/bin/mcp-scanner")
        self.assertEqual(
            mock_which.call_args_list,
            [call("mcp-scanner", path="/managed/.venv/bin"), call("mcp-scanner")],
        )

    @patch("defenseclaw.scanner_binary.shutil.which")
    def test_blank_binary_is_not_searched(self, mock_which):
        self.assertIsNone(resolve_scanner_binary("  "))
        mock_which.assert_not_called()


class ScannerCommandIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    @staticmethod
    def _resolve(binary: str) -> str | None:
        if binary == "skill-scanner":
            return r"C:\managed\.venv\Scripts\skill-scanner.exe"
        return None

    @patch("defenseclaw.commands.cmd_status._fetch_runtime_bound_health", return_value=None)
    @patch("defenseclaw.commands.cmd_status.resolve_scanner_binary", side_effect=_resolve)
    def test_status_human_and_json_share_resolution(self, _resolve_binary, _bound_health):
        runner = CliRunner()

        human = runner.invoke(status_cmd, [], obj=self.app, catch_exceptions=False)
        machine = runner.invoke(status_cmd, ["--json"], obj=self.app, catch_exceptions=False)

        self.assertEqual(human.exit_code, 0, msg=human.output)
        self.assertEqual(machine.exit_code, 0, msg=machine.output)
        self.assertIn("skill-scanner   installed", human.output)
        self.assertIn("mcp-scanner     not found", human.output)
        self.assertEqual(
            json.loads(machine.output)["scanners"],
            {
                "skill-scanner": "installed",
                "mcp-scanner": "not_found",
                "codeguard": "built-in",
            },
        )

    @patch("defenseclaw.commands.cmd_doctor.resolve_scanner_binary", side_effect=_resolve)
    def test_doctor_reports_resolved_managed_path(self, _resolve_binary):
        cfg = SimpleNamespace(
            scanners=SimpleNamespace(
                skill_scanner=SimpleNamespace(binary="skill-scanner"),
                mcp_scanner=SimpleNamespace(binary="mcp-scanner"),
            )
        )
        result = _DoctorResult()

        _check_scanners(cfg, result)

        self.assertEqual(result.checks[0]["status"], "pass")
        self.assertEqual(
            result.checks[0]["detail"],
            r"C:\managed\.venv\Scripts\skill-scanner.exe",
        )
        self.assertEqual(result.checks[1]["status"], "fail")
        self.assertIn("managed environment or on PATH", result.checks[1]["detail"])


if __name__ == "__main__":
    unittest.main()
