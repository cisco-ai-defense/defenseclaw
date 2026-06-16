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

"""E4i: ``skill list --json`` and ``skill info`` emit per-severity counts."""

import json
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw.commands.cmd_skill import (
    _build_scan_map,
    _severity_counts_from_raw,
    skill,
)
from defenseclaw.models import Finding, ScanResult

from tests.helpers import cleanup_app, make_app_context


def _result(target: str) -> ScanResult:
    return ScanResult(
        scanner="skill-scanner",
        target=target,
        timestamp=datetime.now(timezone.utc),
        findings=[
            Finding(id="1", severity="CRITICAL", title="c"),
            Finding(id="2", severity="HIGH", title="h1"),
            Finding(id="3", severity="HIGH", title="h2"),
            Finding(id="4", severity="LOW", title="l"),
        ],
        duration=timedelta(milliseconds=10),
    )


class SeverityCountsPureTests(unittest.TestCase):
    def test_buckets_all_present(self):
        counts = _severity_counts_from_raw(_result("x").to_json())
        self.assertEqual(counts["critical"], 1)
        self.assertEqual(counts["high"], 2)
        self.assertEqual(counts["medium"], 0)
        self.assertEqual(counts["low"], 1)
        self.assertEqual(counts["info"], 0)
        self.assertEqual(set(counts), {"critical", "high", "medium", "low", "info"})

    def test_blank_raw_is_all_zero(self):
        counts = _severity_counts_from_raw("")
        self.assertEqual(sum(counts.values()), 0)

    def test_malformed_raw_is_all_zero(self):
        counts = _severity_counts_from_raw("{not json")
        self.assertEqual(sum(counts.values()), 0)


class SeverityCountsInScanMapTests(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()
        self.app.logger.log_scan(_result("myskill"))

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def test_scan_map_carries_severity_counts(self):
        scan_map = _build_scan_map(self.app.store)
        self.assertIn("myskill", scan_map)
        self.assertEqual(scan_map["myskill"]["severity_counts"]["high"], 2)

    def test_skill_info_json_emits_severity_counts(self):
        result = self.runner.invoke(
            skill, ["info", "myskill", "--json"], obj=self.app, catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        data = json.loads(result.output.strip())
        self.assertIn("scan", data)
        self.assertEqual(data["scan"]["severity_counts"]["critical"], 1)


if __name__ == "__main__":
    unittest.main()
