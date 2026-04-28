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

"""S6.3 — UX contract tests for ``defenseclaw skill scan``.

The existing ``test_cmd_skill.py`` exercises governance commands and
the per-severity-breakdown output of the *detailed* skill block. This
file pins the **shared** ``_scan_ui`` preamble + per-target glyph +
summary that S6.3 wired into both the single-target and ``--all``
paths.

Coverage:

* Single-target preamble: count, label, connector, default categories
* Single-target verdict: ``[ok]`` / ``[BLOCKED]`` glyph + finding
  count + max severity detail
* Single-target summary: clean / blocked / errored counts + duration
* ``--all`` preamble: target count and source dirs
* ``--all`` summary: aggregated clean / blocked / errored / total
* ``--json`` mode silences all human helpers and preserves the legacy
  ``ScanResult.to_json()`` contract
* Error path inside ``--all``: scanner exception bumps the
  ``errored`` count without aborting the whole batch
"""

from __future__ import annotations

import json
import os
import sys
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner

from defenseclaw.commands.cmd_skill import skill
from defenseclaw.models import Finding, ScanResult
from tests.helpers import cleanup_app, make_app_context


class _SkillScanUXBase(unittest.TestCase):
    def setUp(self) -> None:
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self._orig_columns = os.environ.get("COLUMNS")
        os.environ["COLUMNS"] = "200"

        self.skill_dir = os.path.join(self.tmp_dir, "demo-skill")
        os.makedirs(self.skill_dir)
        with open(os.path.join(self.skill_dir, "SKILL.md"), "w") as f:
            f.write("# demo\n")

        self.runner = CliRunner()

    def tearDown(self) -> None:
        cleanup_app(self.app, self.db_path, self.tmp_dir)
        if self._orig_columns is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = self._orig_columns

    def invoke(self, args: list[str]):
        return self.runner.invoke(skill, args, obj=self.app, catch_exceptions=False)

    @staticmethod
    def _clean_result(target: str) -> ScanResult:
        return ScanResult(
            scanner="skill-scanner",
            target=target,
            timestamp=datetime.now(timezone.utc),
            findings=[],
            duration=timedelta(milliseconds=80),
        )

    @staticmethod
    def _blocked_result(target: str) -> ScanResult:
        return ScanResult(
            scanner="skill-scanner",
            target=target,
            timestamp=datetime.now(timezone.utc),
            findings=[
                Finding(
                    id=str(uuid.uuid4()),
                    severity="HIGH",
                    title="Suspicious shell invocation",
                    scanner="skill-scanner",
                ),
            ],
            duration=timedelta(milliseconds=200),
        )


class TestSingleTargetUX(_SkillScanUXBase):
    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_preamble_lists_categories_and_source(self, mock_cls, _mock_info) -> None:
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = self._clean_result(self.skill_dir)
        mock_cls.return_value = mock_scanner

        result = self.invoke(["scan", "demo-skill", "--path", self.skill_dir])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Scanning 1 skill on ", result.output)
        # Default skill categories
        self.assertIn("prompt injection in SKILL.md", result.output)
        self.assertIn("malicious shell / Python invocations", result.output)
        # Source dir surfaced under "Source:"
        self.assertIn("Source:", result.output)
        self.assertIn(self.skill_dir, result.output)

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_clean_glyph_and_summary(self, mock_cls, _mock_info) -> None:
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = self._clean_result(self.skill_dir)
        mock_cls.return_value = mock_scanner

        result = self.invoke(["scan", "demo-skill", "--path", self.skill_dir])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("[ok] demo-skill", result.output)
        self.assertIn("Summary: 1 skill scanned", result.output)
        self.assertIn("clean=1", result.output)
        self.assertIn("blocked=0", result.output)
        self.assertIn("in 80ms", result.output)

    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_blocked_glyph_with_severity_detail(self, mock_cls, _mock_info) -> None:
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = self._blocked_result(self.skill_dir)
        mock_cls.return_value = mock_scanner

        result = self.invoke(["scan", "demo-skill", "--path", self.skill_dir])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("[BLOCKED] demo-skill", result.output)
        self.assertIn("max severity: HIGH", result.output)
        self.assertIn("(1 finding)", result.output)
        self.assertIn("Summary: 1 skill scanned", result.output)
        self.assertIn("clean=0", result.output)
        self.assertIn("blocked=1", result.output)


class TestSingleTargetJsonMode(_SkillScanUXBase):
    @patch("defenseclaw.commands.cmd_skill._get_openclaw_skill_info", return_value=None)
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_json_mode_silences_human_helpers(self, mock_cls, _mock_info) -> None:
        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = self._clean_result(self.skill_dir)
        mock_cls.return_value = mock_scanner

        result = self.invoke(
            ["scan", "demo-skill", "--path", self.skill_dir, "--json"],
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn("Scanning 1 skill", result.output)
        self.assertNotIn("Summary:", result.output)
        self.assertNotIn("[ok]", result.output)
        # Legacy contract: ScanResult.to_json() shape
        payload = json.loads(result.output.strip())
        self.assertIn("scanner", payload)
        self.assertIn("target", payload)
        self.assertIn("findings", payload)


class TestScanAllUX(_SkillScanUXBase):
    """``--all`` preamble + per-target glyph + summary."""

    def _make_skills_dir(self, names: list[str]) -> str:
        root = os.path.join(self.tmp_dir, "skills-root")
        os.makedirs(root, exist_ok=True)
        for n in names:
            d = os.path.join(root, n)
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "SKILL.md"), "w") as f:
                f.write(f"# {n}\n")
        return root

    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full", return_value=None)
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_scan_all_preamble_and_summary(self, mock_cls, _mock_list) -> None:
        # No openclaw CLI listing → falls through to skill_dirs walk.
        root = self._make_skills_dir(["alpha", "beta", "gamma"])
        # Patch active connector so skill_dirs() points at our temp root.
        self.app.cfg.skill_dirs = lambda: [root]

        # Two clean, one blocked.
        responses = {
            os.path.join(root, "alpha"): self._clean_result(os.path.join(root, "alpha")),
            os.path.join(root, "beta"): self._blocked_result(os.path.join(root, "beta")),
            os.path.join(root, "gamma"): self._clean_result(os.path.join(root, "gamma")),
        }
        mock_scanner = MagicMock()
        mock_scanner.scan.side_effect = lambda p: responses[p]
        mock_cls.return_value = mock_scanner

        result = self.invoke(["scan", "--all"])
        self.assertEqual(result.exit_code, 0, result.output)
        # Preamble.
        self.assertIn("Scanning 3 skills on ", result.output)
        # Per-target glyphs.
        self.assertIn("[ok] alpha", result.output)
        self.assertIn("[BLOCKED] beta", result.output)
        self.assertIn("[ok] gamma", result.output)
        # Summary.
        self.assertIn("Summary: 3 skills scanned", result.output)
        self.assertIn("clean=2", result.output)
        self.assertIn("blocked=1", result.output)

    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full", return_value=None)
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_scan_all_handles_scanner_exception(self, mock_cls, _mock_list) -> None:
        """A scanner exception bumps the errored count without aborting the batch."""
        root = self._make_skills_dir(["alpha", "beta"])
        self.app.cfg.skill_dirs = lambda: [root]

        def scan_impl(p):
            if p.endswith("/alpha"):
                return self._clean_result(p)
            raise RuntimeError("boom")

        mock_scanner = MagicMock()
        mock_scanner.scan.side_effect = scan_impl
        mock_cls.return_value = mock_scanner

        result = self.invoke(["scan", "--all"])
        self.assertEqual(result.exit_code, 0, result.output)
        # alpha succeeded.
        self.assertIn("[ok] alpha", result.output)
        # beta errored — appears in the per-target line.
        self.assertIn("[ERROR] beta", result.output)
        self.assertIn("boom", result.output)
        # Summary contains "errored=1" only when there's at least one error.
        self.assertIn("errored=1", result.output)

    @patch("defenseclaw.commands.cmd_skill._list_openclaw_skills_full", return_value=None)
    @patch("defenseclaw.scanner.skill.SkillScannerWrapper")
    def test_scan_all_no_skills_found_path(self, mock_cls, _mock_list) -> None:
        """Empty skill_dirs() prints the expected guidance without crashing."""
        empty = os.path.join(self.tmp_dir, "empty-skills")
        os.makedirs(empty, exist_ok=True)
        self.app.cfg.skill_dirs = lambda: [empty]
        mock_cls.return_value = MagicMock()

        result = self.invoke(["scan", "--all"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("No skills found", result.output)
        # The shared preamble must not run when there are no targets.
        self.assertNotIn("Scanning 0 skills", result.output)


if __name__ == "__main__":
    unittest.main()
