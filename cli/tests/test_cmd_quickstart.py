# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the quickstart compatibility wrapper."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw.commands.cmd_quickstart import quickstart_cmd


class QuickstartProfileDefaultsTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-quickstart-")
        self.home_dir = os.path.join(self.tmp_dir, "home")
        self.empty_path = os.path.join(self.tmp_dir, "empty-bin")
        os.makedirs(self.home_dir, exist_ok=True)
        os.makedirs(self.empty_path, exist_ok=True)
        self.runner = CliRunner()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _invoke(self, args):
        return self.runner.invoke(
            quickstart_cmd,
            args,
            env={
                "DEFENSECLAW_HOME": self.tmp_dir,
                "HOME": self.home_dir,
                "PATH": self.empty_path,
            },
        )

    def test_codex_defaults_to_observe_profile(self):
        result = self._invoke([
            "--connector",
            "codex",
            "--skip-gateway",
            "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        summary = json.loads(result.output)
        self.assertEqual(summary["connector"], "codex")
        self.assertEqual(summary["profile"], "observe")

    def test_openclaw_defaults_to_observe_profile(self):
        result = self._invoke([
            "--connector",
            "openclaw",
            "--skip-gateway",
            "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        summary = json.loads(result.output)
        self.assertEqual(summary["connector"], "openclaw")
        self.assertEqual(summary["profile"], "observe")

    def test_explicit_mode_overrides_connector_default(self):
        result = self._invoke([
            "--connector",
            "codex",
            "--mode",
            "observe",
            "--skip-gateway",
            "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        summary = json.loads(result.output)
        self.assertEqual(summary["profile"], "observe")

    def test_help_lists_fail_mode_flag(self):
        # Quickstart is the headless path most likely to be wired
        # into installers and CI. If --fail-mode disappears from
        # help, scripts that opt into fail-closed silently regress.
        result = self.runner.invoke(quickstart_cmd, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("--fail-mode", result.output)

    def test_fail_mode_closed_persists_to_config(self):
        result = self._invoke([
            "--connector",
            "codex",
            "--skip-gateway",
            "--fail-mode",
            "closed",
            "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        import yaml
        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        self.assertEqual(cfg["guardrail"]["hook_fail_mode"], "closed")

    def test_omitting_fail_mode_resolves_to_open(self):
        result = self._invoke([
            "--connector",
            "codex",
            "--skip-gateway",
            "--json-summary",
        ])
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        import yaml
        with open(os.path.join(self.tmp_dir, "config.yaml"), encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh)
        from defenseclaw.config import _normalize_hook_fail_mode
        raw = cfg["guardrail"].get("hook_fail_mode", "open")
        self.assertEqual(_normalize_hook_fail_mode(raw), "open")


if __name__ == "__main__":
    unittest.main()
