# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``defenseclaw version``.

The command shells out to the gateway binary and reads the plugin's
package.json. Both side effects are mocked here so the tests can run
on a machine with nothing installed.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from unittest.mock import patch

from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw import __version__
from defenseclaw.commands import cmd_version


class ParseGatewayVersionTests(unittest.TestCase):
    """Cobra emits ``<name> version X.Y.Z (...)`` — parse that reliably."""

    def test_parse_standard_line(self):
        version, detail = cmd_version._parse_gateway_version(
            "defenseclaw-gateway version 0.2.0 (commit=abc, built=2025-01-01)"
        )
        self.assertEqual(version, "0.2.0")
        self.assertIn("commit=abc", detail)

    def test_parse_no_detail(self):
        version, detail = cmd_version._parse_gateway_version(
            "defenseclaw-gateway version 1.2.3"
        )
        self.assertEqual(version, "1.2.3")
        self.assertEqual(detail, "")

    def test_parse_unexpected_returns_raw(self):
        version, detail = cmd_version._parse_gateway_version("something weird")
        self.assertEqual(version, "")
        self.assertEqual(detail, "something weird")


class NormalizeTests(unittest.TestCase):
    def test_strips_v_prefix_and_prerelease(self):
        self.assertEqual(cmd_version._normalize("v0.2.0"),       (0, 2, 0))
        self.assertEqual(cmd_version._normalize("0.2.0-rc1"),    (0, 2, 0))
        self.assertEqual(cmd_version._normalize("0.2.0+build"),  (0, 2, 0))

    def test_non_semver_returns_none(self):
        self.assertIsNone(cmd_version._normalize(""))
        self.assertIsNone(cmd_version._normalize("(not installed)"))
        self.assertIsNone(cmd_version._normalize("dev"))
        self.assertIsNone(cmd_version._normalize("0.2"))  # incomplete


class ComputeDriftTests(unittest.TestCase):
    def _mk(self, **vs):
        return [
            cmd_version.Component(name=n, version=v, origin="x")
            for n, v in vs.items()
        ]

    def test_no_drift_when_all_match(self):
        components = self._mk(cli="0.2.0", gateway="0.2.0", plugin="0.2.0")
        self.assertEqual(cmd_version._compute_drift(components), [])

    def test_drift_detected_for_mismatched_minor(self):
        components = self._mk(cli="0.2.0", gateway="0.1.0", plugin="0.2.0")
        issues = cmd_version._compute_drift(components)
        self.assertTrue(any("gateway 0.1.0" in i for i in issues))

    def test_unparseable_components_skip_drift(self):
        components = self._mk(
            cli="0.2.0",
            gateway="(not installed)",
            plugin="0.2.0",
        )
        self.assertEqual(cmd_version._compute_drift(components), [])

    def test_patch_mismatch_triggers_drift(self):
        components = self._mk(cli="0.2.0", gateway="0.2.1", plugin="0.2.0")
        self.assertTrue(cmd_version._compute_drift(components))


class VersionCommandTests(unittest.TestCase):
    """Behaviour of the ``defenseclaw version`` click command."""

    def test_clean_install_exits_zero(self):
        runner = CliRunner()
        with patch("defenseclaw.commands.cmd_version._gateway_component") as gw, \
             patch("defenseclaw.commands.cmd_version._plugin_component") as pl:
            gw.return_value = cmd_version.Component(
                name="gateway", version=__version__, origin="/usr/bin",
            )
            pl.return_value = cmd_version.Component(
                name="plugin", version=__version__, origin="~/.openclaw",
            )
            result = runner.invoke(cmd_version.version_cmd, [])
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertIn("All components in sync", result.output)

    def test_drift_exits_nonzero(self):
        runner = CliRunner()
        with patch("defenseclaw.commands.cmd_version._gateway_component") as gw, \
             patch("defenseclaw.commands.cmd_version._plugin_component") as pl:
            gw.return_value = cmd_version.Component(
                name="gateway", version="0.1.0", origin="/usr/bin",
            )
            pl.return_value = cmd_version.Component(
                name="plugin", version=__version__, origin="~/.openclaw",
            )
            result = runner.invoke(cmd_version.version_cmd, [])
            self.assertEqual(result.exit_code, 1)
            self.assertIn("Drift detected", result.output)

    def test_no_drift_exit_flag_forces_success(self):
        runner = CliRunner()
        with patch("defenseclaw.commands.cmd_version._gateway_component") as gw, \
             patch("defenseclaw.commands.cmd_version._plugin_component") as pl:
            gw.return_value = cmd_version.Component(
                name="gateway", version="0.1.0", origin="/usr/bin",
            )
            pl.return_value = cmd_version.Component(
                name="plugin", version=__version__, origin="~/.openclaw",
            )
            result = runner.invoke(cmd_version.version_cmd, ["--no-drift-exit"])
            self.assertEqual(result.exit_code, 0, msg=result.output)

    def test_json_output_is_valid(self):
        runner = CliRunner()
        with patch("defenseclaw.commands.cmd_version._gateway_component") as gw, \
             patch("defenseclaw.commands.cmd_version._plugin_component") as pl:
            gw.return_value = cmd_version.Component(
                name="gateway", version=__version__, origin="/usr/bin",
            )
            pl.return_value = cmd_version.Component(
                name="plugin", version=__version__, origin="~/.openclaw",
            )
            result = runner.invoke(cmd_version.version_cmd, ["--json"])
            self.assertEqual(result.exit_code, 0, msg=result.output)
            payload = json.loads(result.output)
            self.assertIn("components", payload)
            self.assertTrue(payload["ok"])

    def test_missing_gateway_reports_missing_status(self):
        runner = CliRunner()
        with patch("defenseclaw.commands.cmd_version.resolve_gateway_binary", return_value=None), \
             patch("defenseclaw.commands.cmd_version._plugin_component") as pl:
            pl.return_value = cmd_version.Component(
                name="plugin", version=__version__, origin="~/.openclaw",
            )
            result = runner.invoke(cmd_version.version_cmd, ["--json"])
            payload = json.loads(result.output)
            gw = next(c for c in payload["components"] if c["name"] == "gateway")
            self.assertEqual(gw["status"], "missing")

    def test_gateway_component_uses_resolver_path(self):
        with patch(
            "defenseclaw.commands.cmd_version.resolve_gateway_binary",
            return_value="/custom/defenseclaw-gateway",
        ), patch(
            "defenseclaw.commands.cmd_version.subprocess.check_output",
            return_value="defenseclaw-gateway version 0.2.0",
        ) as check_output:
            component = cmd_version._gateway_component()

        check_output.assert_called_once()
        self.assertEqual(check_output.call_args.args[0][0], "/custom/defenseclaw-gateway")
        self.assertEqual(component.version, "0.2.0")
        self.assertEqual(component.origin, "/custom/defenseclaw-gateway")


if __name__ == "__main__":
    unittest.main()
