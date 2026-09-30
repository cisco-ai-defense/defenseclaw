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
from unittest.mock import Mock, patch

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

    def test_cli_component_reads_the_live_package_version(self):
        with patch("defenseclaw.__version__", "9.9.9"):
            component = cmd_version._cli_component()

        self.assertEqual(component.version, "9.9.9")

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
        # F-0001: the version probe now resolves the gateway through
        # gateway.resolve_gateway_binary() (honouring DEFENSECLAW_GATEWAY_BIN
        # and the canonical install fallback) instead of a bare
        # shutil.which, so patch the resolver to report nothing installed.
        with patch(
            "defenseclaw.commands.cmd_version.gateway.resolve_gateway_binary",
            return_value=None,
        ), \
             patch("defenseclaw.commands.cmd_version._plugin_component") as pl:
            pl.return_value = cmd_version.Component(
                name="plugin", version=__version__, origin="~/.openclaw",
            )
            result = runner.invoke(cmd_version.version_cmd, ["--json"])
            payload = json.loads(result.output)
            gw = next(c for c in payload["components"] if c["name"] == "gateway")
            self.assertEqual(gw["status"], "missing")

    def test_plugin_is_not_used_without_openclaw(self):
        # A Hermes-only install has no OpenClaw plugin to be missing or stale.
        runner = CliRunner()
        cfg = Mock(active_connectors=lambda: ["hermes"])
        with patch("defenseclaw.config.load", return_value=cfg), \
             patch("defenseclaw.commands.cmd_version._gateway_component") as gw, \
             patch("defenseclaw.commands.cmd_version._plugin_component") as pl:
            gw.return_value = cmd_version.Component(
                name="gateway", version=__version__, origin="/usr/bin",
            )
            result = runner.invoke(cmd_version.version_cmd, ["--json"])
            payload = json.loads(result.output)
            plugin = next(c for c in payload["components"] if c["name"] == "plugin")
            self.assertEqual(plugin["status"], "skipped")
            self.assertTrue(payload["ok"])
            pl.assert_not_called()

    def test_plugin_is_not_used_before_init(self):
        # Before init the defaults name OpenClaw, but nothing is configured.
        cfg = Mock(active_connectors=lambda: ["openclaw"], _source_config_version=0)
        with patch("defenseclaw.config.load", return_value=cfg), \
             patch("defenseclaw.config.config_path", return_value=Mock(exists=lambda: False)):
            self.assertFalse(cmd_version._openclaw_connector_active())


class OpenClawPluginRowTests(unittest.TestCase):
    """#881: the plugin row exists only when OpenClaw is an active connector."""

    def _cfg(self, **guardrail):
        from defenseclaw.config import Config, PerConnectorGuardrailConfig

        cfg = Config()
        mode = guardrail.pop("claw_mode", None)
        if mode is not None:
            cfg.claw.mode = mode
        cfg.guardrail.connector = guardrail.pop("connector", "")
        cfg.guardrail.connectors = {
            name: PerConnectorGuardrailConfig(enabled=enabled)
            for name, enabled in guardrail.pop("connectors", {}).items()
        }
        return cfg

    def test_hermes_only_install_is_not_openclaw(self):
        cfg = self._cfg(connector="hermes", claw_mode="hermes")
        self.assertFalse(cmd_version._openclaw_active_in(cfg))

    def test_multi_connector_install_with_openclaw_is_openclaw(self):
        cfg = self._cfg(connector="codex", claw_mode="codex", connectors={"codex": None, "openclaw": None})
        self.assertTrue(cmd_version._openclaw_active_in(cfg))

    def test_disabled_openclaw_connector_is_not_active(self):
        cfg = self._cfg(connector="codex", claw_mode="codex", connectors={"codex": None, "openclaw": False})
        self.assertFalse(cmd_version._openclaw_active_in(cfg))

    def test_unconfigured_install_is_not_openclaw(self):
        cfg = self._cfg(claw_mode="")
        self.assertFalse(cmd_version._openclaw_active_in(cfg))

    def test_single_openclaw_install_is_openclaw(self):
        cfg = self._cfg(connector="openclaw", claw_mode="openclaw")
        self.assertTrue(cmd_version._openclaw_active_in(cfg))

    def test_unreadable_config_keeps_the_plugin_row(self):
        with patch("defenseclaw.config.load", side_effect=RuntimeError("bad yaml")):
            self.assertTrue(cmd_version._openclaw_connector_active())

    def test_reads_the_install_config(self):
        import tempfile

        with tempfile.TemporaryDirectory() as home:
            with open(os.path.join(home, "config.yaml"), "w", encoding="utf-8") as fh:
                fh.write("config_version: 8\nclaw:\n  mode: hermes\nguardrail:\n  connector: hermes\n")
            with patch.dict(os.environ, {"DEFENSECLAW_HOME": home}):
                os.environ.pop("DEFENSECLAW_CONFIG", None)
                self.assertFalse(cmd_version._openclaw_connector_active())

    def test_hermes_only_version_skips_the_plugin(self):
        runner = CliRunner()
        with patch("defenseclaw.commands.cmd_version._openclaw_connector_active", return_value=False), \
             patch("defenseclaw.commands.cmd_version._gateway_component") as gw, \
             patch("defenseclaw.commands.cmd_version._plugin_component") as pl:
            gw.return_value = cmd_version.Component(name="gateway", version=__version__, origin="/usr/bin")
            # A stale plugin left on disk must not count as drift either.
            pl.return_value = cmd_version.Component(name="plugin", version="0.0.1", origin="~/.openclaw")
            human = runner.invoke(cmd_version.version_cmd, [])
            as_json = runner.invoke(cmd_version.version_cmd, ["--json"])

        self.assertEqual(human.exit_code, 0, msg=human.output)
        self.assertIn("(not used)", human.output)
        self.assertIn("All components in sync", human.output)
        payload = json.loads(as_json.output)
        self.assertEqual(
            [(c["name"], c["status"]) for c in payload["components"]],
            [("cli", "ok"), ("gateway", "ok"), ("plugin", "skipped")],
        )
        self.assertTrue(payload["ok"])
        pl.assert_not_called()

    def test_openclaw_install_lists_the_plugin(self):
        runner = CliRunner()
        with patch("defenseclaw.commands.cmd_version._openclaw_connector_active", return_value=True), \
             patch("defenseclaw.commands.cmd_version._gateway_component") as gw, \
             patch("defenseclaw.commands.cmd_version._plugin_component") as pl:
            gw.return_value = cmd_version.Component(name="gateway", version=__version__, origin="/usr/bin")
            pl.return_value = cmd_version.Component(
                name="plugin", version="(not installed)", origin="~/.openclaw", status="missing",
            )
            result = runner.invoke(cmd_version.version_cmd, ["--json"])

        payload = json.loads(result.output)
        plugin = next(c for c in payload["components"] if c["name"] == "plugin")
        self.assertEqual(plugin["status"], "missing")


if __name__ == "__main__":
    unittest.main()
