# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the PR #348 trusted-prefix work and its review follow-ups.

Covers:
  * ``_add_trusted_bin_prefix`` append/dedupe/0600/os.environ behaviour;
  * the action-mode gate's "trust this directory" prompt re-running the FULL
    compatibility check (review finding #1 — the prompt must not short-circuit
    on version truthiness and admit an unsupported version);
  * ``/opt/homebrew/Caskroom`` being a built-in default;
  * the ``defenseclaw setup trusted-paths`` CLI (list / add / remove, JSON,
    world-writable refusal, default protection).
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands import cmd_agent, cmd_setup
from defenseclaw.config import (
    CiscoAIDefenseConfig,
    Config,
    GatewayConfig,
    GuardrailConfig,
    OpenShellConfig,
)
from defenseclaw.connector_contracts import (
    STATUS_KNOWN,
    STATUS_UNKNOWN,
    STATUS_UNVERSIONED,
    ConnectorCompatibility,
    ConnectorContract,
)
from defenseclaw.context import AppContext
from defenseclaw.inventory import agent_discovery as ad


def _make_app_context(data_dir: str) -> AppContext:
    cfg = Config(
        data_dir=data_dir,
        audit_db=os.path.join(data_dir, "audit.db"),
        quarantine_dir=os.path.join(data_dir, "quarantine"),
        plugin_dir=os.path.join(data_dir, "plugins"),
        policy_dir=os.path.join(data_dir, "policies"),
        guardrail=GuardrailConfig(),
        gateway=GatewayConfig(),
        openshell=OpenShellConfig(),
        cisco_ai_defense=CiscoAIDefenseConfig(),
    )
    ctx = AppContext()
    ctx.cfg = cfg
    return ctx


def _signal(version: str, error: str, binary_path: str) -> ad.AgentSignal:
    return ad.AgentSignal(
        name="codex",
        installed=True,
        config_path="",
        binary_path=binary_path,
        version=version,
        error=error,
    )


def _disc(signal: ad.AgentSignal) -> ad.AgentDiscovery:
    return ad.AgentDiscovery(scanned_at="t", agents={"codex": signal}, cache_hit=False)


def _compat(version: str, status: str, contract_id: str | None = None, reason: str = "") -> ConnectorCompatibility:
    contract = ConnectorContract(connector="codex", contract_id=contract_id) if contract_id else None
    return ConnectorCompatibility(
        connector="codex",
        raw_version=version,
        normalized_version=version,
        status=status,
        reason=reason,
        contract=contract,
    )


class AddTrustedBinPrefixTests(unittest.TestCase):
    def test_append_dedupe_persist_0600_and_environ(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {"DEFENSECLAW_TRUSTED_BIN_PREFIXES": ""}, clear=False):
                added1 = cmd_setup._add_trusted_bin_prefix("/opt/tools", tmp)
                added2 = cmd_setup._add_trusted_bin_prefix("/opt/tools", tmp)  # dedupe
                added3 = cmd_setup._add_trusted_bin_prefix("/opt/more", tmp)
                self.assertTrue(added1)
                self.assertFalse(added2, "second add of same prefix should be a no-op")
                self.assertTrue(added3)
                # os.environ reflects both, separated by os.pathsep.
                val = os.environ["DEFENSECLAW_TRUSTED_BIN_PREFIXES"]
                parts = val.split(os.pathsep)
                self.assertEqual(parts.count("/opt/tools"), 1)
                self.assertIn("/opt/more", parts)
            dotenv = os.path.join(tmp, ".env")
            self.assertTrue(os.path.isfile(dotenv))
            self.assertEqual(os.stat(dotenv).st_mode & 0o777, 0o600)
            body = open(dotenv, encoding="utf-8").read()
            self.assertIn("/opt/tools", body)
            self.assertIn("/opt/more", body)


class CaskroomDefaultTests(unittest.TestCase):
    def test_caskroom_is_a_builtin_default(self):
        self.assertIn("/opt/homebrew/Caskroom", ad._TRUSTED_BIN_PREFIXES_DEFAULT)


class GatePromptContractGateTests(unittest.TestCase):
    """Review #1: trusting the prefix must re-run the contract gate, not
    short-circuit on a non-empty version string."""

    def _run(self, second_signal, confirm, contract_side_effect):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        binpath = os.path.join(tmp, "codex")
        first = _disc(_signal("", ad.UNTRUSTED_PREFIX_ERROR, binpath))
        discos = [first, _disc(second_signal)] if second_signal is not None else [first]
        with patch.dict(os.environ, {"DEFENSECLAW_TRUSTED_BIN_PREFIXES": ""}, clear=False), patch.object(
            cmd_setup.agent_discovery, "discover_agents", side_effect=discos
        ) as mock_disc, patch.object(
            cmd_setup, "resolve_connector_contract", side_effect=contract_side_effect
        ), patch.object(
            sys.stdin, "isatty", return_value=True
        ), patch.object(
            sys.stdout, "isatty", return_value=True
        ), patch.object(
            cmd_setup.click, "confirm", return_value=confirm
        ):
            result = cmd_setup._check_connector_version_supported_for_setup(
                "codex", mode="action", data_dir=tmp
            )
        return result, mock_disc, tmp, binpath

    def test_trusted_but_unsupported_version_is_still_refused(self):
        # After trusting, re-discovery yields a real version that maps to
        # STATUS_UNKNOWN (unsupported). The OLD code returned True here; the
        # fix re-runs the gate and returns False.
        def contract(_c, v):
            return _compat(v, STATUS_UNVERSIONED, "codex-hooks-v1") if v == "" else _compat(v, STATUS_UNKNOWN, reason="too new")

        result, mock_disc, tmp, binpath = self._run(
            _signal("99.0", "", os.path.join(tempfile.gettempdir(), "codex")),
            confirm=True,
            contract_side_effect=contract,
        )
        self.assertFalse(result, "unsupported version must be refused even after trusting the path")
        self.assertEqual(mock_disc.call_count, 2, "should re-discover after trusting (full gate re-run)")
        # The path WAS trusted (persisted) — proving we refused on the
        # contract, not because trusting failed.
        body = open(os.path.join(tmp, ".env"), encoding="utf-8").read()
        self.assertIn(os.path.dirname(os.path.realpath(binpath)), body)

    def test_trusted_and_supported_version_is_accepted(self):
        def contract(_c, v):
            return _compat(v, STATUS_UNVERSIONED, "codex-hooks-v1") if v == "" else _compat(v, STATUS_KNOWN, "codex-hooks-v1")

        result, mock_disc, _tmp, _bin = self._run(
            _signal("1.0", "", os.path.join(tempfile.gettempdir(), "codex")),
            confirm=True,
            contract_side_effect=contract,
        )
        self.assertTrue(result, "a supported version should pass after trusting")
        self.assertEqual(mock_disc.call_count, 2)

    def test_declined_prompt_refuses_and_does_not_trust(self):
        def contract(_c, v):
            return _compat(v, STATUS_UNVERSIONED, "codex-hooks-v1")

        result, mock_disc, tmp, _bin = self._run(
            None, confirm=False, contract_side_effect=contract
        )
        self.assertFalse(result)
        self.assertEqual(mock_disc.call_count, 1, "declining must not trigger a re-discovery")
        dotenv = os.path.join(tmp, ".env")
        if os.path.isfile(dotenv):
            self.assertNotIn("DEFENSECLAW_TRUSTED_BIN_PREFIXES", open(dotenv, encoding="utf-8").read())

    def test_declined_prompt_still_emits_trusted_paths_hint(self):
        """Review follow-up: declining the trust prompt must still show remediation."""
        hints: list[str] = []

        def _capture(msg: str) -> None:
            hints.append(msg)

        def contract(_c, v):
            return _compat(v, STATUS_UNVERSIONED, "codex-hooks-v1")

        with patch.object(cmd_setup.ux, "subhead", side_effect=_capture):
            result, _mock_disc, _tmp, binpath = self._run(
                None, confirm=False, contract_side_effect=contract
            )
        self.assertFalse(result)
        joined = " ".join(hints)
        self.assertIn("trusted-paths add", joined)
        self.assertIn(os.path.dirname(os.path.realpath(binpath)), joined)
        self.assertIn("appends to ~/.defenseclaw/.env", joined)


class ValidateTrustedPrefixTests(unittest.TestCase):
    def test_rejects_non_absolute_path(self):
        resolved, err = ad.validate_trusted_prefix("relative/bin")
        self.assertIsNotNone(err)
        self.assertIn("not absolute", err or "")

    def test_realpath_canonicalises_symlink_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "target")
            link = os.path.join(tmp, "link")
            os.makedirs(target)
            os.symlink(target, link)
            resolved, err = ad.validate_trusted_prefix(link)
            self.assertIsNone(err)
            self.assertEqual(resolved, os.path.realpath(target))

    def test_group_writable_directory_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            gdir = os.path.join(tmp, "gtools")
            os.makedirs(gdir)
            os.chmod(gdir, 0o770)
            with patch.object(ad, "_trusted_prefix_dir_mode_error", return_value="directory is group-writable"):
                _resolved, err = ad.validate_trusted_prefix(gdir)
            self.assertEqual(err, "directory is group-writable")


class TrustedPathsCliTests(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()

    def test_list_json_includes_defaults_and_caskroom(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            with patch.dict(os.environ, {"DEFENSECLAW_TRUSTED_BIN_PREFIXES": ""}, clear=False):
                result = self.runner.invoke(cmd_setup.trusted_paths, ["list", "--json"], obj=app)
            self.assertEqual(result.exit_code, 0, msg=result.output)
            rows = json.loads(result.output)
            resolved = {r["resolved"] for r in rows}
            self.assertIn("/opt/homebrew/Caskroom", resolved)
            self.assertTrue(all({"path", "resolved", "source", "status", "removable"} <= set(r) for r in rows))

    def test_add_persists_and_shows_removable(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            newdir = os.path.join(tmp, "tools")
            os.makedirs(newdir)
            resolved, err = ad.validate_trusted_prefix(newdir)
            self.assertIsNone(err)
            with patch.dict(os.environ, {"DEFENSECLAW_TRUSTED_BIN_PREFIXES": ""}, clear=False):
                add = self.runner.invoke(cmd_setup.trusted_paths, ["add", newdir, "--json"], obj=app)
                self.assertEqual(add.exit_code, 0, msg=add.output)
                self.assertTrue(json.loads(add.output)["ok"])
                listing = self.runner.invoke(cmd_setup.trusted_paths, ["list", "--json"], obj=app)
                rows = {r["resolved"]: r for r in json.loads(listing.output)}
            dotenv_body = open(os.path.join(tmp, ".env"), encoding="utf-8").read()
            self.assertIn(resolved, dotenv_body)
            self.assertTrue(rows[resolved]["removable"])
            self.assertEqual(rows[resolved]["source"], ".env")

    def test_add_world_writable_refused_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            wdir = os.path.join(tmp, "wtools")
            os.makedirs(wdir)
            os.chmod(wdir, 0o777)
            with patch.dict(os.environ, {"DEFENSECLAW_TRUSTED_BIN_PREFIXES": ""}, clear=False):
                result = self.runner.invoke(cmd_setup.trusted_paths, ["add", wdir, "--json"], obj=app)
            self.assertNotEqual(result.exit_code, 0)
            payload = json.loads(result.output)
            self.assertFalse(payload["ok"])
            self.assertIn("world-writable", payload["message"])

    def test_add_world_writable_allowed_with_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            wdir = os.path.join(tmp, "wtools")
            os.makedirs(wdir)
            os.chmod(wdir, 0o777)
            with patch.dict(os.environ, {"DEFENSECLAW_TRUSTED_BIN_PREFIXES": ""}, clear=False):
                result = self.runner.invoke(cmd_setup.trusted_paths, ["add", wdir, "--force", "--json"], obj=app)
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertTrue(json.loads(result.output)["ok"])

    def test_add_builtin_default_is_noop(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            with patch.dict(os.environ, {"DEFENSECLAW_TRUSTED_BIN_PREFIXES": ""}, clear=False):
                result = self.runner.invoke(cmd_setup.trusted_paths, ["add", "/usr/bin", "--json"], obj=app)
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertIn("default", json.loads(result.output)["message"])

    def test_remove_operator_added(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            newdir = os.path.join(tmp, "tools")
            os.makedirs(newdir)
            with patch.dict(os.environ, {"DEFENSECLAW_TRUSTED_BIN_PREFIXES": ""}, clear=False):
                self.runner.invoke(cmd_setup.trusted_paths, ["add", newdir], obj=app)
                result = self.runner.invoke(cmd_setup.trusted_paths, ["remove", newdir, "--json"], obj=app)
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertTrue(json.loads(result.output)["ok"])
            self.assertNotIn(newdir, open(os.path.join(tmp, ".env"), encoding="utf-8").read())

    def test_remove_builtin_default_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            with patch.dict(os.environ, {"DEFENSECLAW_TRUSTED_BIN_PREFIXES": ""}, clear=False):
                result = self.runner.invoke(cmd_setup.trusted_paths, ["remove", "/usr/bin", "--json"], obj=app)
            self.assertNotEqual(result.exit_code, 0)
            self.assertIn("default", json.loads(result.output)["message"])

    def test_remove_absent_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            with patch.dict(os.environ, {"DEFENSECLAW_TRUSTED_BIN_PREFIXES": ""}, clear=False):
                result = self.runner.invoke(
                    cmd_setup.trusted_paths, ["remove", os.path.join(tmp, "nope"), "--json"], obj=app
                )
            self.assertNotEqual(result.exit_code, 0)


class AgentDiscoverHintTests(unittest.TestCase):
    """`agent discover` should point at the generic trusted-paths remediation
    when a connector binary is skipped for living outside a trusted prefix."""

    def test_hint_points_at_trusted_paths_for_untrusted_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            binpath = os.path.join(tmp, "codex")
            disc = _disc(_signal("", ad.UNTRUSTED_PREFIX_ERROR, binpath))
            with patch.dict(os.environ, {"DEFENSECLAW_HOME": tmp}, clear=False):
                with patch.object(cmd_agent.agent_discovery, "discover_agents", return_value=disc):
                    result = CliRunner().invoke(cmd_agent.discover, ["--no-emit-otel"], obj=app)
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertIn("trusted-paths add", result.output)
            self.assertIn(os.path.dirname(os.path.realpath(binpath)), result.output)

    def test_no_hint_when_all_binaries_trusted(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            disc = _disc(_signal("1.0", "", "/usr/bin/codex"))
            with patch.dict(os.environ, {"DEFENSECLAW_HOME": tmp}, clear=False):
                with patch.object(cmd_agent.agent_discovery, "discover_agents", return_value=disc):
                    result = CliRunner().invoke(cmd_agent.discover, ["--no-emit-otel"], obj=app)
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertNotIn("trusted-paths add", result.output)

    def test_discover_hydrates_persisted_trusted_prefix_from_env(self):
        """Fix (b): `agent` skips the root config load, so discover must itself
        hydrate ~/.defenseclaw/.env — otherwise a prefix added via
        `trusted-paths add` is ignored by `agent discover`."""
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            with open(os.path.join(tmp, ".env"), "w", encoding="utf-8") as fh:
                fh.write("DEFENSECLAW_TRUSTED_BIN_PREFIXES=/opt/demo-trust\n")
            disc = _disc(_signal("1.0", "", "/usr/bin/codex"))
            env = {"DEFENSECLAW_HOME": tmp}
            with patch.dict(os.environ, env, clear=False):
                os.environ.pop("DEFENSECLAW_TRUSTED_BIN_PREFIXES", None)
                with patch.object(cmd_agent.agent_discovery, "discover_agents", return_value=disc):
                    result = CliRunner().invoke(cmd_agent.discover, ["--no-emit-otel"], obj=app)
                hydrated = os.environ.get("DEFENSECLAW_TRUSTED_BIN_PREFIXES", "")
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertIn("/opt/demo-trust", hydrated.split(os.pathsep))


class TrustedPathsTuiSectionTests(unittest.TestCase):
    """The TUI setup panel exposes a read-only 'Trusted Paths' section that
    reuses the CLI's _collect_trusted_prefixes view (so they can't drift)."""

    def test_section_lists_operator_path_and_cli_hint(self):
        from defenseclaw.tui.panels import setup as panel

        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {"DEFENSECLAW_TRUSTED_BIN_PREFIXES": "/opt/acme/bin"}, clear=False):
                fields = panel._trusted_paths_summary_fields(SimpleNamespace(data_dir=tmp))
            labels = [f.label for f in fields]
            values = " ".join(f.value for f in fields)
            self.assertIn("Built-in defaults", labels)
            self.assertIn("default prefixes", values)
            self.assertIn("/opt/acme/bin", values)
            self.assertTrue(any("trusted-paths add" in f.value for f in fields))

    def test_section_registered_in_build_setup_sections(self):
        from defenseclaw.tui.panels import setup as panel

        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            names = [s.name for s in panel.build_setup_sections(app.cfg)]
            self.assertIn("Trusted Paths", names)


if __name__ == "__main__":
    unittest.main()
