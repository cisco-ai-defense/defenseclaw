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
from threading import Event, Thread
from types import SimpleNamespace
from unittest.mock import patch

import yaml
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
    def test_append_dedupe_persist_to_config_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {"DEFENSECLAW_TRUSTED_BIN_PREFIXES": ""}, clear=False):
                added1 = cmd_setup._add_trusted_bin_prefix("/opt/tools", tmp)
                added2 = cmd_setup._add_trusted_bin_prefix("/opt/tools", tmp)  # dedupe
                added3 = cmd_setup._add_trusted_bin_prefix("/opt/more", tmp)
                self.assertTrue(added1)
                self.assertFalse(added2, "second add of same prefix should be a no-op")
                self.assertTrue(added3)
            cfg_path = os.path.join(tmp, "config.yaml")
            self.assertTrue(os.path.isfile(cfg_path))
            body = yaml.safe_load(open(cfg_path, encoding="utf-8")) or {}
            prefixes = body["ai_discovery"]["trusted_binary_prefixes"]
            self.assertEqual(prefixes.count("/opt/tools"), 1)
            self.assertIn("/opt/more", prefixes)

    def test_embedded_newline_prefix_is_rejected_and_no_entry_injected(self):
        """F-1401: a trusted-path NAME with an embedded newline must not be
        able to inject a second KEY=VALUE line into ~/.defenseclaw/.env.

        ``~/.defenseclaw/.env`` is parsed line-by-line, so a prefix like
        ``/opt/tools\\nDEFENSECLAW_DISABLE_REDACTION=1`` would otherwise add a
        second assignment that disables redaction. The dotenv writer now
        sanitizes (sanitize_dotenv_value) and raises DotenvValueError; the
        write is built before the file is opened, so the pre-existing legit
        entry is preserved and the injected key never lands.
        """
        from defenseclaw.safety import DotenvValueError

        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {"DEFENSECLAW_TRUSTED_BIN_PREFIXES": ""}, clear=False):
                # Seed a legitimate trusted prefix first.
                cmd_setup._add_trusted_bin_prefix("/opt/legit", tmp)

                malicious = "/opt/tools\nDEFENSECLAW_DISABLE_REDACTION=1"
                with self.assertRaises(DotenvValueError):
                    cmd_setup._add_trusted_bin_prefix(malicious, tmp)

            cfg_path = os.path.join(tmp, "config.yaml")
            body = yaml.safe_load(open(cfg_path, encoding="utf-8")) or {}
            self.assertNotIn("DEFENSECLAW_DISABLE_REDACTION", body)
            self.assertEqual(body["ai_discovery"]["trusted_binary_prefixes"], ["/opt/legit"])

    def test_dotenv_writer_refuses_symlink_target(self):
        """Secret/trusted-prefix writes must not follow a symlinked .env."""
        from defenseclaw.safety import SafetyError

        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "target")
            dotenv = os.path.join(tmp, ".env")
            with open(target, "w", encoding="utf-8") as fh:
                fh.write("ORIGINAL=1\n")
            try:
                os.symlink(target, dotenv)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink unavailable: {exc}")

            with self.assertRaises(SafetyError):
                cmd_setup._write_dotenv(dotenv, {"SAFE": "value"})

            with open(target, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "ORIGINAL=1\n")


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
        with (
            patch.dict(os.environ, {"DEFENSECLAW_TRUSTED_BIN_PREFIXES": ""}, clear=False),
            patch.object(cmd_setup.agent_discovery, "discover_agents", side_effect=discos) as mock_disc,
            patch.object(cmd_setup, "resolve_connector_contract", side_effect=contract_side_effect),
            patch.object(sys.stdin, "isatty", return_value=True),
            patch.object(sys.stdout, "isatty", return_value=True),
            patch.object(cmd_setup.click, "confirm", return_value=confirm),
        ):
            result = cmd_setup._check_connector_version_supported_for_setup("codex", mode="action", data_dir=tmp)
        return result, mock_disc, tmp, binpath

    def test_trusted_but_unsupported_version_is_still_refused(self):
        # After trusting, re-discovery yields a real version that maps to
        # STATUS_UNKNOWN (unsupported). The OLD code returned True here; the
        # fix re-runs the gate and returns False.
        def contract(_c, v):
            return (
                _compat(v, STATUS_UNVERSIONED, "codex-hooks-v1")
                if v == ""
                else _compat(v, STATUS_UNKNOWN, reason="too new")
            )

        result, mock_disc, tmp, binpath = self._run(
            _signal("99.0", "", os.path.join(tempfile.gettempdir(), "codex")),
            confirm=True,
            contract_side_effect=contract,
        )
        self.assertFalse(result, "unsupported version must be refused even after trusting the path")
        self.assertEqual(mock_disc.call_count, 2, "should re-discover after trusting (full gate re-run)")
        # The path WAS trusted (persisted) — proving we refused on the
        # contract, not because trusting failed.
        body = yaml.safe_load(open(os.path.join(tmp, "config.yaml"), encoding="utf-8")) or {}
        self.assertIn(
            os.path.dirname(os.path.realpath(binpath)),
            body["ai_discovery"]["trusted_binary_prefixes"],
        )

    def test_trusted_and_supported_version_is_accepted(self):
        def contract(_c, v):
            return (
                _compat(v, STATUS_UNVERSIONED, "codex-hooks-v1")
                if v == ""
                else _compat(v, STATUS_KNOWN, "codex-hooks-v1")
            )

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

        result, mock_disc, tmp, _bin = self._run(None, confirm=False, contract_side_effect=contract)
        self.assertFalse(result)
        self.assertEqual(mock_disc.call_count, 1, "declining must not trigger a re-discovery")
        cfg_path = os.path.join(tmp, "config.yaml")
        if os.path.isfile(cfg_path):
            body = yaml.safe_load(open(cfg_path, encoding="utf-8")) or {}
            self.assertNotIn(
                os.path.dirname(os.path.realpath(_bin)), body.get("ai_discovery", {}).get("trusted_binary_prefixes", [])
            )

    def test_declined_prompt_still_emits_trusted_paths_hint(self):
        """Review follow-up: declining the trust prompt must still show remediation."""
        hints: list[str] = []

        def _capture(msg: str) -> None:
            hints.append(msg)

        def contract(_c, v):
            return _compat(v, STATUS_UNVERSIONED, "codex-hooks-v1")

        with patch.object(cmd_setup.ux, "subhead", side_effect=_capture):
            result, _mock_disc, _tmp, binpath = self._run(None, confirm=False, contract_side_effect=contract)
        self.assertFalse(result)
        joined = " ".join(hints)
        self.assertIn("trusted-paths add", joined)
        self.assertIn(os.path.dirname(os.path.realpath(binpath)), joined)
        self.assertIn("writes ~/.defenseclaw/config.yaml", joined)

    def test_prompt_cache_avoids_reasking_same_directory(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        binpath = os.path.join(tmp, "bin", "codex")
        disc = _disc(_signal("", ad.UNTRUSTED_PREFIX_ERROR, binpath))
        cache: dict[str, bool] = {}

        def contract(_c, v):
            return _compat(v, STATUS_UNVERSIONED, "codex-hooks-v1")

        with (
            patch.dict(os.environ, {"DEFENSECLAW_TRUSTED_BIN_PREFIXES": ""}, clear=False),
            patch.object(cmd_setup.agent_discovery, "discover_agents", return_value=disc),
            patch.object(cmd_setup, "resolve_connector_contract", side_effect=contract),
            patch.object(sys.stdin, "isatty", return_value=True),
            patch.object(sys.stdout, "isatty", return_value=True),
            patch.object(cmd_setup.click, "confirm", return_value=False) as confirm,
        ):
            first = cmd_setup._check_connector_version_supported_for_setup(
                "codex",
                mode="action",
                data_dir=tmp,
                _trusted_prompt_cache=cache,
            )
            second = cmd_setup._check_connector_version_supported_for_setup(
                "codex",
                mode="action",
                data_dir=tmp,
                _trusted_prompt_cache=cache,
            )

        self.assertFalse(first)
        self.assertFalse(second)
        confirm.assert_called_once()
        self.assertEqual(cache, {os.path.dirname(os.path.realpath(binpath)): False})


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
            body = yaml.safe_load(open(os.path.join(tmp, "config.yaml"), encoding="utf-8")) or {}
            self.assertIn(resolved, body["ai_discovery"]["trusted_binary_prefixes"])
            self.assertTrue(rows[resolved]["removable"])
            self.assertEqual(rows[resolved]["source"], "config")

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
            body = yaml.safe_load(open(os.path.join(tmp, "config.yaml"), encoding="utf-8")) or {}
            self.assertNotIn(newdir, body.get("ai_discovery", {}).get("trusted_binary_prefixes", []))

    def test_remove_clears_config_legacy_dotenv_and_process_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            newdir = os.path.join(tmp, "tools")
            os.makedirs(newdir)
            with patch.dict(os.environ, {"DEFENSECLAW_TRUSTED_BIN_PREFIXES": newdir}, clear=False):
                self.runner.invoke(cmd_setup.trusted_paths, ["add", newdir], obj=app)
                cmd_setup._write_dotenv(
                    os.path.join(tmp, ".env"),
                    {"DEFENSECLAW_TRUSTED_BIN_PREFIXES": newdir},
                )
                result = self.runner.invoke(cmd_setup.trusted_paths, ["remove", newdir, "--json"], obj=app)
                self.assertEqual(result.exit_code, 0, msg=result.output)
                self.assertNotIn(newdir, os.environ.get("DEFENSECLAW_TRUSTED_BIN_PREFIXES", ""))
            body = yaml.safe_load(open(os.path.join(tmp, "config.yaml"), encoding="utf-8")) or {}
            self.assertNotIn(newdir, body.get("ai_discovery", {}).get("trusted_binary_prefixes", []))
            dotenv = cmd_setup._load_dotenv(os.path.join(tmp, ".env"))
            self.assertNotIn(newdir, dotenv.get("DEFENSECLAW_TRUSTED_BIN_PREFIXES", ""))

    def test_remove_holds_dotenv_lock_through_config_save_and_rollback_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            newdir = os.path.join(tmp, "tools")
            os.makedirs(newdir)
            dotenv_path = os.path.join(tmp, ".env")
            save_entered = Event()
            release_save = Event()
            writer_done = Event()
            results: list[object] = []
            errors: list[BaseException] = []
            original_save = app.cfg._save_locked

            def paused_save(path: str) -> None:
                save_entered.set()
                if not release_save.wait(5):
                    raise TimeoutError("test did not release config save")
                original_save(path)

            def remove() -> None:
                try:
                    results.append(self.runner.invoke(cmd_setup.trusted_paths, ["remove", newdir], obj=app))
                except BaseException as error:
                    errors.append(error)

            def write_secret() -> None:
                try:
                    cmd_setup._save_secret_to_dotenv("DEFENSECLAW_CONCURRENT_SECRET", "preserved", tmp)
                except BaseException as error:
                    errors.append(error)
                finally:
                    writer_done.set()

            with patch.dict(os.environ, {"DEFENSECLAW_TRUSTED_BIN_PREFIXES": ""}, clear=False):
                self.runner.invoke(cmd_setup.trusted_paths, ["add", newdir], obj=app)
                cmd_setup._write_dotenv(dotenv_path, {"DEFENSECLAW_TRUSTED_BIN_PREFIXES": newdir})
                with patch.object(app.cfg, "_save_locked", side_effect=paused_save):
                    remove_thread = Thread(target=remove, daemon=True)
                    remove_thread.start()
                    self.assertTrue(save_entered.wait(5), "remove did not reach config save")
                    writer_thread = Thread(target=write_secret, daemon=True)
                    writer_thread.start()
                    self.assertFalse(writer_done.wait(0.2), "concurrent writer bypassed the dotenv lock")
                    release_save.set()
                    remove_thread.join(5)
                    writer_thread.join(5)

            self.assertFalse(remove_thread.is_alive(), "remove deadlocked on nested config lock")
            self.assertFalse(writer_thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].exit_code, 0, msg=results[0].output)
            dotenv = cmd_setup._load_dotenv(dotenv_path)
            self.assertEqual(dotenv["DEFENSECLAW_CONCURRENT_SECRET"], "preserved")
            self.assertNotIn(newdir, dotenv.get("DEFENSECLAW_TRUSTED_BIN_PREFIXES", ""))

    def test_remove_validates_legacy_dotenv_before_config_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            newdir = os.path.join(tmp, "tools")
            os.makedirs(newdir)
            with patch.dict(os.environ, {"DEFENSECLAW_TRUSTED_BIN_PREFIXES": ""}, clear=False):
                self.runner.invoke(cmd_setup.trusted_paths, ["add", newdir], obj=app)
                with open(os.path.join(tmp, ".env"), "wb") as handle:
                    handle.write(b"\xff")
                result = self.runner.invoke(cmd_setup.trusted_paths, ["remove", newdir], obj=app)
            self.assertNotEqual(result.exit_code, 0)
            body = yaml.safe_load(open(os.path.join(tmp, "config.yaml"), encoding="utf-8")) or {}
            self.assertIn(os.path.realpath(newdir), body.get("ai_discovery", {}).get("trusted_binary_prefixes", []))

    def test_remove_restores_exact_dotenv_when_config_save_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            newdir = os.path.join(tmp, "tools")
            os.makedirs(newdir)
            resolved = os.path.realpath(newdir)
            with patch.dict(os.environ, {"DEFENSECLAW_TRUSTED_BIN_PREFIXES": ""}, clear=False):
                self.runner.invoke(cmd_setup.trusted_paths, ["add", newdir], obj=app)
                dotenv_path = os.path.join(tmp, ".env")
                original = (
                    f"# preserve me\nOTHER='quoted value'\nDEFENSECLAW_TRUSTED_BIN_PREFIXES={resolved}\n".encode()
                )
                with open(dotenv_path, "wb") as handle:
                    handle.write(original)
                os.chmod(dotenv_path, 0o640)
                config_path = os.path.join(tmp, "config.yaml")
                with open(config_path, "rb") as handle:
                    config_before = handle.read()
                with patch.object(app.cfg, "_save_locked", side_effect=OSError("config save failed")):
                    result = self.runner.invoke(cmd_setup.trusted_paths, ["remove", newdir], obj=app)
            self.assertNotEqual(result.exit_code, 0)
            with open(dotenv_path, "rb") as handle:
                self.assertEqual(handle.read(), original)
            if os.name != "nt":
                self.assertEqual(os.stat(dotenv_path).st_mode & 0o777, 0o640)
            self.assertIn(resolved, app.cfg.ai_discovery.trusted_binary_prefixes)
            with open(config_path, "rb") as handle:
                self.assertEqual(handle.read(), config_before)
            body = yaml.safe_load(open(os.path.join(tmp, "config.yaml"), encoding="utf-8")) or {}
            self.assertIn(resolved, body.get("ai_discovery", {}).get("trusted_binary_prefixes", []))

    def test_remove_restores_exact_dotenv_when_dotenv_write_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            newdir = os.path.join(tmp, "tools")
            os.makedirs(newdir)
            resolved = os.path.realpath(newdir)
            with patch.dict(os.environ, {"DEFENSECLAW_TRUSTED_BIN_PREFIXES": ""}, clear=False):
                self.runner.invoke(cmd_setup.trusted_paths, ["add", newdir], obj=app)
                dotenv_path = os.path.join(tmp, ".env")
                original = f"# preserve me\nDEFENSECLAW_TRUSTED_BIN_PREFIXES={resolved}\n".encode()
                with open(dotenv_path, "wb") as handle:
                    handle.write(original)
                os.chmod(dotenv_path, 0o640)
                config_path = os.path.join(tmp, "config.yaml")
                with open(config_path, "rb") as handle:
                    config_before = handle.read()

                def partial_write(path, _entries):
                    with open(path, "wb") as handle:
                        handle.write(b"partial")
                    raise OSError("dotenv write failed")

                with patch.object(cmd_setup, "_write_dotenv_locked", side_effect=partial_write):
                    result = self.runner.invoke(cmd_setup.trusted_paths, ["remove", newdir], obj=app)
            self.assertNotEqual(result.exit_code, 0)
            with open(dotenv_path, "rb") as handle:
                self.assertEqual(handle.read(), original)
            if os.name != "nt":
                self.assertEqual(os.stat(dotenv_path).st_mode & 0o777, 0o640)
            self.assertIn(resolved, app.cfg.ai_discovery.trusted_binary_prefixes)
            with open(config_path, "rb") as handle:
                self.assertEqual(handle.read(), config_before)

    def test_restore_dotenv_preserves_zero_mode(self):
        if os.name == "nt":
            self.skipTest("Windows does not preserve POSIX mode bits")
        with tempfile.TemporaryDirectory() as tmp:
            dotenv_path = os.path.join(tmp, ".env")
            cmd_setup._restore_dotenv_snapshot(dotenv_path, b"SECRET=value\n", 0)
            self.assertEqual(os.stat(dotenv_path).st_mode & 0o777, 0)

    @unittest.skipIf(os.name == "nt", "mkfifo is unavailable on Windows")
    def test_dotenv_snapshot_and_restore_reject_fifo(self):
        with tempfile.TemporaryDirectory() as tmp:
            dotenv_path = os.path.join(tmp, ".env")
            os.mkfifo(dotenv_path)
            with self.assertRaisesRegex(OSError, "not a regular file"):
                cmd_setup._snapshot_dotenv(dotenv_path)
            with self.assertRaisesRegex(OSError, "not a regular file"):
                cmd_setup._restore_dotenv_snapshot(dotenv_path, b"SECRET=value\n", 0o600)

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
