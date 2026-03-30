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

"""Tests for the guardrail integration — config, utilities, and CLI command."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner

from defenseclaw.config import (
    Config,
    GuardrailConfig,
    default_config,
    load,
)
from defenseclaw.guardrail import (
    _backup,
    _derive_master_key,
    _register_plugin_in_config,
    _remove_from_plugins_allow,
    _unregister_plugin_from_config,
    detect_api_key_env,
    detect_current_model,
    install_openclaw_plugin,
    model_to_proxy_name,
    patch_openclaw_config,
    restore_openclaw_config,
    uninstall_openclaw_plugin,
)
from tests.helpers import make_app_context, cleanup_app


# ---------------------------------------------------------------------------
# GuardrailConfig dataclass
# ---------------------------------------------------------------------------

class TestGuardrailConfig(unittest.TestCase):
    def test_defaults(self):
        gc = GuardrailConfig()
        self.assertFalse(gc.enabled)
        self.assertEqual(gc.mode, "observe")
        self.assertEqual(gc.port, 4000)
        self.assertEqual(gc.model, "")
        self.assertEqual(gc.api_key_env, "")
        self.assertEqual(gc.block_message, "")

    def test_default_config_includes_guardrail(self):
        cfg = default_config()
        self.assertIsInstance(cfg.guardrail, GuardrailConfig)
        self.assertFalse(cfg.guardrail.enabled)
        self.assertEqual(cfg.guardrail.mode, "observe")

    def test_save_and_reload_preserves_guardrail(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = Config(
                data_dir=tmpdir,
                audit_db=os.path.join(tmpdir, "audit.db"),
                quarantine_dir=os.path.join(tmpdir, "quarantine"),
                plugin_dir=os.path.join(tmpdir, "plugins"),
                policy_dir=os.path.join(tmpdir, "policies"),
                environment="macos",
                guardrail=GuardrailConfig(
                    enabled=True,
                    mode="action",
                    port=5000,
                    model="anthropic/claude-opus-4-5",
                    model_name="claude-opus",
                    api_key_env="ANTHROPIC_API_KEY",
                    block_message="Blocked by policy. Contact security@acme.com.",
                ),
            )
            cfg.save()

            import yaml
            with open(os.path.join(tmpdir, "config.yaml")) as f:
                raw = yaml.safe_load(f)

            g = raw["guardrail"]
            self.assertTrue(g["enabled"])
            self.assertEqual(g["mode"], "action")
            self.assertEqual(g["port"], 5000)
            self.assertEqual(g["model"], "anthropic/claude-opus-4-5")
            self.assertEqual(g["model_name"], "claude-opus")
            self.assertEqual(g["api_key_env"], "ANTHROPIC_API_KEY")
            self.assertEqual(g["block_message"], "Blocked by policy. Contact security@acme.com.")


# ---------------------------------------------------------------------------
# Utility functions in guardrail.py
# ---------------------------------------------------------------------------

class TestModelToProxyName(unittest.TestCase):
    def test_anthropic_model(self):
        self.assertEqual(model_to_proxy_name("anthropic/claude-opus-4-5"), "claude-opus-4-5")

    def test_openai_model(self):
        self.assertEqual(model_to_proxy_name("openai/gpt-4o"), "gpt-4o")

    def test_bare_model(self):
        self.assertEqual(model_to_proxy_name("claude-sonnet"), "claude-sonnet")

    def test_empty(self):
        self.assertEqual(model_to_proxy_name(""), "")


class TestDetectApiKeyEnv(unittest.TestCase):
    def test_anthropic(self):
        self.assertEqual(detect_api_key_env("anthropic/claude-opus-4-5"), "ANTHROPIC_API_KEY")

    def test_openai(self):
        self.assertEqual(detect_api_key_env("openai/gpt-4o"), "OPENAI_API_KEY")

    def test_google(self):
        self.assertEqual(detect_api_key_env("google/gemini-pro"), "GOOGLE_API_KEY")

    def test_unknown(self):
        self.assertEqual(detect_api_key_env("some-model"), "LLM_API_KEY")

    def test_claude_without_prefix(self):
        self.assertEqual(detect_api_key_env("claude-sonnet"), "ANTHROPIC_API_KEY")


class TestDetectCurrentModel(unittest.TestCase):
    def test_reads_model_from_openclaw_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            oc = {
                "agents": {"defaults": {"model": {"primary": "anthropic/claude-opus-4-5"}}}
            }
            path = os.path.join(tmpdir, "openclaw.json")
            with open(path, "w") as f:
                json.dump(oc, f)

            model, provider = detect_current_model(path)
            self.assertEqual(model, "anthropic/claude-opus-4-5")
            self.assertEqual(provider, "anthropic")

    def test_missing_file(self):
        model, provider = detect_current_model("/nonexistent/openclaw.json")
        self.assertEqual(model, "")
        self.assertEqual(provider, "")

    def test_defenseclaw_routed_model(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            oc = {
                "agents": {"defaults": {"model": {"primary": "defenseclaw/claude-opus"}}}
            }
            path = os.path.join(tmpdir, "openclaw.json")
            with open(path, "w") as f:
                json.dump(oc, f)

            model, provider = detect_current_model(path)
            self.assertEqual(model, "defenseclaw/claude-opus")
            self.assertEqual(provider, "defenseclaw")


# ---------------------------------------------------------------------------
# install_openclaw_plugin
# ---------------------------------------------------------------------------

class TestInstallOpenclawPlugin(unittest.TestCase):
    def _make_built_plugin(self, tmpdir):
        """Create a fake built plugin tree with dist/, manifest, and node_modules/."""
        plugin_dir = os.path.join(tmpdir, "extensions", "defenseclaw")
        dist_dir = os.path.join(plugin_dir, "dist")
        os.makedirs(dist_dir)
        with open(os.path.join(plugin_dir, "package.json"), "w") as f:
            json.dump({"name": "@defenseclaw/openclaw-plugin", "version": "0.2.0", "main": "dist/index.js"}, f)
        with open(os.path.join(plugin_dir, "openclaw.plugin.json"), "w") as f:
            json.dump({"id": "defenseclaw", "configSchema": {"type": "object"}}, f)
        with open(os.path.join(dist_dir, "index.js"), "w") as f:
            f.write("// compiled plugin\n")

        nm = os.path.join(plugin_dir, "node_modules")
        for dep in ("js-yaml", "argparse"):
            dep_dir = os.path.join(nm, dep)
            os.makedirs(dep_dir)
            with open(os.path.join(dep_dir, "index.js"), "w") as f:
                f.write(f"// {dep}\n")
        return plugin_dir

    def _make_oc_home(self, tmpdir):
        """Create a fake openclaw home with openclaw.json."""
        oc_home = os.path.join(tmpdir, "openclaw-home")
        os.makedirs(oc_home)
        with open(os.path.join(oc_home, "openclaw.json"), "w") as f:
            json.dump({"plugins": {}}, f)
        return oc_home

    @patch("defenseclaw.guardrail.subprocess.run", side_effect=FileNotFoundError)
    def test_manual_fallback_installs_to_openclaw_extensions(self, _mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_dir = self._make_built_plugin(tmpdir)
            oc_home = self._make_oc_home(tmpdir)

            method, cli_error = install_openclaw_plugin(plugin_dir, oc_home)

            self.assertEqual(method, "manual")
            self.assertIn("not found", cli_error)
            target = os.path.join(oc_home, "extensions", "defenseclaw")
            self.assertTrue(os.path.isfile(os.path.join(target, "package.json")))
            self.assertTrue(os.path.isfile(os.path.join(target, "openclaw.plugin.json")))
            self.assertTrue(os.path.isfile(os.path.join(target, "dist", "index.js")))
            self.assertTrue(os.path.isfile(os.path.join(target, "node_modules", "js-yaml", "index.js")))
            self.assertTrue(os.path.isfile(os.path.join(target, "node_modules", "argparse", "index.js")))

    @patch("defenseclaw.guardrail.subprocess.run", side_effect=FileNotFoundError)
    def test_manual_fallback_registers_in_config(self, _mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_dir = self._make_built_plugin(tmpdir)
            oc_home = self._make_oc_home(tmpdir)

            install_openclaw_plugin(plugin_dir, oc_home)

            with open(os.path.join(oc_home, "openclaw.json")) as f:
                cfg = json.load(f)
            plugins = cfg["plugins"]
            self.assertIn("defenseclaw", plugins.get("entries", {}))
            self.assertTrue(plugins["entries"]["defenseclaw"]["enabled"])
            self.assertIn("defenseclaw", plugins.get("installs", {}))
            install_path = os.path.join(oc_home, "extensions", "defenseclaw")
            self.assertIn(install_path, plugins.get("load", {}).get("paths", []))

    @patch("defenseclaw.guardrail.subprocess.run")
    def test_cli_install_when_openclaw_available(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_dir = self._make_built_plugin(tmpdir)
            oc_home = self._make_oc_home(tmpdir)

            method, cli_error = install_openclaw_plugin(plugin_dir, oc_home)

            self.assertEqual(method, "cli")
            self.assertEqual(cli_error, "")
            mock_run.assert_called_once()
            cmd = mock_run.call_args[0][0]
            self.assertEqual(cmd, ["openclaw", "plugins", "install", plugin_dir])

    def test_returns_empty_when_not_built(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_dir = os.path.join(tmpdir, "extensions", "defenseclaw")
            os.makedirs(plugin_dir)
            with open(os.path.join(plugin_dir, "package.json"), "w") as f:
                f.write("{}")

            method, _ = install_openclaw_plugin(plugin_dir, os.path.join(tmpdir, "oc"))
            self.assertEqual(method, "")

    @patch("defenseclaw.guardrail.subprocess.run", side_effect=FileNotFoundError)
    def test_reinstall_replaces_existing(self, _mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_dir = self._make_built_plugin(tmpdir)
            oc_home = self._make_oc_home(tmpdir)

            install_openclaw_plugin(plugin_dir, oc_home)

            stale = os.path.join(oc_home, "extensions", "defenseclaw", "stale.txt")
            with open(stale, "w") as f:
                f.write("old")

            install_openclaw_plugin(plugin_dir, oc_home)
            self.assertFalse(os.path.exists(stale))
            self.assertTrue(os.path.isfile(
                os.path.join(oc_home, "extensions", "defenseclaw", "dist", "index.js"),
            ))

    @patch("defenseclaw.guardrail.subprocess.run")
    def test_manual_fallback_shows_cli_error(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stderr="plugin validation failed", stdout="")
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_dir = self._make_built_plugin(tmpdir)
            oc_home = self._make_oc_home(tmpdir)

            method, cli_error = install_openclaw_plugin(plugin_dir, oc_home)

            self.assertEqual(method, "manual")
            self.assertIn("plugin validation failed", cli_error)


# ---------------------------------------------------------------------------
# uninstall_openclaw_plugin
# ---------------------------------------------------------------------------

class TestUninstallOpenclawPlugin(unittest.TestCase):
    def _make_oc_home_with_plugin(self, tmpdir):
        """Create an oc_home with extensions dir and registered config."""
        oc_home = tmpdir
        ext = os.path.join(oc_home, "extensions", "defenseclaw")
        os.makedirs(ext, exist_ok=True)
        with open(os.path.join(ext, "index.js"), "w") as f:
            f.write("// plugin")
        install_path = os.path.join(oc_home, "extensions", "defenseclaw")
        oc_config = os.path.join(oc_home, "openclaw.json")
        with open(oc_config, "w") as f:
            json.dump({
                "plugins": {
                    "allow": ["defenseclaw", "other"],
                    "entries": {"defenseclaw": {"enabled": True}},
                    "load": {"paths": [install_path]},
                    "installs": {"defenseclaw": {
                        "source": "path",
                        "installPath": install_path,
                    }},
                }
            }, f)
        return oc_home

    @patch("defenseclaw.guardrail.subprocess.run")
    def test_cli_uninstall_when_openclaw_available(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_oc_home_with_plugin(tmpdir)

            result = uninstall_openclaw_plugin(tmpdir)

            self.assertEqual(result, "cli")
            mock_run.assert_called_once()
            cmd = mock_run.call_args[0][0]
            self.assertEqual(cmd, ["openclaw", "plugins", "uninstall", "defenseclaw"])

    @patch("defenseclaw.guardrail.subprocess.run", side_effect=FileNotFoundError)
    def test_manual_fallback_removes_directory(self, _mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_oc_home_with_plugin(tmpdir)

            result = uninstall_openclaw_plugin(tmpdir)

            self.assertEqual(result, "manual")
            ext = os.path.join(tmpdir, "extensions", "defenseclaw")
            self.assertFalse(os.path.exists(ext))

    @patch("defenseclaw.guardrail.subprocess.run", side_effect=FileNotFoundError)
    def test_manual_fallback_cleans_config(self, _mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_oc_home_with_plugin(tmpdir)

            uninstall_openclaw_plugin(tmpdir)

            with open(os.path.join(tmpdir, "openclaw.json")) as f:
                cfg = json.load(f)
            plugins = cfg["plugins"]
            self.assertNotIn("defenseclaw", plugins.get("allow", []))
            self.assertNotIn("defenseclaw", plugins.get("entries", {}))
            self.assertNotIn("defenseclaw", plugins.get("installs", {}))
            self.assertEqual(plugins.get("load", {}).get("paths", []), [])

    @unittest.skipIf(
        os.name == "nt" and not os.environ.get("CI"),
        "os.symlink requires admin or Developer Mode on Windows",
    )
    @patch("defenseclaw.guardrail.subprocess.run", side_effect=FileNotFoundError)
    def test_manual_fallback_removes_symlink(self, _mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            ext_parent = os.path.join(tmpdir, "extensions")
            os.makedirs(ext_parent)
            real_dir = os.path.join(tmpdir, "real-plugin")
            os.makedirs(real_dir)
            link = os.path.join(ext_parent, "defenseclaw")
            os.symlink(real_dir, link)

            result = uninstall_openclaw_plugin(tmpdir)

            self.assertEqual(result, "manual")
            self.assertFalse(os.path.islink(link))
            self.assertTrue(os.path.isdir(real_dir))

    def test_returns_empty_when_not_installed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = uninstall_openclaw_plugin(tmpdir)
            self.assertEqual(result, "")

    @patch("defenseclaw.guardrail.subprocess.run")
    def test_cli_failure_falls_back_to_manual(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stderr="error", stdout="")
        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_oc_home_with_plugin(tmpdir)

            result = uninstall_openclaw_plugin(tmpdir)

            self.assertEqual(result, "manual")
            ext = os.path.join(tmpdir, "extensions", "defenseclaw")
            self.assertFalse(os.path.exists(ext))

    @patch("defenseclaw.guardrail.subprocess.run", side_effect=FileNotFoundError)
    def test_removes_from_plugins_allow(self, _mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_oc_home_with_plugin(tmpdir)

            uninstall_openclaw_plugin(tmpdir)

            with open(os.path.join(tmpdir, "openclaw.json")) as f:
                cfg = json.load(f)
            self.assertNotIn("defenseclaw", cfg["plugins"]["allow"])
            self.assertIn("other", cfg["plugins"]["allow"])

    @patch("defenseclaw.guardrail.subprocess.run", side_effect=FileNotFoundError)
    def test_timeout_on_cli_falls_back_to_manual(self, _mock_run):
        _mock_run.side_effect = subprocess.TimeoutExpired(cmd="openclaw", timeout=30)
        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_oc_home_with_plugin(tmpdir)

            result = uninstall_openclaw_plugin(tmpdir)

            self.assertEqual(result, "manual")
            ext = os.path.join(tmpdir, "extensions", "defenseclaw")
            self.assertFalse(os.path.exists(ext))


# ---------------------------------------------------------------------------
# OpenClaw config patching
# ---------------------------------------------------------------------------

class TestPatchOpenclawConfig(unittest.TestCase):
    def _make_openclaw_json(self, tmpdir, model="anthropic/claude-opus-4-5"):
        oc = {
            "agents": {"defaults": {"model": {"primary": model}}},
            "models": {"providers": {}},
        }
        path = os.path.join(tmpdir, "openclaw.json")
        with open(path, "w") as f:
            json.dump(oc, f)
        return path

    def test_registers_plugin_only(self):
        """patch_openclaw_config only registers the plugin — no provider, no model change."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._make_openclaw_json(tmpdir)

            prev = patch_openclaw_config(
                path, "claude-opus", 4000, "sk-dc-test", ""
            )

            self.assertEqual(prev, "anthropic/claude-opus-4-5")

            with open(path) as f:
                cfg = json.load(f)

            # No defenseclaw provider added
            self.assertNotIn("defenseclaw", cfg["models"]["providers"])

            # Primary model unchanged — fetch interceptor handles routing
            primary = cfg["agents"]["defaults"]["model"]["primary"]
            self.assertEqual(primary, "anthropic/claude-opus-4-5")

    def test_creates_backup(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._make_openclaw_json(tmpdir)
            patch_openclaw_config(path, "claude-opus", 4000, "sk-dc-test", "")
            self.assertTrue(os.path.isfile(path + ".bak"))

    def test_missing_file_returns_none(self):
        result = patch_openclaw_config("/nonexistent.json", "x", 4000, "k", "")
        self.assertIsNone(result)

    def test_adds_defenseclaw_to_plugins_allow(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._make_openclaw_json(tmpdir)

            patch_openclaw_config(path, "claude-opus", 4000, "sk-dc-test", "")

            with open(path) as f:
                cfg = json.load(f)

            self.assertIn("plugins", cfg)
            self.assertIn("defenseclaw", cfg["plugins"]["allow"])

    def test_plugins_allow_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._make_openclaw_json(tmpdir)

            patch_openclaw_config(path, "claude-opus", 4000, "sk-dc-test", "")
            patch_openclaw_config(path, "claude-opus", 4000, "sk-dc-test", "")

            with open(path) as f:
                cfg = json.load(f)

            self.assertEqual(cfg["plugins"]["allow"].count("defenseclaw"), 1)

    def test_model_name_unused(self):
        """model_name parameter is accepted but no longer used."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._make_openclaw_json(tmpdir)
            result = patch_openclaw_config(path, "", 4000, "sk-dc-test", "")
            # Should succeed without error regardless of empty model_name
            self.assertIsNotNone(result)


class TestRestoreOpenclawConfig(unittest.TestCase):
    def test_removes_plugin_and_legacy_providers(self):
        """restore_openclaw_config removes plugin entries and any legacy provider entries."""
        with tempfile.TemporaryDirectory() as tmpdir:
            oc = {
                "agents": {"defaults": {"model": {"primary": "anthropic/claude-opus"}}},
                "models": {"providers": {
                    "litellm": {"baseUrl": "http://localhost:4000"},
                    "defenseclaw": {"baseUrl": "http://localhost:4000"},
                    "anthropic": {"apiKey": "..."},
                }},
                "plugins": {
                    "allow": ["defenseclaw"],
                    "entries": {"defenseclaw": {"enabled": True}},
                },
            }
            path = os.path.join(tmpdir, "openclaw.json")
            with open(path, "w") as f:
                json.dump(oc, f)

            result = restore_openclaw_config(path, "anthropic/claude-opus-4-5")
            self.assertTrue(result)

            with open(path) as f:
                cfg = json.load(f)

            # Plugin removed from all plugin sections
            self.assertNotIn("defenseclaw", cfg["plugins"]["allow"])
            self.assertFalse(cfg["plugins"]["entries"]["defenseclaw"]["enabled"])
            # Legacy provider entries removed
            self.assertNotIn("litellm", cfg["models"]["providers"])
            self.assertNotIn("defenseclaw", cfg["models"]["providers"])
            # Real providers untouched
            self.assertIn("anthropic", cfg["models"]["providers"])
            # Primary model unchanged (was never touched by setup)
            self.assertEqual(cfg["agents"]["defaults"]["model"]["primary"], "anthropic/claude-opus")


# ---------------------------------------------------------------------------
# restore_openclaw_config edge cases
# ---------------------------------------------------------------------------

class TestRestoreOpenclawConfigEdgeCases(unittest.TestCase):
    def test_missing_file_returns_false(self):
        result = restore_openclaw_config("/nonexistent/openclaw.json", "anthropic/claude-opus-4-5")
        self.assertFalse(result)

    def test_malformed_json_returns_false(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "openclaw.json")
            with open(path, "w") as f:
                f.write("not valid json{{{")
            result = restore_openclaw_config(path, "anthropic/claude-opus-4-5")
            self.assertFalse(result)

    def test_creates_backup_before_restoring(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            oc = {
                "agents": {"defaults": {"model": {"primary": "defenseclaw/claude-opus"}}},
                "models": {"providers": {"litellm": {}}},
            }
            path = os.path.join(tmpdir, "openclaw.json")
            with open(path, "w") as f:
                json.dump(oc, f)

            restore_openclaw_config(path, "anthropic/claude-opus-4-5")
            self.assertTrue(os.path.isfile(path + ".bak"))

    def test_no_plugins_section_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            oc = {
                "agents": {"defaults": {"model": {"primary": "defenseclaw/claude-opus"}}},
                "models": {"providers": {}},
            }
            path = os.path.join(tmpdir, "openclaw.json")
            with open(path, "w") as f:
                json.dump(oc, f)

            result = restore_openclaw_config(path, "anthropic/claude-opus-4-5")
            self.assertTrue(result)


# ---------------------------------------------------------------------------
# _remove_from_plugins_allow
# ---------------------------------------------------------------------------

class TestRemoveFromPluginsAllow(unittest.TestCase):
    def test_removes_plugin_id(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "openclaw.json")
            with open(path, "w") as f:
                json.dump({"plugins": {"allow": ["defenseclaw", "other-plugin"]}}, f)

            _remove_from_plugins_allow(path, "defenseclaw")

            with open(path) as f:
                cfg = json.load(f)
            self.assertNotIn("defenseclaw", cfg["plugins"]["allow"])
            self.assertIn("other-plugin", cfg["plugins"]["allow"])

    def test_no_op_when_plugin_not_in_allow(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "openclaw.json")
            with open(path, "w") as f:
                json.dump({"plugins": {"allow": ["other-plugin"]}}, f)

            _remove_from_plugins_allow(path, "defenseclaw")

            with open(path) as f:
                cfg = json.load(f)
            self.assertEqual(cfg["plugins"]["allow"], ["other-plugin"])

    def test_no_op_when_no_plugins_section(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "openclaw.json")
            with open(path, "w") as f:
                json.dump({"agents": {}}, f)

            _remove_from_plugins_allow(path, "defenseclaw")

            with open(path) as f:
                cfg = json.load(f)
            self.assertNotIn("plugins", cfg)

    def test_no_op_when_file_missing(self):
        _remove_from_plugins_allow("/nonexistent/openclaw.json", "defenseclaw")

    def test_no_op_when_json_malformed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "openclaw.json")
            with open(path, "w") as f:
                f.write("{bad json")
            _remove_from_plugins_allow(path, "defenseclaw")


# ---------------------------------------------------------------------------
# _register_plugin_in_config / _unregister_plugin_from_config
# ---------------------------------------------------------------------------

class TestRegisterPluginInConfig(unittest.TestCase):
    def test_registers_all_entries(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            oc_config = os.path.join(tmpdir, "openclaw.json")
            with open(oc_config, "w") as f:
                json.dump({"plugins": {}}, f)

            source = os.path.join(tmpdir, "source")
            os.makedirs(source)
            with open(os.path.join(source, "package.json"), "w") as f:
                json.dump({"version": "0.2.0"}, f)

            _register_plugin_in_config(oc_config, source)

            with open(oc_config) as f:
                cfg = json.load(f)
            plugins = cfg["plugins"]
            self.assertTrue(plugins["entries"]["defenseclaw"]["enabled"])
            install_path = os.path.join(tmpdir, "extensions", "defenseclaw")
            self.assertIn(install_path, plugins["load"]["paths"])
            self.assertEqual(plugins["installs"]["defenseclaw"]["version"], "0.2.0")
            self.assertEqual(plugins["installs"]["defenseclaw"]["installPath"], install_path)

    def test_idempotent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            oc_config = os.path.join(tmpdir, "openclaw.json")
            with open(oc_config, "w") as f:
                json.dump({"plugins": {}}, f)

            source = os.path.join(tmpdir, "source")
            os.makedirs(source)
            with open(os.path.join(source, "package.json"), "w") as f:
                json.dump({"version": "1.0.0"}, f)

            _register_plugin_in_config(oc_config, source)
            _register_plugin_in_config(oc_config, source)

            with open(oc_config) as f:
                cfg = json.load(f)
            install_path = os.path.join(tmpdir, "extensions", "defenseclaw")
            self.assertEqual(cfg["plugins"]["load"]["paths"].count(install_path), 1)

    def test_no_op_on_missing_file(self):
        _register_plugin_in_config("/nonexistent/openclaw.json", "/tmp/source")


class TestUnregisterPluginFromConfig(unittest.TestCase):
    def test_removes_all_entries(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            install_path = os.path.join(tmpdir, "extensions", "defenseclaw")
            oc_config = os.path.join(tmpdir, "openclaw.json")
            with open(oc_config, "w") as f:
                json.dump({
                    "plugins": {
                        "entries": {"defenseclaw": {"enabled": True}, "other": {"enabled": True}},
                        "load": {"paths": [install_path, "/other/path"]},
                        "installs": {"defenseclaw": {"installPath": install_path}},
                    }
                }, f)

            _unregister_plugin_from_config(oc_config)

            with open(oc_config) as f:
                cfg = json.load(f)
            plugins = cfg["plugins"]
            self.assertNotIn("defenseclaw", plugins["entries"])
            self.assertIn("other", plugins["entries"])
            self.assertNotIn(install_path, plugins["load"]["paths"])
            self.assertIn("/other/path", plugins["load"]["paths"])
            self.assertNotIn("defenseclaw", plugins["installs"])

    def test_no_op_when_not_registered(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            oc_config = os.path.join(tmpdir, "openclaw.json")
            with open(oc_config, "w") as f:
                json.dump({"plugins": {"entries": {"other": {"enabled": True}}}}, f)

            _unregister_plugin_from_config(oc_config)

            with open(oc_config) as f:
                cfg = json.load(f)
            self.assertIn("other", cfg["plugins"]["entries"])

    def test_no_op_on_missing_file(self):
        _unregister_plugin_from_config("/nonexistent/openclaw.json")


# ---------------------------------------------------------------------------
# _derive_master_key
# ---------------------------------------------------------------------------

class TestDeriveMasterKey(unittest.TestCase):
    def test_derives_from_device_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key_file = os.path.join(tmpdir, "device.key")
            with open(key_file, "wb") as f:
                f.write(b"test-device-key-data")

            key = _derive_master_key(key_file)
            self.assertTrue(key.startswith("sk-dc-"))
            self.assertEqual(len(key), 6 + 32)  # HMAC-SHA256 → 32 hex chars

    def test_deterministic(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key_file = os.path.join(tmpdir, "device.key")
            with open(key_file, "wb") as f:
                f.write(b"stable-content")

            key1 = _derive_master_key(key_file)
            key2 = _derive_master_key(key_file)
            self.assertEqual(key1, key2)

    @patch("defenseclaw.guardrail.Path")
    def test_raises_when_file_missing(self, mock_path):
        mock_path.home.return_value = Path("/nonexistent-home")
        with self.assertRaises(RuntimeError):
            _derive_master_key("/nonexistent/device.key")


# ---------------------------------------------------------------------------
# _backup
# ---------------------------------------------------------------------------

class TestBackup(unittest.TestCase):
    def test_creates_bak_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "config.json")
            with open(path, "w") as f:
                f.write("original")

            _backup(path)
            self.assertTrue(os.path.isfile(path + ".bak"))
            with open(path + ".bak") as f:
                self.assertEqual(f.read(), "original")

    def test_numbered_backup_when_bak_exists(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "config.json")
            with open(path, "w") as f:
                f.write("v1")
            _backup(path)

            with open(path, "w") as f:
                f.write("v2")
            _backup(path)

            self.assertTrue(os.path.isfile(path + ".bak"))
            self.assertTrue(os.path.isfile(path + ".bak.1"))

    def test_no_op_when_file_missing(self):
        _backup("/nonexistent/config.json")


# ---------------------------------------------------------------------------
# detect_current_model edge cases
# ---------------------------------------------------------------------------

class TestDetectCurrentModelEdgeCases(unittest.TestCase):
    def test_malformed_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "openclaw.json")
            with open(path, "w") as f:
                f.write("{bad json!!}")
            model, provider = detect_current_model(path)
            self.assertEqual(model, "")
            self.assertEqual(provider, "")

    def test_empty_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "openclaw.json")
            with open(path, "w") as f:
                json.dump({}, f)
            model, provider = detect_current_model(path)
            self.assertEqual(model, "")
            self.assertEqual(provider, "")

    def test_model_without_slash(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "openclaw.json")
            oc = {"agents": {"defaults": {"model": {"primary": "claude-sonnet"}}}}
            with open(path, "w") as f:
                json.dump(oc, f)
            model, provider = detect_current_model(path)
            self.assertEqual(model, "claude-sonnet")
            self.assertEqual(provider, "")


# ---------------------------------------------------------------------------
# detect_api_key_env edge cases
# ---------------------------------------------------------------------------

class TestDetectApiKeyEnvEdgeCases(unittest.TestCase):
    def test_bedrock(self):
        self.assertEqual(detect_api_key_env("bedrock/llama-3.1-70b"), "AWS_ACCESS_KEY_ID")

    def test_o1_model(self):
        self.assertEqual(detect_api_key_env("openai/o1-preview"), "OPENAI_API_KEY")


# ---------------------------------------------------------------------------
# install_openclaw_plugin edge cases
# ---------------------------------------------------------------------------

class TestInstallOpenclawPluginEdgeCases(unittest.TestCase):
    def _make_built_plugin(self, tmpdir):
        plugin_dir = os.path.join(tmpdir, "extensions", "defenseclaw")
        dist_dir = os.path.join(plugin_dir, "dist")
        os.makedirs(dist_dir)
        with open(os.path.join(plugin_dir, "package.json"), "w") as f:
            json.dump({"name": "defenseclaw", "main": "dist/index.js"}, f)
        with open(os.path.join(plugin_dir, "openclaw.plugin.json"), "w") as f:
            json.dump({"id": "defenseclaw"}, f)
        with open(os.path.join(dist_dir, "index.js"), "w") as f:
            f.write("// compiled plugin\n")
        return plugin_dir

    def _make_oc_home(self, tmpdir):
        oc_home = os.path.join(tmpdir, "openclaw-home")
        os.makedirs(oc_home)
        with open(os.path.join(oc_home, "openclaw.json"), "w") as f:
            json.dump({"plugins": {}}, f)
        return oc_home

    @patch("defenseclaw.guardrail.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="openclaw", timeout=60))
    def test_cli_timeout_falls_back_to_manual(self, _mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_dir = self._make_built_plugin(tmpdir)
            oc_home = self._make_oc_home(tmpdir)

            method, cli_error = install_openclaw_plugin(plugin_dir, oc_home)

            self.assertEqual(method, "manual")
            self.assertIn("timed out", cli_error)

    @patch("defenseclaw.guardrail.subprocess.run", side_effect=FileNotFoundError)
    @patch("defenseclaw.guardrail.shutil.copytree", side_effect=OSError("permission denied"))
    def test_manual_copy_failure_returns_error(self, _mock_copy, _mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_dir = self._make_built_plugin(tmpdir)
            oc_home = self._make_oc_home(tmpdir)

            method, cli_error = install_openclaw_plugin(plugin_dir, oc_home)

            self.assertEqual(method, "error")
            self.assertIn("manual copy failed", cli_error)

    @patch("defenseclaw.guardrail.subprocess.run", side_effect=FileNotFoundError)
    def test_manual_copy_without_node_modules(self, _mock_run):
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_dir = self._make_built_plugin(tmpdir)
            oc_home = self._make_oc_home(tmpdir)

            method, _ = install_openclaw_plugin(plugin_dir, oc_home)

            self.assertEqual(method, "manual")
            target = os.path.join(oc_home, "extensions", "defenseclaw")
            self.assertTrue(os.path.isfile(os.path.join(target, "dist", "index.js")))
            self.assertFalse(os.path.isdir(os.path.join(target, "node_modules")))


# ---------------------------------------------------------------------------
# setup guardrail CLI command
# ---------------------------------------------------------------------------

class TestSetupGuardrailCommand(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()
        self.oc_path = os.path.join(self.tmp_dir, "openclaw.json")
        oc = {
            "agents": {"defaults": {"model": {"primary": "anthropic/claude-opus-4-5"}}},
            "models": {"providers": {}},
        }
        with open(self.oc_path, "w") as f:
            json.dump(oc, f)
        self.app.cfg.claw.config_file = self.oc_path
        self.app.cfg.gateway.device_key_file = os.path.join(self.tmp_dir, "device.key")
        with open(self.app.cfg.gateway.device_key_file, "wb") as f:
            f.write(b"test-device-key")
        dotenv_path = os.path.join(self.tmp_dir, ".env")
        with open(dotenv_path, "w") as f:
            f.write("ANTHROPIC_API_KEY=test-key-for-tests\n")

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def test_help(self):
        from defenseclaw.commands.cmd_setup import setup
        result = self.runner.invoke(setup, ["guardrail", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("guardrail", result.output)

    def test_disable_when_not_enabled(self):
        from defenseclaw.commands.cmd_setup import setup
        self.app.cfg.claw.home_dir = self.tmp_dir
        result = self.runner.invoke(setup, ["guardrail", "--disable"], obj=self.app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Disabling", result.output)
        self.assertIn("OpenClaw plugin removed", result.output)

    def test_non_interactive_with_model(self):
        from defenseclaw.commands.cmd_setup import setup
        self.app.cfg.guardrail.model = "anthropic/claude-opus-4-5"
        self.app.cfg.guardrail.model_name = "claude-opus"
        self.app.cfg.guardrail.api_key_env = "ANTHROPIC_API_KEY"
        self.app.cfg.claw.home_dir = self.tmp_dir
        result = self.runner.invoke(
            setup,
            ["guardrail", "--non-interactive", "--mode", "observe"],
            obj=self.app,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Guardrail proxy is built into the Go binary", result.output)
        self.assertIn("Config saved", result.output)

        import yaml
        with open(os.path.join(self.tmp_dir, "config.yaml")) as f:
            raw = yaml.safe_load(f)
        self.assertTrue(raw["guardrail"]["enabled"])
        self.assertEqual(raw["guardrail"]["mode"], "observe")

    def test_preflight_aborts_when_openclaw_config_missing(self):
        from defenseclaw.commands.cmd_setup import setup
        self.app.cfg.guardrail.model = "anthropic/claude-opus-4-5"
        self.app.cfg.guardrail.model_name = "claude-opus"
        self.app.cfg.guardrail.api_key_env = "ANTHROPIC_API_KEY"
        self.app.cfg.claw.config_file = "/nonexistent/openclaw.json"
        self.app.cfg.claw.home_dir = self.tmp_dir
        result = self.runner.invoke(
            setup,
            ["guardrail", "--non-interactive", "--mode", "observe"],
            obj=self.app,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("OpenClaw config not found", result.output)
        self.assertIn("Make sure OpenClaw is installed", result.output)
        self.assertNotIn("Guardrail proxy is built into the Go binary", result.output)

    def test_preflight_succeeds_with_empty_model(self):
        """Model is no longer required — fetch interceptor scans all models."""
        from defenseclaw.commands.cmd_setup import setup
        self.app.cfg.guardrail.model = ""
        self.app.cfg.guardrail.model_name = ""
        self.app.cfg.claw.home_dir = self.tmp_dir
        result = self.runner.invoke(
            setup,
            ["guardrail", "--non-interactive", "--mode", "observe"],
            obj=self.app,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        # Setup proceeds without model — all models scanned automatically
        self.assertIn("Guardrail proxy is built into the Go binary", result.output)

    def test_api_key_env_warning_when_not_set(self):
        from defenseclaw.commands.cmd_setup import setup
        self.app.cfg.guardrail.model = "anthropic/claude-opus-4-5"
        self.app.cfg.guardrail.model_name = "claude-opus"
        self.app.cfg.guardrail.api_key_env = "DEFENSECLAW_TEST_KEY_NOTSET_12345"
        self.app.cfg.claw.home_dir = self.tmp_dir
        dotenv_path = os.path.join(self.tmp_dir, ".env")
        with open(dotenv_path, "w") as f:
            f.write("DEFENSECLAW_TEST_KEY_NOTSET_12345=test-val\n")
        result = self.runner.invoke(
            setup,
            ["guardrail", "--non-interactive", "--mode", "observe"],
            obj=self.app,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Guardrail proxy is built into the Go binary", result.output)

    def test_openclaw_config_patched_output(self):
        from defenseclaw.commands.cmd_setup import setup
        self.app.cfg.guardrail.model = "anthropic/claude-opus-4-5"
        self.app.cfg.guardrail.model_name = "claude-opus"
        self.app.cfg.guardrail.api_key_env = "ANTHROPIC_API_KEY"
        self.app.cfg.claw.home_dir = self.tmp_dir
        result = self.runner.invoke(
            setup,
            ["guardrail", "--non-interactive", "--mode", "observe"],
            obj=self.app,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("OpenClaw config patched", result.output)
        self.assertIn("Original model saved for revert", result.output)

    def test_shows_disable_instructions(self):
        from defenseclaw.commands.cmd_setup import setup
        self.app.cfg.guardrail.model = "anthropic/claude-opus-4-5"
        self.app.cfg.guardrail.model_name = "claude-opus"
        self.app.cfg.guardrail.api_key_env = "ANTHROPIC_API_KEY"

        self.app.cfg.claw.home_dir = self.tmp_dir
        result = self.runner.invoke(
            setup,
            ["guardrail", "--non-interactive", "--mode", "observe"],
            obj=self.app,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("defenseclaw setup guardrail --disable", result.output)

    def test_block_message_non_interactive(self):
        from defenseclaw.commands.cmd_setup import setup
        self.app.cfg.guardrail.model = "anthropic/claude-opus-4-5"
        self.app.cfg.guardrail.model_name = "claude-opus"
        self.app.cfg.guardrail.api_key_env = "ANTHROPIC_API_KEY"

        self.app.cfg.claw.home_dir = self.tmp_dir
        custom_msg = "Blocked by policy. Contact security@acme.com."
        result = self.runner.invoke(
            setup,
            ["guardrail", "--non-interactive", "--mode", "action",
             "--block-message", custom_msg],
            obj=self.app,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("block_message", result.output)
        self.assertIn("Blocked by policy", result.output)

        import yaml
        with open(os.path.join(self.tmp_dir, "config.yaml")) as f:
            raw = yaml.safe_load(f)
        self.assertEqual(raw["guardrail"]["block_message"], custom_msg)

    def test_block_message_written_to_runtime_json(self):
        from defenseclaw.commands.cmd_setup import setup
        self.app.cfg.guardrail.model = "anthropic/claude-opus-4-5"
        self.app.cfg.guardrail.model_name = "claude-opus"
        self.app.cfg.guardrail.api_key_env = "ANTHROPIC_API_KEY"

        self.app.cfg.claw.home_dir = self.tmp_dir
        custom_msg = "Custom block message for testing."
        result = self.runner.invoke(
            setup,
            ["guardrail", "--non-interactive", "--mode", "action",
             "--block-message", custom_msg],
            obj=self.app,
        )
        self.assertEqual(result.exit_code, 0, result.output)

        runtime_file = os.path.join(self.tmp_dir, "guardrail_runtime.json")
        self.assertTrue(os.path.isfile(runtime_file))
        with open(runtime_file) as f:
            runtime = json.load(f)
        self.assertEqual(runtime["block_message"], custom_msg)
        self.assertEqual(runtime["mode"], "action")

    def test_block_message_empty_by_default_in_runtime_json(self):
        from defenseclaw.commands.cmd_setup import setup
        self.app.cfg.guardrail.model = "anthropic/claude-opus-4-5"
        self.app.cfg.guardrail.model_name = "claude-opus"
        self.app.cfg.guardrail.api_key_env = "ANTHROPIC_API_KEY"

        self.app.cfg.claw.home_dir = self.tmp_dir
        result = self.runner.invoke(
            setup,
            ["guardrail", "--non-interactive", "--mode", "observe"],
            obj=self.app,
        )
        self.assertEqual(result.exit_code, 0, result.output)

        runtime_file = os.path.join(self.tmp_dir, "guardrail_runtime.json")
        self.assertTrue(os.path.isfile(runtime_file))
        with open(runtime_file) as f:
            runtime = json.load(f)
        self.assertEqual(runtime["block_message"], "")

    def test_help_shows_block_message_option(self):
        from defenseclaw.commands.cmd_setup import setup
        result = self.runner.invoke(setup, ["guardrail", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("--block-message", result.output)


# ---------------------------------------------------------------------------
# Service restart helpers
# ---------------------------------------------------------------------------

class TestIsPidAlive(unittest.TestCase):
    def test_no_file(self):
        from defenseclaw.commands.cmd_setup import _is_pid_alive
        self.assertFalse(_is_pid_alive("/nonexistent/gateway.pid"))

    def test_stale_pid(self):
        from defenseclaw.commands.cmd_setup import _is_pid_alive
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pid", delete=False) as f:
            f.write("999999999")
            f.flush()
            self.assertFalse(_is_pid_alive(f.name))
        os.unlink(f.name)

    def test_own_pid(self):
        from defenseclaw.commands.cmd_setup import _is_pid_alive
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pid", delete=False) as f:
            f.write(str(os.getpid()))
            f.flush()
            self.assertTrue(_is_pid_alive(f.name))
        os.unlink(f.name)

    def test_bad_content(self):
        from defenseclaw.commands.cmd_setup import _is_pid_alive
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pid", delete=False) as f:
            f.write("not-a-number")
            f.flush()
            self.assertFalse(_is_pid_alive(f.name))
        os.unlink(f.name)

    def test_json_pid_own_process(self):
        from defenseclaw.commands.cmd_setup import _is_pid_alive
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pid", delete=False) as f:
            json.dump({"pid": os.getpid(), "executable": "/usr/bin/test", "start_time": 0}, f)
            f.flush()
            self.assertTrue(_is_pid_alive(f.name))
        os.unlink(f.name)

    def test_json_pid_stale_process(self):
        from defenseclaw.commands.cmd_setup import _is_pid_alive
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pid", delete=False) as f:
            json.dump({"pid": 999999999, "executable": "/usr/bin/test", "start_time": 0}, f)
            f.flush()
            self.assertFalse(_is_pid_alive(f.name))
        os.unlink(f.name)


class TestRestartDefenseGateway(unittest.TestCase):
    @patch("defenseclaw.commands.cmd_setup.subprocess.run")
    def test_starts_when_not_running(self, mock_run):
        from defenseclaw.commands.cmd_setup import _restart_defense_gateway
        mock_run.return_value = MagicMock(returncode=0)

        with tempfile.TemporaryDirectory() as tmpdir:
            _restart_defense_gateway(tmpdir)
            mock_run.assert_called_once()
            cmd = mock_run.call_args[0][0]
            self.assertEqual(cmd, ["defenseclaw-gateway", "start"])

    @patch("defenseclaw.commands.cmd_setup.subprocess.run")
    def test_restarts_when_running(self, mock_run):
        from defenseclaw.commands.cmd_setup import _restart_defense_gateway
        mock_run.return_value = MagicMock(returncode=0)

        with tempfile.TemporaryDirectory() as tmpdir:
            pid_file = os.path.join(tmpdir, "gateway.pid")
            with open(pid_file, "w") as f:
                f.write(str(os.getpid()))

            _restart_defense_gateway(tmpdir)
            mock_run.assert_called_once()
            cmd = mock_run.call_args[0][0]
            self.assertEqual(cmd, ["defenseclaw-gateway", "restart"])

    @patch("defenseclaw.commands.cmd_setup.subprocess.run", side_effect=FileNotFoundError)
    def test_binary_not_found(self, mock_run):
        from defenseclaw.commands.cmd_setup import _restart_defense_gateway
        with tempfile.TemporaryDirectory() as tmpdir:
            _restart_defense_gateway(tmpdir)


class TestCheckOpenclawGateway(unittest.TestCase):
    def _fast_monotonic(self, step=5):
        """Return a side_effect that advances time by *step* seconds per call."""
        t = [0.0]
        def _tick():
            val = t[0]
            t[0] += step
            return val
        return _tick

    @patch("time.sleep")
    @patch("time.monotonic")
    @patch("defenseclaw.commands.cmd_setup._openclaw_gateway_healthy", return_value=True)
    def test_reports_healthy(self, mock_healthy, mock_monotonic, mock_sleep):
        from defenseclaw.commands.cmd_setup import _check_openclaw_gateway
        mock_monotonic.side_effect = self._fast_monotonic(step=10)
        _check_openclaw_gateway("10.0.0.5", 19000)
        self.assertTrue(mock_healthy.call_count >= 1)
        mock_healthy.assert_any_call("10.0.0.5", 19000)

    @patch("time.sleep")
    @patch("time.monotonic")
    @patch("defenseclaw.commands.cmd_setup._openclaw_gateway_healthy", return_value=False)
    def test_reports_not_running_after_retries(self, mock_healthy, mock_monotonic, mock_sleep):
        from defenseclaw.commands.cmd_setup import _check_openclaw_gateway
        mock_monotonic.side_effect = self._fast_monotonic(step=5)
        _check_openclaw_gateway("127.0.0.1", 18789)
        self.assertTrue(mock_healthy.call_count >= 2)

    @patch("time.sleep")
    @patch("time.monotonic")
    @patch("defenseclaw.commands.cmd_setup._openclaw_gateway_healthy",
           side_effect=[False, False, True] + [True] * 20)
    def test_retries_until_healthy(self, mock_healthy, mock_monotonic, mock_sleep):
        from defenseclaw.commands.cmd_setup import _check_openclaw_gateway
        mock_monotonic.side_effect = self._fast_monotonic(step=5)
        _check_openclaw_gateway("127.0.0.1", 18789)
        self.assertTrue(mock_healthy.call_count >= 3)
        mock_sleep.assert_called_with(3)


class TestSetupGuardrailRestart(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()
        self.oc_path = os.path.join(self.tmp_dir, "openclaw.json")
        oc = {
            "agents": {"defaults": {"model": {"primary": "anthropic/claude-opus-4-5"}}},
            "models": {"providers": {}},
        }
        with open(self.oc_path, "w") as f:
            json.dump(oc, f)
        self.app.cfg.claw.config_file = self.oc_path
        self.app.cfg.claw.home_dir = self.tmp_dir
        self.app.cfg.gateway.device_key_file = os.path.join(self.tmp_dir, "device.key")
        with open(self.app.cfg.gateway.device_key_file, "wb") as f:
            f.write(b"test-device-key")
        self.app.cfg.guardrail.model = "anthropic/claude-opus-4-5"
        self.app.cfg.guardrail.model_name = "claude-opus"
        self.app.cfg.guardrail.api_key_env = "ANTHROPIC_API_KEY"

        dotenv_path = os.path.join(self.tmp_dir, ".env")
        with open(dotenv_path, "w") as f:
            f.write("ANTHROPIC_API_KEY=test-key-for-tests\n")

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def test_without_restart_shows_manual_instructions(self):
        from defenseclaw.commands.cmd_setup import setup
        result = self.runner.invoke(
            setup,
            ["guardrail", "--non-interactive", "--mode", "observe"],
            obj=self.app,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        # Setup shows restart instructions when --restart not passed
        self.assertIn("defenseclaw-gateway restart", result.output)
        self.assertIn("--restart", result.output)

    @patch("defenseclaw.commands.cmd_setup._restart_services")
    def test_with_restart_calls_restart_services(self, mock_restart):
        from defenseclaw.commands.cmd_setup import setup
        result = self.runner.invoke(
            setup,
            ["guardrail", "--non-interactive", "--mode", "observe", "--restart"],
            obj=self.app,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        mock_restart.assert_called_once()
        self.assertNotIn("Restart services for changes to take effect", result.output)

    def test_disable_restarts_openclaw(self):
        """Disabling always restarts OpenClaw gateway to unload the plugin."""
        from defenseclaw.commands.cmd_setup import setup
        self.app.cfg.guardrail.enabled = True
        self.app.cfg.guardrail.original_model = "anthropic/claude-opus-4-5"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = self.runner.invoke(
                setup,
                ["guardrail", "--disable"],
                obj=self.app,
            )
        self.assertEqual(result.exit_code, 0, result.output)
        # Verify openclaw gateway restart was attempted
        calls = [str(c) for c in mock_run.call_args_list]
        self.assertTrue(
            any("openclaw" in c and "gateway" in c and "restart" in c for c in calls),
            f"Expected openclaw gateway restart call. Got: {calls}"
        )
        self.assertIn("OpenClaw gateway restarted", result.output)

    def test_disable_without_restart_shows_instructions(self):
        """--disable always restarts OpenClaw; no separate --restart flag needed."""
        from defenseclaw.commands.cmd_setup import setup
        self.app.cfg.guardrail.enabled = True
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = self.runner.invoke(
                setup,
                ["guardrail", "--disable"],
                obj=self.app,
            )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("OpenClaw plugin removed", result.output)
        self.assertIn("Restarting OpenClaw gateway", result.output)

    def test_help_shows_restart_option(self):
        from defenseclaw.commands.cmd_setup import setup
        result = self.runner.invoke(setup, ["guardrail", "--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("--restart", result.output)


# ---------------------------------------------------------------------------
# Disable guardrail flow
# ---------------------------------------------------------------------------

class TestDisableGuardrailFlow(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()
        self.oc_path = os.path.join(self.tmp_dir, "openclaw.json")
        oc = {
            "agents": {"defaults": {"model": {"primary": "defenseclaw/claude-opus"}}},
            "models": {"providers": {
                "litellm": {"baseUrl": "http://localhost:4000"},
                "anthropic": {"apiKey": "..."},
            }},
            "plugins": {"allow": ["defenseclaw"]},
        }
        with open(self.oc_path, "w") as f:
            json.dump(oc, f)
        self.app.cfg.claw.config_file = self.oc_path
        self.app.cfg.claw.home_dir = self.tmp_dir
        self.app.cfg.guardrail.enabled = True
        self.app.cfg.guardrail.original_model = "anthropic/claude-opus-4-5"

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def test_successful_restore_with_original_model(self):
        from defenseclaw.commands.cmd_setup import setup
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = self.runner.invoke(
                setup, ["guardrail", "--disable"], obj=self.app,
            )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Config saved", result.output)
        self.assertNotIn("Manual steps required", result.output)

        with open(self.oc_path) as f:
            cfg = json.load(f)
        # Primary model untouched — setup no longer changes it
        self.assertNotIn("litellm", cfg["models"]["providers"])
        # Plugin removed
        self.assertNotIn("defenseclaw", cfg.get("plugins", {}).get("allow", []))

    def test_restore_failure_shows_manual_steps(self):
        from defenseclaw.commands.cmd_setup import setup
        self.app.cfg.claw.config_file = "/nonexistent/openclaw.json"
        result = self.runner.invoke(
            setup, ["guardrail", "--disable"], obj=self.app,
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Could not update OpenClaw config", result.output)
        self.assertIn("Manual steps required", result.output)
        self.assertIn("Manually remove defenseclaw", result.output)

    def test_uninstalls_plugin_during_disable(self):
        from unittest.mock import patch
        from defenseclaw.commands.cmd_setup import setup
        ext = os.path.join(self.tmp_dir, "extensions", "defenseclaw")
        os.makedirs(ext)
        with open(os.path.join(ext, "index.js"), "w") as f:
            f.write("// plugin")

        with patch("defenseclaw.guardrail.subprocess.run", side_effect=FileNotFoundError):
            result = self.runner.invoke(
                setup, ["guardrail", "--disable"], obj=self.app,
            )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("plugin removed from extensions", result.output)
        self.assertFalse(os.path.exists(ext))

    def test_no_original_model_still_disables(self):
        """Disable works without original_model since we no longer change the model."""
        from defenseclaw.commands.cmd_setup import setup
        self.app.cfg.guardrail.original_model = ""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = self.runner.invoke(
                setup, ["guardrail", "--disable"], obj=self.app,
            )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("OpenClaw plugin removed", result.output)
        self.assertIn("Restarting OpenClaw gateway", result.output)

    def test_disable_sets_enabled_false(self):
        from defenseclaw.commands.cmd_setup import setup
        self.assertTrue(self.app.cfg.guardrail.enabled)
        self.runner.invoke(
            setup, ["guardrail", "--disable"], obj=self.app,
        )
        self.assertFalse(self.app.cfg.guardrail.enabled)


# ---------------------------------------------------------------------------
# Restart helper edge cases
# ---------------------------------------------------------------------------

class TestRestartDefenseGatewayEdgeCases(unittest.TestCase):
    @patch("defenseclaw.commands.cmd_setup.subprocess.run")
    def test_nonzero_exit_shows_stderr(self, mock_run):
        from defenseclaw.commands.cmd_setup import _restart_defense_gateway
        mock_run.return_value = MagicMock(
            returncode=1, stderr="bind: address already in use\nfailed to start", stdout="",
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            _restart_defense_gateway(tmpdir)
        mock_run.assert_called_once()

    @patch("defenseclaw.commands.cmd_setup.subprocess.run",
           side_effect=subprocess.TimeoutExpired(cmd="defenseclaw-gateway", timeout=30))
    def test_timeout(self, _mock_run):
        from defenseclaw.commands.cmd_setup import _restart_defense_gateway
        with tempfile.TemporaryDirectory() as tmpdir:
            _restart_defense_gateway(tmpdir)


class TestCheckOpenclawGatewayEdgeCases(unittest.TestCase):
    def test_healthy_uses_configured_host_and_port(self):
        from defenseclaw.commands.cmd_setup import _openclaw_gateway_healthy
        with patch("urllib.request.urlopen") as mock_open:
            mock_resp = MagicMock(status=200)
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_open.return_value = mock_resp
            result = _openclaw_gateway_healthy("10.0.0.5", 19000)
            self.assertTrue(result)
            req = mock_open.call_args[0][0]
            self.assertEqual(req.full_url, "http://10.0.0.5:19000/health")

    def test_healthy_returns_false_on_connection_error(self):
        from defenseclaw.commands.cmd_setup import _openclaw_gateway_healthy
        result = _openclaw_gateway_healthy("127.0.0.1", 1)
        self.assertFalse(result)


# ---------------------------------------------------------------------------
# _looks_like_secret helper
# ---------------------------------------------------------------------------

class TestLooksLikeSecret(unittest.TestCase):
    def test_api_key_prefixes(self):
        from defenseclaw.commands.cmd_setup import _looks_like_secret
        self.assertTrue(_looks_like_secret("sk-ant-api03-abc123"))
        self.assertTrue(_looks_like_secret("sk-proj-abc"))
        self.assertTrue(_looks_like_secret("ghp_1234567890abcdef"))

    def test_long_non_uppercase(self):
        from defenseclaw.commands.cmd_setup import _looks_like_secret
        self.assertTrue(_looks_like_secret("a" * 40))

    def test_env_var_name(self):
        from defenseclaw.commands.cmd_setup import _looks_like_secret
        self.assertFalse(_looks_like_secret("ANTHROPIC_API_KEY"))
        self.assertFalse(_looks_like_secret("OPENAI_API_KEY"))
        self.assertFalse(_looks_like_secret(""))

    def test_short_harmless(self):
        from defenseclaw.commands.cmd_setup import _looks_like_secret
        self.assertFalse(_looks_like_secret("MY_KEY"))


# ---------------------------------------------------------------------------
# init guardrail install
# ---------------------------------------------------------------------------

class TestInitGuardrailInstall(unittest.TestCase):
    def test_install_guardrail_reports_builtin(self):
        from defenseclaw.commands.cmd_init import _install_guardrail
        cfg = default_config()
        logger = MagicMock()

        _install_guardrail(cfg, logger, skip=False)
        logger.log_action.assert_called_once_with("install-dep", "guardrail", "builtin")

    def test_install_guardrail_skip_flag(self):
        from defenseclaw.commands.cmd_init import _install_guardrail
        cfg = default_config()
        logger = MagicMock()

        _install_guardrail(cfg, logger, skip=True)
        logger.log_action.assert_not_called()


if __name__ == "__main__":
    unittest.main()
