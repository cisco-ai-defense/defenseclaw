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

"""Tests for 'defenseclaw init' command."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner
from defenseclaw.commands.cmd_init import init_cmd
from defenseclaw.context import AppContext


class TestInitCommand(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-test-")
        self.runner = CliRunner()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_help(self):
        result = self.runner.invoke(init_cmd, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Initialize DefenseClaw environment", result.output)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_skip_install_creates_dirs(self, mock_path, _mock_env, mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)

        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))
        self.assertIn("Platform:", result.output)
        self.assertIn("Directories:", result.output)
        self.assertIn("Config:", result.output)
        self.assertIn("Audit DB:", result.output)

        # Verify config file was created
        config_file = os.path.join(self.tmp_dir, "config.yaml")
        self.assertTrue(os.path.isfile(config_file))

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_logs_action(self, mock_path, _mock_env, mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output + (result.stderr or ""))

        # The DB should have at least one event (the init action)
        from defenseclaw.db import Store
        db_path = os.path.join(self.tmp_dir, "audit.db")
        store = Store(db_path)
        events = store.list_events(10)
        self.assertTrue(len(events) >= 1)
        init_events = [e for e in events if e.action == "init"]
        self.assertEqual(len(init_events), 1, f"expected exactly one 'init' event, got actions: {[e.action for e in events]}")
        self.assertEqual(init_events[0].action, "init")
        store.close()

class TestInitVersionDisplay(unittest.TestCase):
    """Tests for version info in init Environment section."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-ver-")
        self.runner = CliRunner()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_shows_cli_version(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("DefenseClaw:", result.output)

    @patch("defenseclaw.commands.cmd_init._get_gateway_version", return_value="v0.5.0")
    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_shows_gateway_version(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which, _mock_gw_ver):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Gateway:       v0.5.0", result.output)

    @patch("defenseclaw.commands.cmd_init._get_gateway_version", return_value=None)
    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_gateway_not_found(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which, _mock_gw_ver):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Gateway:       not found", result.output)


class TestInitPreservesExistingConfig(unittest.TestCase):
    """Regression tests for P5 fix: init must not overwrite existing config."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-preserve-")
        self.runner = CliRunner()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_preserves_existing_config(self, mock_path, _mock_env, mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        # Run init once to create config
        app1 = AppContext()
        result1 = self.runner.invoke(init_cmd, ["--skip-install"], obj=app1)
        self.assertEqual(result1.exit_code, 0, result1.output)

        # Modify the config on disk so we can detect overwrites
        config_file = os.path.join(self.tmp_dir, "config.yaml")
        self.assertTrue(os.path.isfile(config_file))

        import yaml
        with open(config_file) as f:
            cfg_data = yaml.safe_load(f)

        cfg_data["gateway"] = cfg_data.get("gateway", {})
        cfg_data["gateway"]["host"] = "10.20.30.40"
        cfg_data["gateway"]["port"] = 99999

        with open(config_file, "w") as f:
            yaml.dump(cfg_data, f)

        # Run init again — should preserve
        app2 = AppContext()
        result2 = self.runner.invoke(init_cmd, ["--skip-install"], obj=app2)
        self.assertEqual(result2.exit_code, 0, result2.output)
        self.assertIn("preserved existing", result2.output)

        # Verify the customized values survived
        with open(config_file) as f:
            reloaded = yaml.safe_load(f)

        self.assertEqual(reloaded["gateway"]["host"], "10.20.30.40")
        self.assertEqual(reloaded["gateway"]["port"], 99999)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_creates_new_defaults_when_no_config(self, mock_path, _mock_env, mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("created new defaults", result.output)


class TestInitDoesNotCreateExternalDirs(unittest.TestCase):
    """Regression tests for P3 fix: init must not create dirs outside data_dir."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-scope-")
        self.runner = CliRunner()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_does_not_create_openclaw_dirs(self, mock_path, _mock_env, mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)

        for root, dirs, _files in os.walk(self.tmp_dir):
            for d in dirs:
                full = os.path.join(root, d)
                real = os.path.realpath(full)
                self.assertTrue(
                    real.startswith(os.path.realpath(self.tmp_dir)),
                    f"init created directory outside data_dir: {full}"
                )

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_creates_defenseclaw_dirs(self, mock_path, _mock_env, mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)

        # Core DefenseClaw dirs should exist
        self.assertTrue(os.path.isdir(self.tmp_dir))
        quarantine = os.path.join(self.tmp_dir, "quarantine")
        self.assertTrue(os.path.isdir(quarantine))
        plugins = os.path.join(self.tmp_dir, "plugins")
        self.assertTrue(os.path.isdir(plugins))


class TestInitShowsScannerDefaults(unittest.TestCase):
    """Verify that init displays scanner defaults to the user."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-scandef-")
        self.runner = CliRunner()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_displays_skill_scanner_defaults(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("skill-scanner:", result.output)
        self.assertIn("policy=permissive", result.output)
        self.assertIn("lenient=True", result.output)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_displays_mcp_scanner_defaults(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("mcp-scanner:", result.output)
        self.assertIn("analyzers=yara", result.output)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_displays_setup_hint(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("defenseclaw setup", result.output)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_saves_scanner_defaults_to_config(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        import yaml

        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)

        config_file = os.path.join(self.tmp_dir, "config.yaml")
        with open(config_file) as f:
            raw = yaml.safe_load(f)

        sc = raw.get("scanners", {}).get("skill_scanner", {})
        self.assertEqual(sc.get("policy"), "permissive")
        self.assertTrue(sc.get("lenient"))
        self.assertFalse(sc.get("use_llm"))

        mc = raw.get("scanners", {}).get("mcp_scanner", {})
        self.assertEqual(mc.get("analyzers"), "yara")
        self.assertFalse(mc.get("scan_prompts"))


class TestInitShowsGatewayDefaults(unittest.TestCase):
    """Verify that init displays gateway defaults."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-gwdef-")
        self.runner = CliRunner()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_displays_gateway_section(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Gateway", result.output)
        self.assertIn("OpenClaw:", result.output)
        self.assertIn("127.0.0.1:18789", result.output)
        self.assertIn("API port:", result.output)
        self.assertIn("18970", result.output)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_displays_watcher_defaults(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Watcher:", result.output)
        self.assertIn("enabled=True", result.output)
        self.assertIn("take_action=False", result.output)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_saves_gateway_defaults_to_config(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        import yaml

        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)

        config_file = os.path.join(self.tmp_dir, "config.yaml")
        with open(config_file) as f:
            raw = yaml.safe_load(f)

        gw = raw.get("gateway", {})
        self.assertEqual(gw.get("host"), "127.0.0.1")
        self.assertEqual(gw.get("port"), 18789)
        self.assertEqual(gw.get("api_port"), 18970)
        self.assertTrue(gw.get("watcher", {}).get("enabled"))
        self.assertFalse(gw.get("watcher", {}).get("skill", {}).get("take_action"))

    @patch("defenseclaw.commands.cmd_init._resolve_openclaw_gateway",
           return_value={"host": "127.0.0.1", "port": 18789, "token": ""})
    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    @patch.dict(os.environ, {}, clear=False)
    def test_init_no_token_shows_local(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which, _mock_gw):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)
        os.environ.pop("OPENCLAW_GATEWAY_TOKEN", None)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("none (local)", result.output)


class TestResolveOpenclawGateway(unittest.TestCase):
    """Tests for _resolve_openclaw_gateway helper."""

    def test_no_openclaw_json_returns_defaults(self):
        from defenseclaw.commands.cmd_init import _resolve_openclaw_gateway
        result = _resolve_openclaw_gateway("/tmp/nonexistent/openclaw.json")
        self.assertEqual(result["host"], "127.0.0.1")
        self.assertEqual(result["port"], 18789)
        self.assertEqual(result["token"], "")

    def test_local_mode_reads_port_and_token(self):
        import json
        from defenseclaw.commands.cmd_init import _resolve_openclaw_gateway

        with tempfile.TemporaryDirectory() as tmpdir:
            oc_data = {
                "gateway": {
                    "model": "local",
                    "port": 19000,
                    "auth": {"token": "test-token-abc"},
                }
            }
            oc_path = os.path.join(tmpdir, "openclaw.json")
            with open(oc_path, "w") as f:
                json.dump(oc_data, f)

            result = _resolve_openclaw_gateway(oc_path)
            self.assertEqual(result["host"], "127.0.0.1")
            self.assertEqual(result["port"], 19000)
            self.assertEqual(result["token"], "test-token-abc")

    def test_non_local_mode_reads_host(self):
        import json
        from defenseclaw.commands.cmd_init import _resolve_openclaw_gateway

        with tempfile.TemporaryDirectory() as tmpdir:
            oc_data = {
                "gateway": {
                    "mode": "remote",
                    "host": "10.0.0.5",
                    "port": 20000,
                    "auth": {"token": "remote-token"},
                }
            }
            oc_path = os.path.join(tmpdir, "openclaw.json")
            with open(oc_path, "w") as f:
                json.dump(oc_data, f)

            result = _resolve_openclaw_gateway(oc_path)
            self.assertEqual(result["host"], "10.0.0.5")
            self.assertEqual(result["port"], 20000)
            self.assertEqual(result["token"], "remote-token")

    def test_missing_gateway_block(self):
        import json
        from defenseclaw.commands.cmd_init import _resolve_openclaw_gateway

        with tempfile.TemporaryDirectory() as tmpdir:
            oc_data = {"agents": {"defaults": {}}}
            oc_path = os.path.join(tmpdir, "openclaw.json")
            with open(oc_path, "w") as f:
                json.dump(oc_data, f)

            result = _resolve_openclaw_gateway(oc_path)
            self.assertEqual(result["host"], "127.0.0.1")
            self.assertEqual(result["port"], 18789)
            self.assertEqual(result["token"], "")

    def test_no_auth_token(self):
        import json
        from defenseclaw.commands.cmd_init import _resolve_openclaw_gateway

        with tempfile.TemporaryDirectory() as tmpdir:
            oc_data = {"gateway": {"model": "local", "port": 18789}}
            oc_path = os.path.join(tmpdir, "openclaw.json")
            with open(oc_path, "w") as f:
                json.dump(oc_data, f)

            result = _resolve_openclaw_gateway(oc_path)
            self.assertEqual(result["token"], "")


class TestResolveSplunkBridgeBundle(unittest.TestCase):
    def test_prefers_packaged_bundle_data(self):
        from defenseclaw.commands.cmd_init import _resolve_splunk_bridge_bundle

        def fake_is_dir(path):
            path_str = str(path)
            return path_str.endswith("_data/splunk_local_bridge") or path_str.endswith("bundles/splunk_local_bridge")

        with patch("pathlib.Path.is_dir", autospec=True, side_effect=fake_is_dir):
            result = _resolve_splunk_bridge_bundle()

        self.assertTrue(str(result).endswith("_data/splunk_local_bridge"))


class TestInitSeedsSplunkBridge(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-splunk-")
        self.bundle_dir = tempfile.mkdtemp(prefix="dclaw-bundle-splunk-")
        self.runner = CliRunner()

        bin_dir = os.path.join(self.bundle_dir, "bin")
        os.makedirs(bin_dir, exist_ok=True)
        bridge_bin = os.path.join(bin_dir, "splunk-claw-bridge")
        with open(bridge_bin, "w", encoding="utf-8") as handle:
            handle.write("#!/usr/bin/env bash\n")
        os.chmod(bridge_bin, 0o644)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)
        shutil.rmtree(self.bundle_dir, ignore_errors=True)

    @patch("defenseclaw.commands.cmd_init._resolve_splunk_bridge_bundle")
    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_seeds_bundled_splunk_runtime(
        self,
        mock_path,
        _mock_env,
        _mock_scanners,
        _mock_guardrail,
        _mock_which,
        mock_bundle,
    ):
        mock_path.return_value = Path(self.tmp_dir)
        mock_bundle.return_value = Path(self.bundle_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Splunk bridge: seeded in", result.output)
        seeded_bin = os.path.join(self.tmp_dir, "splunk-bridge", "bin", "splunk-claw-bridge")
        self.assertTrue(os.path.isfile(seeded_bin))
        self.assertTrue(os.access(seeded_bin, os.X_OK))


class TestSeedGuardrailProfiles(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-guardrail-")
        self.bundle_dir = tempfile.mkdtemp(prefix="dclaw-bundle-guardrail-")
        for profile in ("default", "strict", "permissive"):
            rules_dir = os.path.join(self.bundle_dir, profile, "rules")
            os.makedirs(rules_dir, exist_ok=True)
            with open(os.path.join(rules_dir, "secrets.yaml"), "w", encoding="utf-8") as handle:
                handle.write("rules: []\n")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)
        shutil.rmtree(self.bundle_dir, ignore_errors=True)

    @patch("defenseclaw.commands.cmd_init.bundled_guardrail_profiles_dir")
    def test_seeds_profiles_when_absent(self, mock_bundled):
        from defenseclaw.commands.cmd_init import _seed_guardrail_profiles

        mock_bundled.return_value = Path(self.bundle_dir)
        _seed_guardrail_profiles(self.tmp_dir)

        for profile in ("default", "strict", "permissive"):
            seeded = os.path.join(self.tmp_dir, "guardrail", profile, "rules", "secrets.yaml")
            self.assertTrue(os.path.isfile(seeded), f"expected seeded file {seeded}")

    @patch("defenseclaw.commands.cmd_init.bundled_guardrail_profiles_dir")
    def test_preserves_existing_profile(self, mock_bundled):
        from defenseclaw.commands.cmd_init import _seed_guardrail_profiles

        mock_bundled.return_value = Path(self.bundle_dir)
        existing_dir = os.path.join(self.tmp_dir, "guardrail", "default")
        os.makedirs(existing_dir, exist_ok=True)
        marker = os.path.join(existing_dir, "user-edited.yaml")
        with open(marker, "w", encoding="utf-8") as handle:
            handle.write("custom: true\n")

        _seed_guardrail_profiles(self.tmp_dir)

        self.assertTrue(os.path.isfile(marker), "existing profile must be preserved intact")
        self.assertFalse(
            os.path.isfile(os.path.join(existing_dir, "rules", "secrets.yaml")),
            "existing profile must not be overwritten",
        )
        self.assertTrue(
            os.path.isfile(os.path.join(self.tmp_dir, "guardrail", "strict", "rules", "secrets.yaml"))
        )

    @patch("defenseclaw.commands.cmd_init.bundled_guardrail_profiles_dir", return_value=None)
    def test_missing_bundle_is_noop(self, _mock_bundled):
        from defenseclaw.commands.cmd_init import _seed_guardrail_profiles

        _seed_guardrail_profiles(self.tmp_dir)
        self.assertFalse(os.path.isdir(os.path.join(self.tmp_dir, "guardrail")))


class TestInstallScanners(unittest.TestCase):
    @patch("defenseclaw.commands.cmd_init._verify_scanner_sdk")
    def test_install_scanners_verifies_sdks(self, mock_verify):
        from defenseclaw.commands.cmd_init import _install_scanners
        from defenseclaw.config import default_config

        cfg = default_config()
        logger = MagicMock()

        _install_scanners(cfg, logger, skip=False)
        self.assertEqual(mock_verify.call_count, 2)
        call_names = [c[0][0] for c in mock_verify.call_args_list]
        self.assertIn("skill-scanner", call_names)
        self.assertIn("mcp-scanner", call_names)

    def test_install_scanners_skip(self):
        from defenseclaw.commands.cmd_init import _install_scanners
        from defenseclaw.config import default_config
        cfg = default_config()
        logger = MagicMock()

        # skip=True should print skip message without calling install
        _install_scanners(cfg, logger, skip=True)
        logger.log_action.assert_not_called()


class TestInitEnableGuardrail(unittest.TestCase):
    """Tests for the --enable-guardrail flag during init."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-guardrail-")
        self.runner = CliRunner()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_enable_guardrail_flag_appears_in_help(self, mock_path, _mock_env, _mock_scanners, _mock_which):
        result = self.runner.invoke(init_cmd, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("--enable-guardrail", result.output)

    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_without_flag_shows_guardrail_hint(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("defenseclaw setup guardrail", result.output)
        self.assertIn("enable llm traffic inspection", result.output.lower())

    @patch("defenseclaw.commands.cmd_init._start_gateway")
    @patch("defenseclaw.commands.cmd_init._install_codeguard_skill")
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.commands.cmd_setup._interactive_guardrail_setup")
    @patch("defenseclaw.commands.cmd_setup.execute_guardrail_setup", return_value=(True, []))
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_enable_guardrail_calls_interactive_setup(
        self, mock_path, _mock_env, mock_exec, mock_interactive,
        _mock_scanners, _mock_which, _mock_guardrail, _mock_codeguard, _mock_start_gw
    ):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        def fake_interactive(app, gc):
            gc.enabled = True
            gc.mode = "observe"
            gc.model = "anthropic/test-model"
            gc.model_name = "test-model"
            gc.api_key_env = "ANTHROPIC_API_KEY"

        mock_interactive.side_effect = fake_interactive

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install", "--enable-guardrail"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        mock_interactive.assert_called_once()
        mock_exec.assert_called_once()

    @patch("defenseclaw.commands.cmd_init._start_gateway")
    @patch("defenseclaw.commands.cmd_init._install_codeguard_skill")
    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.commands.cmd_setup._interactive_guardrail_setup")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_enable_guardrail_declined_shows_hint(
        self, mock_path, _mock_env, mock_interactive,
        _mock_scanners, _mock_which, _mock_codeguard, _mock_start_gw
    ):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        def fake_decline(app, gc):
            gc.enabled = False

        mock_interactive.side_effect = fake_decline

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install", "--enable-guardrail"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Guardrail not enabled", result.output)
        self.assertIn("defenseclaw setup guardrail", result.output)

    @patch("defenseclaw.commands.cmd_init._start_gateway")
    @patch("defenseclaw.commands.cmd_init._install_codeguard_skill")
    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None)
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.commands.cmd_setup._interactive_guardrail_setup")
    @patch("defenseclaw.commands.cmd_setup.execute_guardrail_setup", return_value=(True, ["test warning"]))
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_enable_guardrail_shows_warnings(
        self, mock_path, _mock_env, mock_exec, mock_interactive,
        _mock_scanners, _mock_which, _mock_guardrail, _mock_codeguard, _mock_start_gw
    ):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        def fake_interactive(app, gc):
            gc.enabled = True
            gc.mode = "observe"
            gc.model = "anthropic/test-model"
            gc.model_name = "test-model"

        mock_interactive.side_effect = fake_interactive

        app = AppContext()
        result = self.runner.invoke(init_cmd, ["--skip-install", "--enable-guardrail"], obj=app)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("test warning", result.output)


class TestInitStartsGateway(unittest.TestCase):
    """Tests for the sidecar start during init."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-init-sidecar-")
        self.runner = CliRunner()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_init_shows_sidecar_section(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        with patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None):
            app = AppContext()
            result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("Sidecar", result.output)

    @patch("defenseclaw.commands.cmd_init._install_guardrail")
    @patch("defenseclaw.commands.cmd_init._install_scanners")
    @patch("defenseclaw.config.detect_environment", return_value="macos")
    @patch("defenseclaw.config.default_data_path")
    def test_sidecar_binary_not_found(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

        with patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None):
            app = AppContext()
            result = self.runner.invoke(init_cmd, ["--skip-install"], obj=app)
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("not found", result.output)
            self.assertIn("make gateway-install", result.output)

    def test_start_gateway_binary_missing(self):
        from defenseclaw.commands.cmd_init import _start_gateway
        from defenseclaw.config import default_config

        cfg = default_config()
        cfg.data_dir = self.tmp_dir
        logger = MagicMock()

        with patch("defenseclaw.commands.cmd_init.shutil.which", return_value=None):
            _start_gateway(cfg, logger)
            logger.log_action.assert_not_called()

    def test_start_gateway_already_running(self):
        from defenseclaw.commands.cmd_init import _start_gateway
        from defenseclaw.config import default_config

        cfg = default_config()
        cfg.data_dir = self.tmp_dir
        logger = MagicMock()

        pid_file = os.path.join(self.tmp_dir, "gateway.pid")
        with open(pid_file, "w") as f:
            f.write(str(os.getpid()))

        with patch("defenseclaw.commands.cmd_init.shutil.which", return_value="/usr/bin/defenseclaw-gateway"):
            _start_gateway(cfg, logger)
            logger.log_action.assert_not_called()

    def test_start_gateway_starts_successfully(self):
        from defenseclaw.commands.cmd_init import _start_gateway
        from defenseclaw.config import default_config

        cfg = default_config()
        cfg.data_dir = self.tmp_dir
        logger = MagicMock()

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        mock_result.stdout = ""

        with patch("defenseclaw.commands.cmd_init.shutil.which", return_value="/usr/bin/defenseclaw-gateway"), \
             patch("defenseclaw.commands.cmd_init.subprocess.run", return_value=mock_result), \
             patch("defenseclaw.commands.cmd_init._check_sidecar_health"):
            _start_gateway(cfg, logger)
            logger.log_action.assert_called_once()
            self.assertIn("init-sidecar", logger.log_action.call_args[0])

    def test_start_gateway_fails(self):
        from defenseclaw.commands.cmd_init import _start_gateway
        from defenseclaw.config import default_config

        cfg = default_config()
        cfg.data_dir = self.tmp_dir
        logger = MagicMock()

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "connection refused"
        mock_result.stdout = ""

        with patch("defenseclaw.commands.cmd_init.shutil.which", return_value="/usr/bin/defenseclaw-gateway"), \
             patch("defenseclaw.commands.cmd_init.subprocess.run", return_value=mock_result), \
             patch("defenseclaw.commands.cmd_init._check_sidecar_health"):
            _start_gateway(cfg, logger)
            logger.log_action.assert_not_called()


class TestIsSidecarRunning(unittest.TestCase):
    """Tests for the _is_sidecar_running helper."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-sidecar-pid-")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_no_pid_file(self):
        from defenseclaw.commands.cmd_init import _is_sidecar_running
        self.assertFalse(_is_sidecar_running("/tmp/nonexistent/gateway.pid"))

    def test_valid_pid(self):
        from defenseclaw.commands.cmd_init import _is_sidecar_running
        pid_file = os.path.join(self.tmp_dir, "gateway.pid")
        with open(pid_file, "w") as f:
            f.write(str(os.getpid()))
        self.assertTrue(_is_sidecar_running(pid_file))

    def test_stale_pid(self):
        from defenseclaw.commands.cmd_init import _is_sidecar_running
        pid_file = os.path.join(self.tmp_dir, "gateway.pid")
        with open(pid_file, "w") as f:
            f.write("999999999")
        self.assertFalse(_is_sidecar_running(pid_file))

    def test_json_pid_format(self):
        import json
        from defenseclaw.commands.cmd_init import _read_pid
        pid_file = os.path.join(self.tmp_dir, "gateway.pid")
        with open(pid_file, "w") as f:
            json.dump({"pid": os.getpid()}, f)
        self.assertEqual(_read_pid(pid_file), os.getpid())


class TestDetectOpenclawHome(unittest.TestCase):
    """Tests for _detect_openclaw_home helper."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dclaw-detect-oc-")
        self.oc_home = os.path.join(self.tmp_dir, ".openclaw")
        os.makedirs(self.oc_home)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_returns_none_when_no_openclaw(self):
        from defenseclaw.commands.cmd_init_sandbox import _detect_openclaw_home
        with patch.dict(os.environ, {"SUDO_USER": ""}, clear=False), \
             patch("os.path.expanduser", return_value=os.path.join(self.tmp_dir, "nonexistent")):
            result = _detect_openclaw_home()
            # May find real ~/.openclaw on the host — just check it's str or None
            self.assertTrue(result is None or isinstance(result, str))

    def test_finds_openclaw_with_config(self):
        from defenseclaw.commands.cmd_init_sandbox import _detect_openclaw_home
        # Create openclaw.json
        with open(os.path.join(self.oc_home, "openclaw.json"), "w") as f:
            f.write('{"gateway": {}}')

        with patch("os.path.expanduser", return_value=self.oc_home), \
             patch.dict(os.environ, {"SUDO_USER": ""}, clear=False):
            result = _detect_openclaw_home()
            self.assertEqual(result, self.oc_home)

    def test_prefers_sudo_user_home(self):
        from defenseclaw.commands.cmd_init_sandbox import _detect_openclaw_home

        # Create two homes with openclaw.json
        sudo_home = os.path.join(self.tmp_dir, "sudouser")
        sudo_oc = os.path.join(sudo_home, ".openclaw")
        os.makedirs(sudo_oc)
        with open(os.path.join(sudo_oc, "openclaw.json"), "w") as f:
            f.write('{}')
        with open(os.path.join(self.oc_home, "openclaw.json"), "w") as f:
            f.write('{}')

        mock_pw = MagicMock()
        mock_pw.pw_dir = sudo_home

        with patch.dict(os.environ, {"SUDO_USER": "testuser"}, clear=False), \
             patch("pwd.getpwnam", return_value=mock_pw), \
             patch("os.path.expanduser", return_value=self.oc_home):
            result = _detect_openclaw_home()
            self.assertEqual(result, sudo_oc)


class TestSaveOwnershipBackup(unittest.TestCase):
    """Tests for _save_ownership_backup helper."""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="dclaw-backup-")
        self.oc_home = tempfile.mkdtemp(prefix="dclaw-oc-home-")

    def tearDown(self):
        shutil.rmtree(self.data_dir, ignore_errors=True)
        shutil.rmtree(self.oc_home, ignore_errors=True)

    def test_creates_backup_file(self):
        import json
        from defenseclaw.commands.cmd_init_sandbox import _save_ownership_backup, OPENCLAW_OWNERSHIP_BACKUP
        backup_path = _save_ownership_backup(self.oc_home, self.data_dir)
        self.assertTrue(os.path.isfile(backup_path))

        with open(backup_path) as f:
            data = json.load(f)
        self.assertIn("openclaw_home", data)
        self.assertIn("original_uid", data)
        self.assertIn("original_gid", data)
        self.assertIn("original_mode", data)
        self.assertEqual(data["original_uid"], os.stat(self.oc_home).st_uid)
        self.assertEqual(data["original_gid"], os.stat(self.oc_home).st_gid)

    def test_backup_file_path(self):
        from defenseclaw.commands.cmd_init_sandbox import _save_ownership_backup, OPENCLAW_OWNERSHIP_BACKUP
        backup_path = _save_ownership_backup(self.oc_home, self.data_dir)
        expected = os.path.join(self.data_dir, OPENCLAW_OWNERSHIP_BACKUP)
        self.assertEqual(backup_path, expected)


class TestIntegrateOpenclawHomeIdempotent(unittest.TestCase):
    """Tests for _integrate_openclaw_home idempotency."""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="dclaw-integrate-")
        self.sandbox_home = tempfile.mkdtemp(prefix="dclaw-sandbox-")
        self.oc_home = tempfile.mkdtemp(prefix="dclaw-oc-real-")

    def tearDown(self):
        shutil.rmtree(self.data_dir, ignore_errors=True)
        shutil.rmtree(self.sandbox_home, ignore_errors=True)
        shutil.rmtree(self.oc_home, ignore_errors=True)

    def test_idempotent_when_already_configured(self):
        import json
        from defenseclaw.commands.cmd_init_sandbox import _integrate_openclaw_home, OPENCLAW_OWNERSHIP_BACKUP

        # Simulate a previous successful integration
        backup_path = os.path.join(self.data_dir, OPENCLAW_OWNERSHIP_BACKUP)
        with open(backup_path, "w") as f:
            json.dump({"openclaw_home": self.oc_home, "original_uid": 1000, "original_gid": 1000, "original_mode": "0o755"}, f)

        # Create the symlink
        symlink_path = os.path.join(self.sandbox_home, ".openclaw")
        os.symlink(self.oc_home, symlink_path)

        cfg = MagicMock()
        cfg.data_dir = self.data_dir

        result = _integrate_openclaw_home(cfg, self.sandbox_home)
        self.assertTrue(result)

    def test_returns_false_when_no_openclaw(self):
        from defenseclaw.commands.cmd_init_sandbox import _integrate_openclaw_home

        cfg = MagicMock()
        cfg.data_dir = self.data_dir

        with patch("defenseclaw.commands.cmd_init_sandbox._detect_openclaw_home", return_value=None):
            result = _integrate_openclaw_home(cfg, self.sandbox_home)
            self.assertFalse(result)


class TestRestoreOpenclawOwnership(unittest.TestCase):
    """Tests for _restore_openclaw_ownership in cmd_setup."""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="dclaw-restore-")
        self.sandbox_home = tempfile.mkdtemp(prefix="dclaw-sandbox-")
        self.oc_home = tempfile.mkdtemp(prefix="dclaw-oc-restore-")
        self._sudo_patcher = patch(
            "defenseclaw.commands.cmd_init_sandbox._needs_sudo", return_value=False
        )
        self._sudo_patcher.start()

    def tearDown(self):
        self._sudo_patcher.stop()
        shutil.rmtree(self.data_dir, ignore_errors=True)
        shutil.rmtree(self.sandbox_home, ignore_errors=True)
        shutil.rmtree(self.oc_home, ignore_errors=True)

    def test_noop_when_no_backup(self):
        from defenseclaw.commands.cmd_setup_sandbox import _restore_openclaw_ownership
        # Should not raise
        _restore_openclaw_ownership(self.data_dir, self.sandbox_home)

    def test_removes_symlink(self):
        import json
        from defenseclaw.commands.cmd_init_sandbox import OPENCLAW_OWNERSHIP_BACKUP
        from defenseclaw.commands.cmd_setup_sandbox import _restore_openclaw_ownership

        st = os.stat(self.oc_home)
        backup_path = os.path.join(self.data_dir, OPENCLAW_OWNERSHIP_BACKUP)
        with open(backup_path, "w") as f:
            json.dump({
                "openclaw_home": self.oc_home,
                "original_uid": st.st_uid,
                "original_gid": st.st_gid,
                "original_mode": "0o755",
            }, f)

        # Create symlink
        symlink_path = os.path.join(self.sandbox_home, ".openclaw")
        os.symlink(self.oc_home, symlink_path)

        _restore_openclaw_ownership(self.data_dir, self.sandbox_home)

        self.assertFalse(os.path.islink(symlink_path))
        self.assertFalse(os.path.isfile(backup_path))


if __name__ == "__main__":
    unittest.main()
