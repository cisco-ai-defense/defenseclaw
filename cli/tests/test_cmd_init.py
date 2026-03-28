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
    def test_init_no_token_shows_local(self, mock_path, _mock_env, _mock_scanners, _mock_guardrail, _mock_which, _mock_gw):
        from pathlib import Path
        mock_path.return_value = Path(self.tmp_dir)

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
                    "model": "remote",
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


if __name__ == "__main__":
    unittest.main()
