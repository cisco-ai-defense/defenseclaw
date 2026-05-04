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

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from defenseclaw.migrations import (
    _migrate_0_3_0,
    _migrate_0_3_0_from_pristine,
    _migrate_0_3_0_surgical,
    run_migrations,
)


def _write_json(path: str, data: dict) -> None:
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def _read_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


class TestMigrate030FromPristine(unittest.TestCase):
    """Tests for the pristine-backup restore path."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dclaw-mig-")
        self.oc_json = os.path.join(self.tmp, "openclaw.json")
        self.pristine = os.path.join(self.tmp, "openclaw.json.pristine")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_restores_from_pristine_and_registers_plugin(self):
        pristine_cfg = {
            "models": {"providers": {"openai": {"key": "sk-test"}}},
            "agents": {"defaults": {"model": {"primary": "claude-sonnet-4-20250514"}}},
        }
        _write_json(self.pristine, pristine_cfg)

        current_cfg = {
            "models": {
                "providers": {
                    "openai": {"key": "sk-test"},
                    "defenseclaw": {"url": "http://localhost:8080"},
                    "litellm": {"url": "http://localhost:8081"},
                }
            },
            "agents": {"defaults": {"model": {"primary": "defenseclaw/claude-sonnet-4-20250514"}}},
        }
        _write_json(self.oc_json, current_cfg)

        _migrate_0_3_0_from_pristine(self.oc_json, self.pristine)

        result = _read_json(self.oc_json)
        self.assertNotIn("defenseclaw", result.get("models", {}).get("providers", {}))
        self.assertNotIn("litellm", result.get("models", {}).get("providers", {}))
        self.assertEqual(
            result["agents"]["defaults"]["model"]["primary"], "claude-sonnet-4-20250514"
        )
        self.assertIn("defenseclaw", result["plugins"]["allow"])
        self.assertEqual(result["plugins"]["entries"]["defenseclaw"]["enabled"], True)
        install_path = os.path.join(self.tmp, "extensions", "defenseclaw")
        self.assertIn(install_path, result["plugins"]["load"]["paths"])

    def test_creates_pre_migration_backup(self):
        _write_json(self.pristine, {"plugins": {}})
        _write_json(self.oc_json, {"old": True})

        _migrate_0_3_0_from_pristine(self.oc_json, self.pristine)

        backup = self.oc_json + ".pre-0.3.0-migration"
        self.assertTrue(os.path.isfile(backup))
        self.assertEqual(_read_json(backup), {"old": True})

    def test_preserves_existing_plugin_entries(self):
        pristine_cfg = {
            "plugins": {
                "allow": ["other-plugin"],
                "entries": {"other-plugin": {"enabled": True}},
                "load": {"paths": ["/some/path"]},
            }
        }
        _write_json(self.pristine, pristine_cfg)
        _write_json(self.oc_json, {})

        _migrate_0_3_0_from_pristine(self.oc_json, self.pristine)

        result = _read_json(self.oc_json)
        self.assertIn("other-plugin", result["plugins"]["allow"])
        self.assertIn("defenseclaw", result["plugins"]["allow"])
        self.assertIn("other-plugin", result["plugins"]["entries"])

    def test_falls_back_to_surgical_on_corrupted_pristine(self):
        with open(self.pristine, "w") as f:
            f.write("not valid json{{{")

        current_cfg = {
            "models": {
                "providers": {"defenseclaw": {"url": "http://localhost:8080"}}
            },
        }
        _write_json(self.oc_json, current_cfg)

        _migrate_0_3_0_from_pristine(self.oc_json, self.pristine)

        result = _read_json(self.oc_json)
        self.assertNotIn("defenseclaw", result.get("models", {}).get("providers", {}))


class TestMigrate030Surgical(unittest.TestCase):
    """Tests for the surgical fallback path."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dclaw-mig-")
        self.oc_json = os.path.join(self.tmp, "openclaw.json")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_removes_defenseclaw_and_litellm_providers(self):
        cfg = {
            "models": {
                "providers": {
                    "openai": {"key": "sk-test"},
                    "defenseclaw": {"url": "http://localhost:8080"},
                    "litellm": {"url": "http://localhost:8081"},
                }
            },
        }
        _write_json(self.oc_json, cfg)

        _migrate_0_3_0_surgical(self.oc_json)

        result = _read_json(self.oc_json)
        providers = result["models"]["providers"]
        self.assertNotIn("defenseclaw", providers)
        self.assertNotIn("litellm", providers)
        self.assertIn("openai", providers)

    def test_restores_model_primary_defenseclaw_prefix(self):
        cfg = {
            "agents": {"defaults": {"model": {"primary": "defenseclaw/claude-sonnet-4-20250514"}}},
        }
        _write_json(self.oc_json, cfg)

        _migrate_0_3_0_surgical(self.oc_json)

        result = _read_json(self.oc_json)
        self.assertEqual(
            result["agents"]["defaults"]["model"]["primary"], "claude-sonnet-4-20250514"
        )

    def test_restores_model_primary_litellm_prefix(self):
        cfg = {
            "agents": {"defaults": {"model": {"primary": "litellm/gpt-4o"}}},
        }
        _write_json(self.oc_json, cfg)

        _migrate_0_3_0_surgical(self.oc_json)

        result = _read_json(self.oc_json)
        self.assertEqual(result["agents"]["defaults"]["model"]["primary"], "gpt-4o")

    def test_noop_when_no_legacy_entries(self):
        cfg = {
            "models": {"providers": {"openai": {"key": "sk-test"}}},
            "agents": {"defaults": {"model": {"primary": "claude-sonnet-4-20250514"}}},
        }
        _write_json(self.oc_json, cfg)
        mtime_before = os.path.getmtime(self.oc_json)

        _migrate_0_3_0_surgical(self.oc_json)

        mtime_after = os.path.getmtime(self.oc_json)
        self.assertEqual(mtime_before, mtime_after)

    def test_noop_when_file_missing(self):
        _migrate_0_3_0_surgical(os.path.join(self.tmp, "nonexistent.json"))

    def test_noop_when_file_is_invalid_json(self):
        with open(self.oc_json, "w") as f:
            f.write("{bad json")
        _migrate_0_3_0_surgical(self.oc_json)


class TestMigrate030Dispatch(unittest.TestCase):
    """Tests for the top-level _migrate_0_3_0 dispatch logic."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dclaw-mig-")
        self.oc_home = self.tmp
        self.oc_json = os.path.join(self.oc_home, "openclaw.json")
        self.data_dir = os.path.join(self.tmp, ".defenseclaw")
        os.makedirs(self.data_dir, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_noop_when_no_openclaw_json(self):
        _migrate_0_3_0(self.oc_home)

    @patch("defenseclaw.guardrail.pristine_backup_path")
    @patch("defenseclaw.migrations._migrate_0_3_0_from_pristine")
    def test_uses_pristine_when_available(self, mock_from_pristine, mock_pristine_path):
        _write_json(self.oc_json, {})
        mock_pristine_path.return_value = "/some/pristine/backup"

        _migrate_0_3_0(self.oc_home)

        mock_from_pristine.assert_called_once_with(self.oc_json, "/some/pristine/backup")

    @patch("defenseclaw.guardrail.pristine_backup_path")
    @patch("defenseclaw.migrations._migrate_0_3_0_surgical")
    def test_falls_back_to_surgical_when_no_pristine(self, mock_surgical, mock_pristine_path):
        _write_json(self.oc_json, {})
        mock_pristine_path.return_value = None

        _migrate_0_3_0(self.oc_home)

        mock_surgical.assert_called_once_with(self.oc_json)


class TestRunMigrations(unittest.TestCase):
    """Tests for the run_migrations orchestrator."""

    def test_applies_migrations_in_range(self):
        count = run_migrations("0.2.0", "0.3.0", tempfile.mkdtemp())
        self.assertEqual(count, 1)

    def test_applies_same_version_migrations(self):
        count = run_migrations("0.3.0", "0.3.0", tempfile.mkdtemp())
        self.assertEqual(count, 1)

    def test_skips_already_applied_migrations(self):
        count = run_migrations("0.3.0", "0.4.0", tempfile.mkdtemp())
        self.assertEqual(count, 0)

    def test_skips_future_migrations(self):
        count = run_migrations("0.1.0", "0.2.0", tempfile.mkdtemp())
        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
