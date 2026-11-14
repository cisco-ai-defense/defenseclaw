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

"""GAP-0598: the Python OpenClaw config writers follow the Go connector rule.

Setup sets ``plugins.entries.defenseclaw.enabled=true`` and keeps every other
key. Teardown removes only ``enabled`` and drops the entry when nothing an
operator wrote is left. A null or non-object entry is treated as absent.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from defenseclaw.openclaw_guardrail import (
    _unregister_plugin_from_config,
    patch_openclaw_config,
    restore_openclaw_config,
)

OPERATOR_KEYS = {"hooks": {"allowConversationAccess": True}, "config": {"awsHttp1Shim": "off"}}


def _write(tmpdir: str, cfg: dict) -> str:
    path = os.path.join(tmpdir, "openclaw.json")
    with open(path, "w") as f:
        json.dump(cfg, f)
    return path


def _read(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


class TestUnregisterKeepsOperatorKeys(unittest.TestCase):
    def test_removes_only_enabled_and_keeps_operator_keys(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write(d, {"plugins": {"entries": {"defenseclaw": {"enabled": True, **OPERATOR_KEYS}}}})
            _unregister_plugin_from_config(path)
            self.assertEqual(_read(path)["plugins"]["entries"]["defenseclaw"], OPERATOR_KEYS)

    def test_benign_twin_enabled_only_entry_is_dropped(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write(d, {"plugins": {"entries": {"defenseclaw": {"enabled": True}, "other": {"enabled": True}}}})
            _unregister_plugin_from_config(path)
            entries = _read(path)["plugins"]["entries"]
            self.assertNotIn("defenseclaw", entries)
            self.assertIn("other", entries)

    def test_second_run_is_stable(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write(d, {"plugins": {"entries": {"defenseclaw": {"enabled": True, **OPERATOR_KEYS}}}})
            _unregister_plugin_from_config(path)
            first = _read(path)
            _unregister_plugin_from_config(path)
            self.assertEqual(_read(path), first)

    def test_null_and_non_object_entry_do_not_raise_and_are_dropped(self):
        for bad in (None, "x", ["y"], True, 3):
            with self.subTest(entry=bad), tempfile.TemporaryDirectory() as d:
                path = _write(d, {"plugins": {"entries": {"defenseclaw": bad}}})
                _unregister_plugin_from_config(path)
                self.assertNotIn("defenseclaw", _read(path)["plugins"]["entries"])


class TestRestoreLeavesNoEnabledResidue(unittest.TestCase):
    def test_enabled_only_entry_is_dropped_not_set_false(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write(d, {"plugins": {"allow": ["defenseclaw"], "entries": {"defenseclaw": {"enabled": True}}}})
            self.assertTrue(restore_openclaw_config(path, ""))
            cfg = _read(path)
            self.assertNotIn("defenseclaw", cfg["plugins"]["entries"])
            self.assertNotIn("defenseclaw", cfg["plugins"]["allow"])

    def test_operator_keys_survive_and_enabled_is_gone(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write(d, {"plugins": {"entries": {"defenseclaw": {"enabled": True, **OPERATOR_KEYS}}}})
            self.assertTrue(restore_openclaw_config(path, ""))
            entry = _read(path)["plugins"]["entries"]["defenseclaw"]
            self.assertNotIn("enabled", entry)
            self.assertEqual(entry, OPERATOR_KEYS)

    def test_non_object_entries_do_not_raise(self):
        for bad in (None, "x"):
            with self.subTest(entries=bad), tempfile.TemporaryDirectory() as d:
                path = _write(d, {"plugins": {"entries": bad}})
                self.assertTrue(restore_openclaw_config(path, ""))


class TestPatchMergesEntry(unittest.TestCase):
    def _patch(self, path: str) -> None:
        patch_openclaw_config(path, "m", 4000, "")

    def test_keeps_operator_keys_and_sets_enabled(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write(d, {"plugins": {"entries": {"defenseclaw": {"enabled": False, **OPERATOR_KEYS}}}})
            self._patch(path)
            self.assertEqual(_read(path)["plugins"]["entries"]["defenseclaw"], {"enabled": True, **OPERATOR_KEYS})

    def test_null_and_non_object_entry_do_not_raise(self):
        for bad in (None, "x", ["y"], True, 3):
            with self.subTest(entry=bad), tempfile.TemporaryDirectory() as d:
                path = _write(d, {"plugins": {"entries": {"defenseclaw": bad}}})
                self._patch(path)
                self.assertEqual(_read(path)["plugins"]["entries"]["defenseclaw"], {"enabled": True})

    def test_null_entries_map_does_not_raise(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write(d, {"plugins": {"entries": None}})
            self._patch(path)
            self.assertEqual(_read(path)["plugins"]["entries"]["defenseclaw"], {"enabled": True})

    def test_benign_twin_new_entry_is_enabled_only(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write(d, {})
            self._patch(path)
            self.assertEqual(_read(path)["plugins"]["entries"]["defenseclaw"], {"enabled": True})

    def test_patch_then_restore_round_trip_leaves_no_entry(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write(d, {})
            self._patch(path)
            self.assertTrue(restore_openclaw_config(path, ""))
            self.assertNotIn("defenseclaw", _read(path)["plugins"]["entries"])


def _plugin_dir(tmpdir: str) -> str:
    path = os.path.join(tmpdir, "extensions", "defenseclaw")
    os.makedirs(path)
    return path


class TestRestoreKeepsPluginDisabledWhenFolderStays(unittest.TestCase):
    """defenseclaw reset keeps the plugin folder: the entry must stay enabled=false."""

    def test_folder_present_keeps_enabled_false_and_operator_keys(self):
        with tempfile.TemporaryDirectory() as d:
            _plugin_dir(d)
            path = _write(
                d,
                {"plugins": {"allow": ["defenseclaw"], "entries": {"defenseclaw": {"enabled": True, **OPERATOR_KEYS}}}},
            )
            self.assertTrue(restore_openclaw_config(path, "", keep_disabled_if_plugin_present=True))
            cfg = _read(path)
            self.assertEqual(cfg["plugins"]["entries"]["defenseclaw"], {"enabled": False, **OPERATOR_KEYS})
            self.assertNotIn("defenseclaw", cfg["plugins"]["allow"])

    def test_folder_present_and_bad_entry_writes_a_disabled_entry(self):
        for bad in (None, "x"):
            with self.subTest(entry=bad), tempfile.TemporaryDirectory() as d:
                _plugin_dir(d)
                path = _write(d, {"plugins": {"entries": {"defenseclaw": bad}}})
                self.assertTrue(restore_openclaw_config(path, "", keep_disabled_if_plugin_present=True))
                self.assertEqual(_read(path)["plugins"]["entries"]["defenseclaw"], {"enabled": False})

    def test_benign_twin_folder_gone_drops_the_entry(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write(d, {"plugins": {"entries": {"defenseclaw": {"enabled": True}}}})
            self.assertTrue(restore_openclaw_config(path, "", keep_disabled_if_plugin_present=True))
            self.assertNotIn("defenseclaw", _read(path)["plugins"]["entries"])

    def test_flag_off_drops_the_entry_even_with_folder(self):
        with tempfile.TemporaryDirectory() as d:
            _plugin_dir(d)
            path = _write(d, {"plugins": {"entries": {"defenseclaw": {"enabled": True}}}})
            self.assertTrue(restore_openclaw_config(path, ""))
            self.assertNotIn("defenseclaw", _read(path)["plugins"]["entries"])


class TestRevertOpenclawPythonFallback(unittest.TestCase):
    """The uninstall/reset fallback when the Go teardown failed and there is no pristine backup."""

    def _revert(self, d: str, config: dict, remove_plugin: bool) -> dict:
        from defenseclaw.commands.cmd_uninstall import UninstallPlan, _revert_openclaw_python

        data_dir = os.path.join(d, "dc-data")
        os.makedirs(data_dir)
        path = _write(d, config)
        plan = UninstallPlan(openclaw_config_file=path, data_dir=data_dir, remove_plugin=remove_plugin)
        _revert_openclaw_python(plan)
        return _read(path)

    def test_reset_with_plugin_folder_keeps_enabled_false(self):
        with tempfile.TemporaryDirectory() as d:
            _plugin_dir(d)
            cfg = self._revert(d, {"plugins": {"entries": {"defenseclaw": {"enabled": True}}}}, remove_plugin=False)
            self.assertEqual(cfg["plugins"]["entries"]["defenseclaw"], {"enabled": False})

    def test_uninstall_drops_the_entry_because_the_plugin_is_removed_next(self):
        with tempfile.TemporaryDirectory() as d:
            _plugin_dir(d)
            cfg = self._revert(d, {"plugins": {"entries": {"defenseclaw": {"enabled": True}}}}, remove_plugin=True)
            self.assertNotIn("defenseclaw", cfg["plugins"]["entries"])

    def test_reset_without_plugin_folder_drops_the_entry(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = self._revert(d, {"plugins": {"entries": {"defenseclaw": {"enabled": True}}}}, remove_plugin=False)
            self.assertNotIn("defenseclaw", cfg["plugins"]["entries"])


if __name__ == "__main__":
    unittest.main()
