# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""S7.5 — connector residue check + remediation.

Verifies that ``defenseclaw doctor`` detects when an inactive connector
has left state behind (backup files, hook scripts), and that
``--fix`` mode delegates to ``defenseclaw-gateway connector teardown``
for each residual connector.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_doctor import (
    _CONNECTOR_RESIDUE_ARTIFACTS,
    _DoctorResult,
    _check_connector_residue,
    _fix_connector_residue,
)


def _cfg(data_dir: str, *, openclaw_config_file: str = "") -> SimpleNamespace:
    return SimpleNamespace(
        data_dir=data_dir,
        claw=SimpleNamespace(config_file=openclaw_config_file),
    )


class CheckConnectorResidueTests(unittest.TestCase):
    def test_passes_when_no_residue(self):
        with tempfile.TemporaryDirectory() as data_dir:
            r = _DoctorResult()
            _check_connector_residue(_cfg(data_dir), "openclaw", r)
        self.assertEqual(r.passed, 1)
        self.assertEqual(r.warned, 0)
        self.assertEqual(r.checks[0]["status"], "pass")
        self.assertEqual(r.checks[0]["label"], "Connector residue")

    def test_warns_when_codex_backup_present_with_openclaw_active(self):
        with tempfile.TemporaryDirectory() as data_dir:
            with open(os.path.join(data_dir, "codex_backup.json"), "w") as fh:
                fh.write("{}")
            r = _DoctorResult()
            _check_connector_residue(_cfg(data_dir), "openclaw", r)
        self.assertEqual(r.warned, 1)
        check = r.checks[0]
        self.assertEqual(check["status"], "warn")
        self.assertIn("codex", check["detail"])
        self.assertIn("doctor --fix", check["detail"])

    def test_warns_when_managed_codex_backup_present_with_openclaw_active(self):
        with tempfile.TemporaryDirectory() as data_dir:
            managed = os.path.join(
                data_dir,
                "connector_backups",
                "codex",
                "config.toml.json",
            )
            os.makedirs(os.path.dirname(managed), exist_ok=True)
            with open(managed, "w") as fh:
                fh.write("{}")
            r = _DoctorResult()
            _check_connector_residue(_cfg(data_dir), "openclaw", r)
        self.assertEqual(r.warned, 1)
        self.assertIn("codex", r.checks[0]["detail"])
        self.assertIn("connector_backups", r.checks[0]["detail"])

    def test_does_not_flag_active_connectors_own_artifacts(self):
        """If codex IS the active connector, codex_backup.json is not residue."""
        with tempfile.TemporaryDirectory() as data_dir:
            with open(os.path.join(data_dir, "codex_backup.json"), "w") as fh:
                fh.write("{}")
            r = _DoctorResult()
            _check_connector_residue(_cfg(data_dir), "codex", r)
        self.assertEqual(r.warned, 0, msg=r.checks)
        self.assertEqual(r.passed, 1)

    def test_groups_multiple_residual_connectors(self):
        with tempfile.TemporaryDirectory() as data_dir:
            for f in ("codex_backup.json", "claudecode_backup.json"):
                with open(os.path.join(data_dir, f), "w") as fh:
                    fh.write("{}")
            r = _DoctorResult()
            _check_connector_residue(_cfg(data_dir), "openclaw", r)
        self.assertEqual(r.warned, 1)
        detail = r.checks[0]["detail"]
        self.assertIn("codex", detail)
        self.assertIn("claudecode", detail)

    def test_flags_openclaw_pristine_when_codex_is_active(self):
        """OpenClaw's pristine backup lives next to openclaw.json, not
        under data_dir, so it gets a separate detection path."""
        with tempfile.TemporaryDirectory() as base:
            data_dir = os.path.join(base, "data")
            os.makedirs(data_dir)
            oc_path = os.path.join(base, "openclaw.json")
            pristine = oc_path + ".pristine"
            with open(pristine, "w") as fh:
                fh.write("{}")
            r = _DoctorResult()
            _check_connector_residue(
                _cfg(data_dir, openclaw_config_file=oc_path), "codex", r,
            )
        self.assertEqual(r.warned, 1)
        self.assertIn("openclaw", r.checks[0]["detail"])

    def test_flags_openclaw_managed_backup_when_codex_is_active(self):
        with tempfile.TemporaryDirectory() as data_dir:
            managed = os.path.join(
                data_dir,
                "connector_backups",
                "openclaw",
                "openclaw.json.json",
            )
            os.makedirs(os.path.dirname(managed), exist_ok=True)
            with open(managed, "w") as fh:
                fh.write("{}")
            r = _DoctorResult()
            _check_connector_residue(_cfg(data_dir), "codex", r)
        self.assertEqual(r.warned, 1)
        self.assertIn("openclaw", r.checks[0]["detail"])

    def test_skips_when_data_dir_missing(self):
        cfg = SimpleNamespace(data_dir="", claw=SimpleNamespace(config_file=""))
        r = _DoctorResult()
        _check_connector_residue(cfg, "openclaw", r)
        self.assertEqual(r.skipped, 1)
        self.assertEqual(r.checks[0]["status"], "skip")

    def test_unknown_active_connector_still_detects_residue(self):
        """A plugin/unknown active connector must NOT suppress residue
        detection — operators running plugins are exactly the people
        most likely to have stale state from a previous switch."""
        with tempfile.TemporaryDirectory() as data_dir:
            with open(os.path.join(data_dir, "codex_backup.json"), "w") as fh:
                fh.write("{}")
            r = _DoctorResult()
            _check_connector_residue(_cfg(data_dir), "myplugin", r)
        self.assertEqual(r.warned, 1)


class FixConnectorResidueTests(unittest.TestCase):
    def _cfg_with_residue(self, data_dir: str, *files: str):
        for f in files:
            with open(os.path.join(data_dir, f), "w") as fh:
                fh.write("{}")
        cfg = _cfg(data_dir)
        cfg.active_connector = lambda: "openclaw"
        cfg.guardrail = SimpleNamespace(connector="openclaw")
        return cfg

    def test_skip_when_no_residue(self):
        with tempfile.TemporaryDirectory() as data_dir:
            cfg = self._cfg_with_residue(data_dir)
            tag, detail = _fix_connector_residue(cfg, assume_yes=True)
        self.assertEqual(tag, "skip")
        self.assertIn("no inactive-connector residue", detail)

    def test_calls_gateway_teardown_for_each_residual(self):
        with tempfile.TemporaryDirectory() as data_dir:
            cfg = self._cfg_with_residue(
                data_dir, "codex_backup.json", "claudecode_backup.json",
            )
            with patch("shutil.which", return_value="/usr/bin/defenseclaw-gateway"), \
                 patch("subprocess.run") as run_mock:
                run_mock.return_value.returncode = 0
                run_mock.return_value.stdout = ""
                run_mock.return_value.stderr = ""
                tag, detail = _fix_connector_residue(cfg, assume_yes=True)
        self.assertEqual(tag, "pass", msg=detail)
        # Both connectors must have been torn down.
        self.assertEqual(run_mock.call_count, 2)
        called_args = [c.args[0] for c in run_mock.call_args_list]
        connectors = [args[args.index("--connector") + 1] for args in called_args]
        self.assertEqual(set(connectors), {"codex", "claudecode"})

    def test_calls_gateway_teardown_for_managed_residual(self):
        with tempfile.TemporaryDirectory() as data_dir:
            managed = os.path.join(
                data_dir,
                "connector_backups",
                "codex",
                "config.toml.json",
            )
            os.makedirs(os.path.dirname(managed), exist_ok=True)
            with open(managed, "w") as fh:
                fh.write("{}")
            cfg = self._cfg_with_residue(data_dir)
            with patch("shutil.which", return_value="/usr/bin/defenseclaw-gateway"), \
                 patch("subprocess.run") as run_mock:
                run_mock.return_value.returncode = 0
                run_mock.return_value.stdout = ""
                run_mock.return_value.stderr = ""
                tag, detail = _fix_connector_residue(cfg, assume_yes=True)
        self.assertEqual(tag, "pass", msg=detail)
        run_mock.assert_called_once()
        args = run_mock.call_args.args[0]
        self.assertEqual(args[args.index("--connector") + 1], "codex")

    def test_warns_when_gateway_binary_missing(self):
        with tempfile.TemporaryDirectory() as data_dir:
            cfg = self._cfg_with_residue(data_dir, "codex_backup.json")
            with patch("shutil.which", return_value=None):
                tag, detail = _fix_connector_residue(cfg, assume_yes=True)
        self.assertEqual(tag, "warn")
        self.assertIn("not on PATH", detail)

    def test_partial_success_when_one_teardown_fails(self):
        with tempfile.TemporaryDirectory() as data_dir:
            cfg = self._cfg_with_residue(
                data_dir, "codex_backup.json", "claudecode_backup.json",
            )
            with patch("shutil.which", return_value="/usr/bin/defenseclaw-gateway"), \
                 patch("subprocess.run") as run_mock:
                def side_effect(args, **_kwargs):
                    rv = MagicMock()
                    name = args[args.index("--connector") + 1]
                    rv.returncode = 0 if name == "codex" else 1
                    rv.stdout = ""
                    rv.stderr = "boom" if rv.returncode else ""
                    return rv
                run_mock.side_effect = side_effect
                tag, detail = _fix_connector_residue(cfg, assume_yes=True)
        self.assertEqual(tag, "warn")
        self.assertIn("partial", detail)
        self.assertIn("codex", detail)
        self.assertIn("claudecode", detail)

    def test_declined_by_user_skips(self):
        with tempfile.TemporaryDirectory() as data_dir:
            cfg = self._cfg_with_residue(data_dir, "codex_backup.json")
            with patch("click.confirm", return_value=False), \
                 patch("subprocess.run") as run_mock:
                tag, detail = _fix_connector_residue(cfg, assume_yes=False)
        self.assertEqual(tag, "skip")
        self.assertIn("declined", detail)
        run_mock.assert_not_called()


class ResidueArtifactsContractTests(unittest.TestCase):
    """Lock down the artifact filename map so a typo when wiring up a
    new connector adapter can't silently disable residue detection."""

    def test_built_in_connectors_present(self):
        for name in ("claudecode", "codex", "zeptoclaw"):
            self.assertIn(name, _CONNECTOR_RESIDUE_ARTIFACTS)

    def test_artifact_filenames_match_connector_state(self):
        """Filenames must cover both legacy and managed backup names that
        the Go connectors write under data_dir. Drift here would
        cause silent false-negatives in residue detection."""
        self.assertIn("claudecode_backup.json", _CONNECTOR_RESIDUE_ARTIFACTS["claudecode"])
        self.assertIn(
            os.path.join("connector_backups", "claudecode", "settings.json.json"),
            _CONNECTOR_RESIDUE_ARTIFACTS["claudecode"],
        )
        self.assertIn("codex_backup.json", _CONNECTOR_RESIDUE_ARTIFACTS["codex"])
        self.assertIn("codex_config_backup.json", _CONNECTOR_RESIDUE_ARTIFACTS["codex"])
        self.assertIn(
            os.path.join("connector_backups", "codex", "config.toml.json"),
            _CONNECTOR_RESIDUE_ARTIFACTS["codex"],
        )
        self.assertIn("zeptoclaw_backup.json", _CONNECTOR_RESIDUE_ARTIFACTS["zeptoclaw"])
        self.assertIn(
            os.path.join("connector_backups", "zeptoclaw", "config.json.json"),
            _CONNECTOR_RESIDUE_ARTIFACTS["zeptoclaw"],
        )


if __name__ == "__main__":
    unittest.main()
