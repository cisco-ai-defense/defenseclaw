# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Phase 13 ``defenseclaw policy export``/``import`` CLI."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from click.testing import CliRunner

from defenseclaw.commands.cmd_policy import policy
from tests.helpers import cleanup_app, make_app_context


class _PolicyExportImportBase(unittest.TestCase):
    def setUp(self) -> None:
        self.app, self.tmp_dir, self.db_path = make_app_context()
        os.makedirs(self.app.cfg.policy_dir, exist_ok=True)
        self.runner = CliRunner()
        # Seed a known custom policy so we don't depend on bundled
        # presets resolving identically across hosts.
        result = self.runner.invoke(
            policy,
            ["create", "round-trip-target", "-d", "round-trip fixture"],
            obj=self.app,
            catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0, result.output)

    def tearDown(self) -> None:
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _invoke(self, args: list[str]):
        return self.runner.invoke(policy, args, obj=self.app, catch_exceptions=False)


class TestExportShareBlob(_PolicyExportImportBase):
    def test_export_to_stdout_emits_versioned_blob(self) -> None:
        result = self._invoke(["export", "round-trip-target"])
        self.assertEqual(result.exit_code, 0, result.output)
        # The encoded blob format is ``v1.<base64url(gzip(json))>``.
        self.assertIn("v1.", result.output)
        # No stray YAML in the output.
        self.assertNotIn("rule_pack:", result.output)

    def test_export_url_flag_emits_hash_fragment(self) -> None:
        result = self._invoke(["export", "round-trip-target", "--url"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("#policy=v1.", result.output)

    def test_export_writes_to_out_file(self) -> None:
        out_path = Path(self.tmp_dir) / "share.txt"
        result = self._invoke(
            ["export", "round-trip-target", "--out", str(out_path)]
        )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(out_path.is_file())
        body = out_path.read_text().strip()
        self.assertTrue(body.startswith("v1."))

    def test_export_unknown_policy_returns_error(self) -> None:
        result = self.runner.invoke(
            policy,
            ["export", "does-not-exist"],
            obj=self.app,
            catch_exceptions=True,
        )
        # ClickException surfaces as a non-zero exit code with a
        # human-readable error.
        self.assertNotEqual(result.exit_code, 0)


class TestImportShareBlob(_PolicyExportImportBase):
    def _make_blob(self, name: str = "round-trip-target") -> str:
        result = self._invoke(["export", name])
        self.assertEqual(result.exit_code, 0, result.output)
        return result.output.strip().splitlines()[-1]

    def test_import_round_trip_creates_yaml_file(self) -> None:
        blob = self._make_blob()
        result = self._invoke(["import", blob, "--name", "imported", "--force"])
        self.assertEqual(result.exit_code, 0, result.output)
        target = Path(self.app.cfg.policy_dir) / "imported.yaml"
        self.assertTrue(target.is_file())

    def test_import_refuses_to_clobber_without_force(self) -> None:
        blob = self._make_blob()
        first = self._invoke(["import", blob, "--name", "duplicate"])
        self.assertEqual(first.exit_code, 0, first.output)
        second = self.runner.invoke(
            policy,
            ["import", blob, "--name", "duplicate"],
            obj=self.app,
            catch_exceptions=True,
        )
        self.assertNotEqual(second.exit_code, 0)
        self.assertIn("already exists", second.output)

    def test_import_from_file_reads_blob(self) -> None:
        blob = self._make_blob()
        path = Path(self.tmp_dir) / "share.txt"
        path.write_text(blob + "\n")
        result = self._invoke(
            ["import", "--from-file", str(path), "--name", "fromfile", "--force"]
        )
        self.assertEqual(result.exit_code, 0, result.output)
        target = Path(self.app.cfg.policy_dir) / "fromfile.yaml"
        self.assertTrue(target.is_file())

    def test_import_accepts_url_fragment(self) -> None:
        blob = self._make_blob()
        fragment = f"#policy={blob}"
        result = self._invoke(
            ["import", fragment, "--name", "frag", "--force"]
        )
        self.assertEqual(result.exit_code, 0, result.output)
        target = Path(self.app.cfg.policy_dir) / "frag.yaml"
        self.assertTrue(target.is_file())

    def test_import_malformed_blob_returns_error(self) -> None:
        result = self.runner.invoke(
            policy,
            ["import", "not-a-real-share-blob"],
            obj=self.app,
            catch_exceptions=True,
        )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("decode", result.output.lower())

    def test_import_with_no_blob_or_file_fails(self) -> None:
        result = self.runner.invoke(
            policy,
            ["import"],
            obj=self.app,
            catch_exceptions=True,
        )
        self.assertNotEqual(result.exit_code, 0)


if __name__ == "__main__":
    unittest.main()
