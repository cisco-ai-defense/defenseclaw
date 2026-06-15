#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for ``_sync_guardrail_hilt_to_opa``.

The HILT toggle in ``config.yaml`` does NOT control prompt-side
guardrail verdicts on its own — those are decided by the Rego
policy at ``policies/rego/data.json`` (``data.guardrail.hilt``).
Pre-fix, ``defenseclaw setup guardrail`` wrote ``hilt.enabled = true``
to ``config.yaml`` only, leaving the Rego data file untouched, so
HIGH-severity prompt findings were resolved as ``alert`` instead of
``confirm`` — the user-visible "HILT is on but no permission prompt"
bug observed during manual probe testing.

Invariants under test:

1. **Setup wizard mirrors HILT into Rego data.json** when the file
   already exists (the post-install steady state).
2. **Sync is a no-op** when ``hilt`` already matches — keeps
   ``defenseclaw policy activate`` runs idempotent.
3. **Missing data.json is tolerated** — the wizard must not fail
   on pre-bootstrap or partial installs; the Rego seed will land
   when activation runs.
4. **min_severity is normalized to upper-case** so the Rego
   ``object.get(severity_rank, ...)`` lookup succeeds regardless of
   how the operator typed the value.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_setup import _sync_guardrail_hilt_to_opa
from defenseclaw.config import GuardrailConfig, HILTConfig


def _write_data_json(policy_dir: str, hilt: dict) -> str:
    rego_dir = os.path.join(policy_dir, "rego")
    os.makedirs(rego_dir, exist_ok=True)
    path = os.path.join(rego_dir, "data.json")
    with open(path, "w") as f:
        json.dump({"guardrail": {"hilt": hilt, "block_threshold": 4}}, f)
    return path


def _read_hilt(path: str) -> dict:
    with open(path) as f:
        return json.load(f)["guardrail"]["hilt"]


class TestSyncGuardrailHiltToOPA(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dclaw-hilt-sync-")

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _gc(self, *, enabled: bool, min_sev: str = "HIGH") -> GuardrailConfig:
        gc = GuardrailConfig()
        gc.hilt = HILTConfig(enabled=enabled, min_severity=min_sev)
        return gc

    def test_enables_hilt_in_rego_data_json(self) -> None:
        path = _write_data_json(self.tmp, {"enabled": False, "min_severity": "HIGH"})
        _sync_guardrail_hilt_to_opa(self.tmp, self._gc(enabled=True))
        self.assertEqual(_read_hilt(path), {"enabled": True, "min_severity": "HIGH"})

    def test_disables_hilt_in_rego_data_json(self) -> None:
        path = _write_data_json(self.tmp, {"enabled": True, "min_severity": "HIGH"})
        _sync_guardrail_hilt_to_opa(self.tmp, self._gc(enabled=False))
        self.assertEqual(_read_hilt(path), {"enabled": False, "min_severity": "HIGH"})

    def test_normalizes_min_severity_case(self) -> None:
        # The Rego severity_rank lookup is case-sensitive; lower-case
        # input from the operator must round-trip as "MEDIUM".
        path = _write_data_json(self.tmp, {"enabled": False, "min_severity": "HIGH"})
        _sync_guardrail_hilt_to_opa(
            self.tmp,
            self._gc(enabled=True, min_sev="medium"),
        )
        self.assertEqual(_read_hilt(path), {"enabled": True, "min_severity": "MEDIUM"})

    def test_noop_when_already_synced(self) -> None:
        # Idempotency: a second wizard pass with identical settings
        # must not rewrite the file (mtime preserved).
        path = _write_data_json(self.tmp, {"enabled": True, "min_severity": "HIGH"})
        before = os.path.getmtime(path)
        # Sleep delta to force any stat change to be observable; we
        # don't actually want it to change.
        os.utime(path, (before - 5, before - 5))
        before = os.path.getmtime(path)
        _sync_guardrail_hilt_to_opa(self.tmp, self._gc(enabled=True))
        self.assertEqual(_read_hilt(path), {"enabled": True, "min_severity": "HIGH"})
        self.assertEqual(os.path.getmtime(path), before, "no-op must not rewrite file")

    def test_missing_data_json_tolerated(self) -> None:
        # Pre-bootstrap install: rego/data.json does not exist yet.
        # The helper must silently skip — `defenseclaw policy activate`
        # will seed the file later.
        result = _sync_guardrail_hilt_to_opa(
            self.tmp, self._gc(enabled=True),
        )
        self.assertIsNone(result)
        self.assertFalse(os.path.exists(
            os.path.join(self.tmp, "rego", "data.json")
        ))

    def test_corrupt_data_json_tolerated(self) -> None:
        # A corrupt data.json must not crash the wizard; the user
        # gets a warning and the file is left alone for `policy activate`
        # to repair.
        rego_dir = os.path.join(self.tmp, "rego")
        os.makedirs(rego_dir, exist_ok=True)
        path = os.path.join(rego_dir, "data.json")
        with open(path, "w") as f:
            f.write("{not json")
        _sync_guardrail_hilt_to_opa(self.tmp, self._gc(enabled=True))
        # File preserved as-is; sync must not silently overwrite
        # corrupt data.
        with open(path) as f:
            self.assertEqual(f.read(), "{not json")

    def test_preserves_other_guardrail_keys(self) -> None:
        # The narrow sync must NOT clobber thresholds or other state
        # owned by `defenseclaw policy activate`.
        path = _write_data_json(self.tmp, {"enabled": False, "min_severity": "HIGH"})
        with open(path) as f:
            data = json.load(f)
        data["guardrail"]["block_threshold"] = 4
        data["guardrail"]["alert_threshold"] = 2
        data["guardrail"]["patterns"] = {"injection": ["jailbreak"]}
        with open(path, "w") as f:
            json.dump(data, f)

        _sync_guardrail_hilt_to_opa(self.tmp, self._gc(enabled=True))

        with open(path) as f:
            after = json.load(f)
        self.assertEqual(after["guardrail"]["hilt"], {"enabled": True, "min_severity": "HIGH"})
        self.assertEqual(after["guardrail"]["block_threshold"], 4)
        self.assertEqual(after["guardrail"]["alert_threshold"], 2)
        self.assertEqual(after["guardrail"]["patterns"], {"injection": ["jailbreak"]})


if __name__ == "__main__":
    unittest.main()
