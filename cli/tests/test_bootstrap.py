# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``defenseclaw.bootstrap``.

``bootstrap_env`` powers both ``init`` and ``quickstart``, so these
tests pin its idempotency + reporting contract. We run it twice per case
to catch any accidental re-seeding regressions.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.bootstrap import BootstrapReport, bootstrap_env
from defenseclaw.config import (
    Config,
    GatewayConfig,
    GuardrailConfig,
    OpenShellConfig,
)


def _cfg_for(tmp: str) -> Config:
    return Config(
        data_dir=tmp,
        audit_db=os.path.join(tmp, "audit.db"),
        quarantine_dir=os.path.join(tmp, "quarantine"),
        plugin_dir=os.path.join(tmp, "plugins"),
        policy_dir=os.path.join(tmp, "policies"),
        guardrail=GuardrailConfig(),
        gateway=GatewayConfig(),
        openshell=OpenShellConfig(),
    )


class BootstrapEnvTests(unittest.TestCase):
    def test_first_run_creates_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg_for(os.path.join(tmp, "dchome"))
            report = bootstrap_env(cfg)

            self.assertIsInstance(report, BootstrapReport)
            self.assertEqual(report.errors, [], msg=report.errors)
            for d in (cfg.data_dir, cfg.quarantine_dir, cfg.plugin_dir, cfg.policy_dir):
                self.assertTrue(os.path.isdir(d), f"expected {d} to be created")

    def test_creates_audit_db_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg_for(os.path.join(tmp, "dchome"))
            bootstrap_env(cfg)
            self.assertTrue(os.path.isfile(cfg.audit_db))

    def test_idempotent(self):
        """Running bootstrap twice must not error or duplicate side effects."""
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg_for(os.path.join(tmp, "dchome"))
            first = bootstrap_env(cfg)
            self.assertEqual(first.errors, [])
            second = bootstrap_env(cfg)
            self.assertEqual(second.errors, [])
            # First run flags is_new_config; second run must not.
            self.assertFalse(second.is_new_config)

    def test_reports_data_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _cfg_for(os.path.join(tmp, "dchome"))
            report = bootstrap_env(cfg)
            self.assertEqual(report.data_dir, cfg.data_dir)
            self.assertEqual(report.audit_db, cfg.audit_db)


if __name__ == "__main__":
    unittest.main()
