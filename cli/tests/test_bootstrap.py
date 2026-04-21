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
    # Every test needs ``DEFENSECLAW_HOME`` pointed at a tempdir so
    # ``config_path()`` doesn't resolve to the developer's real
    # ``~/.defenseclaw/config.yaml``. Without this, ``is_new_config``
    # becomes a function of the host machine rather than the code
    # under test, and the idempotency contract can't be exercised on
    # a fresh CI runner.
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._prev_home = os.environ.get("DEFENSECLAW_HOME")
        os.environ["DEFENSECLAW_HOME"] = self._tmp.name
        self.addCleanup(self._restore_home)

    def _restore_home(self) -> None:
        if self._prev_home is None:
            os.environ.pop("DEFENSECLAW_HOME", None)
        else:
            os.environ["DEFENSECLAW_HOME"] = self._prev_home

    def test_first_run_creates_directories(self):
        cfg = _cfg_for(os.path.join(self._tmp.name, "dchome"))
        report = bootstrap_env(cfg)

        self.assertIsInstance(report, BootstrapReport)
        self.assertEqual(report.errors, [], msg=report.errors)
        for d in (cfg.data_dir, cfg.quarantine_dir, cfg.plugin_dir, cfg.policy_dir):
            self.assertTrue(os.path.isdir(d), f"expected {d} to be created")

    def test_creates_audit_db_file(self):
        cfg = _cfg_for(os.path.join(self._tmp.name, "dchome"))
        bootstrap_env(cfg)
        self.assertTrue(os.path.isfile(cfg.audit_db))

    def test_idempotent(self):
        """Running bootstrap twice must not error or duplicate side effects."""
        cfg = _cfg_for(os.path.join(self._tmp.name, "dchome"))
        first = bootstrap_env(cfg)
        self.assertEqual(first.errors, [])
        self.assertTrue(first.is_new_config)

        # ``init`` / ``quickstart`` persist the config after
        # ``bootstrap_env`` returns; simulate that here so the
        # ``is_new_config`` flag on the second run reflects reality.
        from defenseclaw.config import config_path
        cfg_file = str(config_path())
        os.makedirs(os.path.dirname(cfg_file), exist_ok=True)
        with open(cfg_file, "w", encoding="utf-8") as fh:
            fh.write("# seeded by test\n")

        second = bootstrap_env(cfg)
        self.assertEqual(second.errors, [])
        self.assertFalse(second.is_new_config)

    def test_reports_data_paths(self):
        cfg = _cfg_for(os.path.join(self._tmp.name, "dchome"))
        report = bootstrap_env(cfg)
        self.assertEqual(report.data_dir, cfg.data_dir)
        self.assertEqual(report.audit_db, cfg.audit_db)


if __name__ == "__main__":
    unittest.main()
