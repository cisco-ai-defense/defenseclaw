# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``defenseclaw config``.

``validate`` is the most important surface — ``main.py`` runs it as a
pre-flight hook, so any regression here cascades into every command.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands import cmd_config


class _IsolatedHome:
    """Context manager that redirects ``DEFENSECLAW_HOME`` to a tmpdir.

    The config module caches paths at import time, so we also patch the
    resolved ``config_path()``/``load()`` helpers to pick up the new
    home. This keeps the tests hermetic even when the developer has a
    real config on disk.
    """

    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name)
        self.config_path = self.home / "config.yaml"

    def __enter__(self):
        self._patches = [
            patch.dict(os.environ, {"DEFENSECLAW_HOME": str(self.home)}, clear=False),
            patch("defenseclaw.commands.cmd_config.config_module.config_path",
                  return_value=self.config_path),
        ]
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in reversed(self._patches):
            p.stop()
        self._tmp.cleanup()
        return False


class ValidateConfigTests(unittest.TestCase):
    def test_missing_config_is_ok(self):
        """No config yet → soft-pass so recovery/init commands can run."""
        with _IsolatedHome() as env:
            self.assertFalse(env.config_path.exists())
            res = cmd_config.validate_config()
            self.assertTrue(res.ok)
            self.assertFalse(res.exists)

    def test_invalid_yaml_reports_parse_error(self):
        with _IsolatedHome() as env:
            # Guaranteed YAML parse error (dangling unclosed bracket).
            env.config_path.write_text("guardrail:\n  port: [oops\n", encoding="utf-8")
            res = cmd_config.validate_config()
            self.assertFalse(res.ok)
            self.assertTrue(res.parse_error)

    def test_out_of_range_port_is_error(self):
        with _IsolatedHome() as env:
            env.config_path.write_text(
                # Minimal, but enough to parse. Everything not listed
                # takes its dataclass default via the loader.
                "guardrail:\n"
                "  port: 99999\n"
                "  mode: observe\n"
                "  scanner_mode: local\n",
                encoding="utf-8",
            )
            res = cmd_config.validate_config()
            self.assertFalse(res.ok)
            self.assertTrue(any("guardrail.port" in e for e in res.errors),
                            msg=f"errors were: {res.errors}")

    def test_bad_scanner_mode_is_error(self):
        with _IsolatedHome() as env:
            env.config_path.write_text(
                "guardrail:\n"
                "  mode: observe\n"
                "  port: 4000\n"
                "  scanner_mode: bogus\n",
                encoding="utf-8",
            )
            res = cmd_config.validate_config()
            self.assertFalse(res.ok)
            self.assertTrue(any("scanner_mode" in e for e in res.errors))

    def test_gateway_port_clash_is_warning_not_error(self):
        with _IsolatedHome() as env:
            env.config_path.write_text(
                "guardrail:\n"
                "  mode: observe\n"
                "  port: 4000\n"
                "  scanner_mode: local\n"
                "gateway:\n"
                "  port: 7070\n"
                "  api_port: 7070\n",
                encoding="utf-8",
            )
            res = cmd_config.validate_config()
            # Port clash is advisory — don't fail CI over it; just warn.
            self.assertTrue(res.ok, msg=f"errors: {res.errors}")
            self.assertTrue(any("api_port" in w for w in res.warnings),
                            msg=f"warnings: {res.warnings}")


if __name__ == "__main__":
    unittest.main()
