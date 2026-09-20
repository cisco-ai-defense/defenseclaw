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

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands import cmd_config
from defenseclaw.config import default_config
from defenseclaw.config_inspect import ConfigInspectError


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
            env.config_path.write_text(
                "config_version: 8\nguardrail:\n  port: [oops\n",
                encoding="utf-8",
            )
            with patch.object(
                cmd_config,
                "inspect_v8_config",
                side_effect=ConfigInspectError("invalid YAML source"),
            ):
                res = cmd_config.validate_config()
            self.assertFalse(res.ok)
            self.assertTrue(any("invalid YAML" in error for error in res.errors))

    def test_out_of_range_port_is_error(self):
        with _IsolatedHome() as env:
            env.config_path.write_text(
                # Minimal, but enough to parse. Everything not listed
                # takes its dataclass default via the loader.
                "config_version: 8\n"
                "observability: {}\n"
                "guardrail:\n"
                "  port: 99999\n"
                "  mode: observe\n"
                "  scanner_mode: local\n",
                encoding="utf-8",
            )
            with patch.object(
                cmd_config,
                "inspect_v8_config",
                side_effect=ConfigInspectError("guardrail.port: must be between 1 and 65535"),
            ):
                res = cmd_config.validate_config()
            self.assertFalse(res.ok)
            self.assertTrue(any("guardrail.port" in e for e in res.errors),
                            msg=f"errors were: {res.errors}")

    def test_bad_scanner_mode_is_error(self):
        with _IsolatedHome() as env:
            env.config_path.write_text(
                "config_version: 8\n"
                "observability: {}\n"
                "guardrail:\n"
                "  mode: observe\n"
                "  port: 4000\n"
                "  scanner_mode: bogus\n",
                encoding="utf-8",
            )
            with patch.object(
                cmd_config,
                "inspect_v8_config",
                side_effect=ConfigInspectError("guardrail.scanner_mode: unsupported value"),
            ):
                res = cmd_config.validate_config()
            self.assertFalse(res.ok)
            self.assertTrue(any("scanner_mode" in e for e in res.errors))

    def test_gateway_port_clash_is_warning_not_error(self):
        with _IsolatedHome() as env:
            env.config_path.write_text(
                "config_version: 8\n"
                "observability: {}\n"
                "guardrail:\n"
                "  mode: observe\n"
                "  port: 4000\n"
                "  scanner_mode: local\n"
                "gateway:\n"
                "  port: 7070\n"
                "  api_port: 7070\n",
                encoding="utf-8",
            )
            with patch.object(
                cmd_config,
                "inspect_v8_config",
                return_value=SimpleNamespace(valid=True),
            ):
                res = cmd_config.validate_config()
            # The canonical Go validator owns any advisory diagnostics. The
            # Python command must accept its valid decision without trying to
            # reimplement config semantics.
            self.assertTrue(res.ok, msg=f"errors: {res.errors}")


class ConfigShowTests(unittest.TestCase):
    def test_masked_dict_hides_internal_loader_snapshots(self):
        cfg = default_config()
        cfg._loaded_authoritative_dicts = {
            "guardrail.connectors": {
                "codex": {"mode": "observe", "rule_pack_dir": ""}
            }
        }
        cfg._loaded_owned_nested_values = {
            "guardrail.connectors": {"codex": {"hilt": {"enabled": True}}}
        }

        rendered = cmd_config._config_to_masked_dict(cfg, reveal=False)
        blob = json.dumps(rendered)

        self.assertNotIn("_loaded_authoritative_dicts", rendered)
        self.assertNotIn("_loaded_owned_nested_values", rendered)
        self.assertNotIn("_loaded_authoritative_dicts", blob)
        self.assertNotIn("_loaded_owned_nested_values", blob)


if __name__ == "__main__":
    unittest.main()
