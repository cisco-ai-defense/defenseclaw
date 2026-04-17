# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``defenseclaw keys`` (list / set / check).

Commands are invoked through ``CliRunner`` with a minimal ``AppContext``
so we exercise the real Click wiring without needing a full config file
on disk.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_keys import keys_cmd
from defenseclaw.config import (
    Config,
    GatewayConfig,
    GuardrailConfig,
    OpenShellConfig,
)
from defenseclaw.context import AppContext


def _make_app_context(data_dir: str, **overrides) -> AppContext:
    cfg = Config(
        data_dir=data_dir,
        audit_db=os.path.join(data_dir, "audit.db"),
        quarantine_dir=os.path.join(data_dir, "quarantine"),
        plugin_dir=os.path.join(data_dir, "plugins"),
        policy_dir=os.path.join(data_dir, "policies"),
        guardrail=overrides.get("guardrail", GuardrailConfig()),
        gateway=overrides.get("gateway", GatewayConfig()),
        openshell=overrides.get("openshell", OpenShellConfig()),
    )
    ctx = AppContext()
    ctx.cfg = cfg
    return ctx


class KeysListTests(unittest.TestCase):
    def test_list_as_json_returns_one_entry_per_spec(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            runner = CliRunner()
            result = runner.invoke(keys_cmd, ["list", "--json"], obj=app)
            self.assertEqual(result.exit_code, 0, msg=result.output)
            payload = json.loads(result.output)
            self.assertTrue(payload, "expected non-empty output")
            for item in payload:
                self.assertIn("env_name", item)
                self.assertIn("requirement", item)

    def test_list_missing_only_filters_to_required_unset(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Guardrail on + scanner_mode=remote → CISCO key becomes REQUIRED.
            app = _make_app_context(
                tmp,
                guardrail=GuardrailConfig(enabled=True, scanner_mode="remote"),
            )
            # Clear the relevant env vars so missing filter triggers.
            env = {k: v for k, v in os.environ.items()
                   if k not in ("OPENCLAW_GATEWAY_TOKEN", "CISCO_AI_DEFENSE_API_KEY")}
            with patch.dict(os.environ, env, clear=True):
                runner = CliRunner()
                result = runner.invoke(
                    keys_cmd, ["list", "--missing-only", "--json"], obj=app,
                )
                self.assertEqual(result.exit_code, 0, msg=result.output)
                payload = json.loads(result.output)
                names = {item["env_name"] for item in payload}
                self.assertIn("OPENCLAW_GATEWAY_TOKEN", names)


class KeysCheckTests(unittest.TestCase):
    def test_check_exits_nonzero_when_missing_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            env = {k: v for k, v in os.environ.items()
                   if k != "OPENCLAW_GATEWAY_TOKEN"}
            with patch.dict(os.environ, env, clear=True):
                runner = CliRunner()
                result = runner.invoke(keys_cmd, ["check"], obj=app)
                self.assertNotEqual(result.exit_code, 0)


class KeysSetTests(unittest.TestCase):
    def test_set_writes_value_to_dotenv(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            runner = CliRunner()
            # Use a fake env var name so we exercise the "not in
            # registry" branch without bleeding into real credential
            # resolution.
            result = runner.invoke(
                keys_cmd, ["set", "DEFENSECLAW_TEST_KEY", "--value", "s3cret"],
                obj=app,
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)
            dotenv_path = os.path.join(tmp, ".env")
            self.assertTrue(os.path.isfile(dotenv_path))
            with open(dotenv_path, encoding="utf-8") as fh:
                body = fh.read()
            self.assertIn("DEFENSECLAW_TEST_KEY", body)
            self.assertIn("s3cret", body)

    def test_set_rejects_empty_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            runner = CliRunner()
            result = runner.invoke(
                keys_cmd,
                ["set", "DEFENSECLAW_TEST_KEY", "--value", ""],
                obj=app,
            )
            self.assertNotEqual(result.exit_code, 0)


if __name__ == "__main__":
    unittest.main()
