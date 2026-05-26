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
    CiscoAIDefenseConfig,
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
        cisco_ai_defense=overrides.get("cisco_ai_defense", CiscoAIDefenseConfig()),
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


class BoundEndpointHintTests(unittest.TestCase):
    """When a credential has a paired endpoint (today: AI Defense
    region URL), `keys set` and `keys fill-missing` must surface the
    bound URL right after the save line. The most common UX failure
    we're catching is "operator pasted a key issued for a different
    region into a config still pointed at the default" — all three
    AID regions reply with the same opaque 401 body, so the only
    durable signal of mismatch is showing the URL we'll send to.
    """

    def test_set_emits_bound_endpoint_for_cisco_aid(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(
                tmp,
                cisco_ai_defense=CiscoAIDefenseConfig(
                    endpoint="https://eu.api.inspect.aidefense.security.cisco.com",
                ),
            )
            runner = CliRunner()
            result = runner.invoke(
                keys_cmd,
                ["set", "CISCO_AI_DEFENSE_API_KEY", "--value", "fake-aid-key-123"],
                obj=app,
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertIn(
                "↪ bound to https://eu.api.inspect.aidefense.security.cisco.com",
                result.output,
            )
            self.assertIn("change region/host", result.output)

    def test_set_does_not_emit_hint_for_unbound_credential(self):
        """VirusTotal has no paired endpoint — no hint should fire,
        otherwise we'd train operators to ignore them."""
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            runner = CliRunner()
            result = runner.invoke(
                keys_cmd,
                ["set", "VIRUSTOTAL_API_KEY", "--value", "fake-vt-key"],
                obj=app,
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertNotIn("↪ bound to", result.output)

    def test_set_does_not_emit_hint_for_unregistered_env(self):
        """Custom env vars without a registry entry (e.g. ad-hoc
        operator-defined keys) must save successfully *and* not
        attempt to render a hint — the spec is None in that path."""
        with tempfile.TemporaryDirectory() as tmp:
            app = _make_app_context(tmp)
            runner = CliRunner()
            result = runner.invoke(
                keys_cmd,
                ["set", "DEFENSECLAW_TEST_CUSTOM_KEY", "--value", "abc"],
                obj=app,
            )
            self.assertEqual(result.exit_code, 0, msg=result.output)
            self.assertNotIn("↪ bound to", result.output)


if __name__ == "__main__":
    unittest.main()
