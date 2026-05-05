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

"""Tests for ``defenseclaw agent discover``."""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import requests
from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_agent import agent
from defenseclaw.context import AppContext
from defenseclaw.inventory.agent_discovery import AgentDiscovery, AgentSignal

from tests.helpers import cleanup_app, make_app_context


def _discovery(cache_hit: bool = False) -> AgentDiscovery:
    return AgentDiscovery(
        scanned_at="2026-05-04T18:21:00Z",
        cache_hit=cache_hit,
        agents={
            "codex": AgentSignal(
                name="codex",
                installed=True,
                config_path="/Users/alice/.codex/config.toml",
                binary_path="/opt/homebrew/bin/codex",
                version="codex 1.2.3",
                error="",
            ),
            "claudecode": AgentSignal(
                name="claudecode",
                installed=False,
                config_path="",
                binary_path="",
                version="",
                error="version probe timed out",
            ),
        },
    )


class TestAgentDiscoverCommand(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()

    def test_json_no_emit_is_pre_init_safe(self):
        with patch(
            "defenseclaw.commands.cmd_agent.agent_discovery.discover_agents",
            return_value=_discovery(cache_hit=True),
        ):
            result = self.runner.invoke(
                agent,
                ["discover", "--json", "--no-emit-otel"],
                obj=AppContext(),
                catch_exceptions=False,
            )

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertTrue(payload["cache_hit"])
        self.assertTrue(payload["agents"]["codex"]["installed"])
        self.assertEqual(payload["otel"], {"attempted": False, "emitted": False, "error": ""})

    def test_default_emits_sanitized_report(self):
        app, tmp_dir, db_path = make_app_context()
        app.cfg.gateway.host = "127.0.0.1"
        app.cfg.gateway.api_port = 18970
        app.cfg.gateway.token = "secret-token-123"
        captured: list[dict] = []

        class FakeClient:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

            def emit_agent_discovery(self, report):
                captured.append(report)
                return {"status": "ok"}

        try:
            with patch(
                "defenseclaw.commands.cmd_agent.agent_discovery.discover_agents",
                return_value=_discovery(),
            ), patch("defenseclaw.commands.cmd_agent.OrchestratorClient", FakeClient):
                result = self.runner.invoke(
                    agent,
                    ["discover"],
                    obj=app,
                    catch_exceptions=False,
                )
        finally:
            cleanup_app(app, db_path, tmp_dir)

        self.assertEqual(result.exit_code, 0, result.output + result.stderr)
        self.assertEqual(len(captured), 1)
        report = captured[0]
        self.assertEqual(report["source"], "cli")
        self.assertEqual(report["agents"]["codex"]["config_basename"], "config.toml")
        self.assertTrue(report["agents"]["codex"]["config_path_hash"].startswith("sha256:"))
        rendered = json.dumps(report, sort_keys=True)
        self.assertNotIn("/Users/alice", rendered)
        self.assertNotIn("/opt/homebrew", rendered)

    def test_emit_failure_is_fail_open_unless_required(self):
        app, tmp_dir, db_path = make_app_context()
        app.cfg.gateway.token = "secret-token-123"

        class FailingClient:
            def __init__(self, **_kwargs):
                pass

            def emit_agent_discovery(self, _report):
                raise requests.ConnectionError("no sidecar")

        try:
            with patch(
                "defenseclaw.commands.cmd_agent.agent_discovery.discover_agents",
                return_value=_discovery(),
            ), patch("defenseclaw.commands.cmd_agent.OrchestratorClient", FailingClient):
                result = self.runner.invoke(
                    agent,
                    ["discover"],
                    obj=app,
                    catch_exceptions=False,
                )
                required = self.runner.invoke(
                    agent,
                    ["discover", "--require-otel"],
                    obj=app,
                    catch_exceptions=False,
                )
        finally:
            cleanup_app(app, db_path, tmp_dir)

        self.assertEqual(result.exit_code, 0, result.output + result.stderr)
        self.assertIn("OTel: not emitted", result.stderr)
        self.assertNotEqual(required.exit_code, 0)
        self.assertIn("sidecar unavailable", required.output)

    def test_no_emit_skips_client(self):
        with patch(
            "defenseclaw.commands.cmd_agent.agent_discovery.discover_agents",
            return_value=_discovery(),
        ), patch("defenseclaw.commands.cmd_agent.OrchestratorClient") as client:
            result = self.runner.invoke(
                agent,
                ["discover", "--no-emit-otel"],
                obj=AppContext(),
                catch_exceptions=False,
            )

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("codex", result.output)
        client.assert_not_called()

    def test_usage_json_queries_sidecar(self):
        app, tmp_dir, db_path = make_app_context()
        app.cfg.gateway.token = "secret-token-123"

        class FakeClient:
            def __init__(self, **_kwargs):
                pass

            def ai_usage(self):
                return {
                    "enabled": True,
                    "summary": {"active_signals": 1, "new_signals": 1},
                    "signals": [{"state": "new", "category": "ai_cli", "product": "Codex"}],
                }

        try:
            with patch("defenseclaw.commands.cmd_agent.OrchestratorClient", FakeClient):
                result = self.runner.invoke(
                    agent,
                    ["usage", "--json"],
                    obj=app,
                    catch_exceptions=False,
                )
        finally:
            cleanup_app(app, db_path, tmp_dir)

        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["summary"]["active_signals"], 1)
        self.assertEqual(payload["signals"][0]["product"], "Codex")

    def test_usage_refresh_triggers_scan(self):
        app, tmp_dir, db_path = make_app_context()
        app.cfg.gateway.token = "secret-token-123"
        calls: list[str] = []

        class FakeClient:
            def __init__(self, **_kwargs):
                pass

            def scan_ai_usage(self):
                calls.append("scan")
                return {
                    "enabled": True,
                    "summary": {"active_signals": 1, "new_signals": 1, "changed_signals": 0, "gone_signals": 0},
                    "signals": [{"state": "new", "category": "ai_cli", "product": "Codex", "vendor": "OpenAI"}],
                }

        try:
            with patch("defenseclaw.commands.cmd_agent.OrchestratorClient", FakeClient):
                result = self.runner.invoke(
                    agent,
                    ["usage", "--refresh"],
                    obj=app,
                    catch_exceptions=False,
                )
        finally:
            cleanup_app(app, db_path, tmp_dir)

        self.assertEqual(result.exit_code, 0, result.output + result.stderr)
        self.assertEqual(calls, ["scan"])
        self.assertIn("Codex", result.output)

    def test_signatures_validate_and_install(self):
        app, tmp_dir, db_path = make_app_context()
        app.cfg.data_dir = str(Path(tmp_dir) / ".defenseclaw-signatures")
        pack = Path(tmp_dir) / "pack.json"
        pack.write_text(
            json.dumps({
                "version": 1,
                "id": "custom-pack",
                "signatures": [{
                    "id": "custom-cli-ai",
                    "name": "Custom CLI AI",
                    "vendor": "Example",
                    "category": "ai_cli",
                    "confidence": 0.7,
                }],
            }),
            encoding="utf-8",
        )

        try:
            valid = self.runner.invoke(agent, ["signatures", "validate", str(pack)], obj=app, catch_exceptions=False)
            installed = self.runner.invoke(agent, ["signatures", "install", str(pack)], obj=app, catch_exceptions=False)
            listed = self.runner.invoke(agent, ["signatures", "list", "--json"], obj=app, catch_exceptions=False)
        finally:
            cleanup_app(app, db_path, tmp_dir)

        self.assertEqual(valid.exit_code, 0, valid.output)
        self.assertIn("Signature pack valid", valid.output)
        self.assertEqual(installed.exit_code, 0, installed.output)
        self.assertIn("custom-pack.json", installed.output)
        payload = json.loads(listed.output)
        self.assertIn("custom-cli-ai", {sig["id"] for sig in payload})

    def test_signatures_disable_updates_config(self):
        app, tmp_dir, db_path = make_app_context()
        app.cfg.data_dir = str(Path(tmp_dir) / ".defenseclaw-signatures")
        try:
            result = self.runner.invoke(
                agent,
                ["signatures", "disable", "Custom_AI"],
                obj=app,
                catch_exceptions=False,
            )
        finally:
            cleanup_app(app, db_path, tmp_dir)

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("custom-ai", result.output)
        self.assertIn("custom-ai", app.cfg.ai_discovery.disabled_signature_ids)


if __name__ == "__main__":
    unittest.main()
