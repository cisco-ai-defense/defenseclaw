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


def _ai_signal(
    *,
    state: str,
    category: str,
    product: str,
    vendor: str,
    detector: str,
    basenames: list[str] | None = None,
) -> dict:
    return {
        "state": state,
        "category": category,
        "product": product,
        "vendor": vendor,
        "detector": detector,
        "basenames": basenames or [],
    }


def _wide_payload() -> dict:
    """Mimic the noisy real-world payload that motivated the redesign:

    488 ``package_dependency`` rows for "AI SDKs" / "Multiple" plus a
    handful of distinct categories. The grouped renderer must collapse
    the bulk into a single row, and the per-signal ``--detail`` mode
    must still surface every entry.
    """
    signals: list[dict] = []
    for i in range(488):
        signals.append(_ai_signal(
            state="new",
            category="package_dependency",
            product="AI SDKs",
            vendor="Multiple",
            detector="package_manifest",
            basenames=[f"manifest_{i}.json"],
        ))
    signals.append(_ai_signal(
        state="new",
        category="ai_cli",
        product="Codex",
        vendor="OpenAI",
        detector="binary",
        basenames=["codex"],
    ))
    signals.append(_ai_signal(
        state="changed",
        category="active_process",
        product="Cursor",
        vendor="Anysphere",
        detector="process",
    ))
    signals.append(_ai_signal(
        state="gone",
        category="ai_cli",
        product="OldTool",
        vendor="Acme",
        detector="binary",
    ))
    return {
        "enabled": True,
        "summary": {
            "active_signals": len(signals),
            "new_signals": 489,
            "changed_signals": 1,
            "gone_signals": 1,
            "files_scanned": 1002,
            "scanned_at": "2026-05-06T03:45:38Z",
        },
        "signals": signals,
    }


class AiUsageRendererTests(unittest.TestCase):
    """Cover the grouped/detail/filter behavior added to fix the
    "488 identical package_dependency rows" report."""

    def test_summary_collapses_wide_groups_into_one_row_with_count(self):
        from defenseclaw.commands import cmd_agent

        out = cmd_agent._render_ai_usage_table(_wide_payload())
        # Wide-net group must appear exactly once with the rolled-up count.
        self.assertEqual(out.count("package_dependency"), 1, out)
        self.assertIn("488", out)
        # The grouped view replaces the redundant Evidence column with
        # a count and a basename sample — both must show up.
        self.assertIn("Count", out)
        self.assertIn("Sample evidence", out)

    def test_summary_hides_gone_signals_by_default(self):
        from defenseclaw.commands import cmd_agent

        out = cmd_agent._render_ai_usage_table(_wide_payload())
        # The "OldTool" gone signal must be suppressed in the default
        # render even though it's still counted in the footer (which
        # always reflects the unfiltered summary so operators don't
        # think the sidecar lost a signal).
        self.assertNotIn("OldTool", out)
        self.assertIn("gone=1", out)

    def test_summary_show_gone_includes_gone_rows(self):
        from defenseclaw.commands import cmd_agent

        out = cmd_agent._render_ai_usage_table(_wide_payload(), show_gone=True)
        self.assertIn("OldTool", out)

    def test_state_filter_is_exact(self):
        from defenseclaw.commands import cmd_agent

        out = cmd_agent._render_ai_usage_table(_wide_payload(), states=("changed",))
        self.assertIn("Cursor", out)
        # Only the changed row should make it through the filter.
        self.assertNotIn("AI SDKs", out)
        self.assertNotIn("Codex", out)

    def test_product_filter_is_substring_and_case_insensitive(self):
        from defenseclaw.commands import cmd_agent

        out = cmd_agent._render_ai_usage_table(_wide_payload(), products=("codex",))
        self.assertIn("Codex", out)
        self.assertNotIn("Cursor", out)
        self.assertNotIn("AI SDKs", out)

    def test_category_filter_is_exact_and_case_insensitive(self):
        from defenseclaw.commands import cmd_agent

        out = cmd_agent._render_ai_usage_table(
            _wide_payload(), categories=("AI_CLI",),
        )
        self.assertIn("Codex", out)
        self.assertNotIn("AI SDKs", out)

    def test_detail_mode_emits_one_row_per_signal(self):
        from defenseclaw.commands import cmd_agent

        out = cmd_agent._render_ai_usage_table(_wide_payload(), detail=True)
        # 488 manifest rows must appear individually in detail mode.
        self.assertEqual(out.count("package_dependency"), 488, out[:200])
        # And the noisy "Sample evidence" column should NOT be added —
        # detail mode keeps the per-signal "Evidence" column only.
        self.assertNotIn("Sample evidence", out)
        self.assertNotIn("Count ", out)

    def test_limit_caps_summary_groups_and_warns(self):
        from defenseclaw.commands import cmd_agent

        out = cmd_agent._render_ai_usage_table(_wide_payload(), limit=1)
        # First group (sorted: state weight, then desc count) is the
        # 488-row package_dependency one.
        self.assertIn("488", out)
        # Other groups must be hidden behind the limit warning.
        self.assertNotIn("Codex", out)
        self.assertIn("hidden by --limit", out)

    def test_limit_caps_detail_rows(self):
        from defenseclaw.commands import cmd_agent

        out = cmd_agent._render_ai_usage_table(
            _wide_payload(), detail=True, limit=5,
        )
        # Only 5 rows; everything else hidden.
        self.assertEqual(out.count("package_dependency"), 5, out[:200])
        self.assertIn("hidden by --limit", out)

    def test_filter_signals_helper_handles_empty_inputs(self):
        from defenseclaw.commands import cmd_agent

        # No signals → empty list (must not crash on the gone-suppression
        # path that touches state.lower()).
        self.assertEqual(
            cmd_agent._filter_ai_usage_signals(
                [],
                states=(),
                categories=(),
                products=(),
                show_gone=False,
            ),
            [],
        )
        self.assertEqual(
            cmd_agent._filter_ai_usage_signals(
                None,  # type: ignore[arg-type]
                states=(),
                categories=(),
                products=(),
                show_gone=False,
            ),
            [],
        )

    def test_summary_sort_orders_by_state_then_count(self):
        from defenseclaw.commands import cmd_agent

        signals = [
            _ai_signal(state="active", category="ai_cli", product="Z",
                       vendor="V", detector="d", basenames=["a"]),
            _ai_signal(state="new", category="ai_cli", product="A",
                       vendor="V", detector="d", basenames=["a"]),
            _ai_signal(state="new", category="ai_cli", product="A",
                       vendor="V", detector="d", basenames=["b"]),
            _ai_signal(state="changed", category="ai_cli", product="M",
                       vendor="V", detector="d", basenames=["a"]),
        ]
        rows = cmd_agent._summarize_ai_usage_signals(signals)
        # Order: new (count 2) -> changed -> active. Single new group has
        # both basenames merged.
        self.assertEqual(rows[0][0][0], "new")
        self.assertEqual(rows[0][1], 2)
        self.assertEqual(rows[0][2], ["a", "b"])
        self.assertEqual(rows[1][0][0], "changed")
        self.assertEqual(rows[2][0][0], "active")

    def test_format_evidence_sample_truncates_with_plus_n(self):
        from defenseclaw.commands import cmd_agent

        self.assertEqual(cmd_agent._format_evidence_sample([]), "")
        self.assertEqual(
            cmd_agent._format_evidence_sample(["a", "b", "c"]),
            "a, b, c",
        )
        self.assertEqual(
            cmd_agent._format_evidence_sample(["a", "b", "c", "d", "e"]),
            "a, b, c (+2)",
        )

    def test_grouped_view_surfaces_per_component_confidence(self):
        """Default grouped table must show Identity / Presence so
        operators don't have to drop into ``--detail`` to see the
        engine's verdict. Bug regression: pre-fix the columns only
        appeared in detail mode and were repeated 488x per group."""
        from defenseclaw.commands import cmd_agent

        sigs = []
        for i in range(3):
            sigs.append({
                "state": "new",
                "category": "package_dependency",
                "product": "Anthropic Claude",
                "vendor": "Anthropic",
                "detector": "package_manifest",
                "basenames": [f"pkg_{i}.json"],
                "component": {
                    "ecosystem": "npm",
                    "name": "@anthropic-ai/sdk",
                    "version": "0.20.0",
                },
                "identity_score": 0.91,
                "identity_band": "high",
                "presence_score": 0.78,
                "presence_band": "medium",
            })
        payload = {
            "enabled": True,
            "summary": {"active_signals": 3, "new_signals": 3,
                        "changed_signals": 0, "gone_signals": 0,
                        "scanned_at": "2026-05-05T00:00:00Z",
                        "files_scanned": 1},
            "signals": sigs,
        }
        out = cmd_agent._render_ai_usage_table(payload)
        self.assertIn("Identity", out)
        self.assertIn("Presence", out)
        # Bands rendered with percentage just like --detail does.
        # Rich may wrap the cell across lines depending on terminal
        # width; assert each fragment separately so the test is
        # robust to lipgloss/Rich line-wrapping decisions.
        self.assertIn("91%", out)
        self.assertIn("78%", out)
        self.assertIn("high", out)
        self.assertIn("medium", out)
        # Three signals collapse to one grouped row. Rich may
        # truncate the component cell with "…" when the terminal
        # width is tight, so we assert on the unique prefix.
        self.assertEqual(out.count("@anthrop"), 1)

    def test_grouped_view_omits_confidence_when_engine_silent(self):
        """Older sidecars without the engine must render the legacy
        column set unchanged so existing dashboards / golden fixtures
        keep working."""
        from defenseclaw.commands import cmd_agent

        out = cmd_agent._render_ai_usage_table(_wide_payload())
        self.assertNotIn("Identity", out)
        self.assertNotIn("Presence", out)

    def test_normalized_view_collapses_one_product_across_detectors(self):
        """Real-world bug: "Claude Code" was independently discovered
        by 7 detectors (binary, process, mcp, config, shell_history,
        provider_history, desktop_app) and showed up as 7 near-identical
        rows in the default grouped view. Operators wanted "where is
        Claude Code?" -- ONE row per product -- with the constituent
        categories / detectors aggregated as a list, not seven rows.
        """
        from defenseclaw.commands import cmd_agent

        sigs = [
            {"state": "seen", "category": "ai_cli",
             "product": "Claude Code", "vendor": "Anthropic",
             "detector": "binary", "basenames": ["claude"]},
            {"state": "seen", "category": "active_process",
             "product": "Claude Code", "vendor": "Anthropic",
             "detector": "process", "basenames": []},
            {"state": "seen", "category": "mcp_server",
             "product": "Claude Code", "vendor": "Anthropic",
             "detector": "mcp", "basenames": ["settings.json"]},
            {"state": "seen", "category": "supported_app",
             "product": "Claude Code", "vendor": "Anthropic",
             "detector": "config", "basenames": [".claude.json"]},
            {"state": "seen", "category": "shell_history",
             "product": "Claude Code", "vendor": "Anthropic",
             "detector": "shell_history", "basenames": [".zsh_history"]},
            {"state": "seen", "category": "provider_history",
             "product": "Claude Code", "vendor": "Anthropic",
             "detector": "shell_history", "basenames": [".zsh_history"]},
            {"state": "seen", "category": "desktop_app",
             "product": "Claude Code", "vendor": "Anthropic",
             "detector": "application", "basenames": []},
            # A genuinely different product to prove we don't collapse
            # across vendors/products by accident.
            {"state": "seen", "category": "ai_cli",
             "product": "Cursor", "vendor": "Anysphere",
             "detector": "binary", "basenames": ["cursor"]},
        ]
        # Default: normalized view collapses the 7 Claude Code rows
        # into 1 (+ 1 Cursor row).
        rows = cmd_agent._summarize_ai_usage_signals_full(sigs)
        self.assertEqual(len(rows), 2,
                         f"expected 2 rolled-up rows, got: {rows}")
        claude = next(r for r in rows if r["component"] == "" and "Claude Code" in r["key"][2])
        self.assertEqual(claude["count"], 7)
        self.assertEqual(set(claude["categories"]), {
            "ai_cli", "active_process", "mcp_server", "supported_app",
            "shell_history", "provider_history", "desktop_app",
        })
        self.assertEqual(set(claude["detectors"]), {
            "binary", "process", "mcp", "config", "shell_history",
            "application",
        })
        # Legacy 5-tuple slots carry the comma-joined aggregates so
        # downstream parsers (and `_summarize_ai_usage_signals`) keep
        # working without a code change.
        self.assertIn(",", claude["key"][1], "expected joined categories in key")
        self.assertIn(",", claude["key"][4], "expected joined detectors in key")

        # --by-detector flag restores the legacy 7-row split.
        rows_by_det = cmd_agent._summarize_ai_usage_signals_full(
            sigs, by_detector=True,
        )
        self.assertEqual(len(rows_by_det), 8,
                         f"expected 8 rows in --by-detector mode, got: {rows_by_det}")

    def test_normalized_view_does_not_merge_distinct_vendors(self):
        """We collapse across detectors, NEVER across vendor/product.
        Two distinct products from the same vendor (Claude Code +
        Claude Desktop) must remain separate rows."""
        from defenseclaw.commands import cmd_agent

        sigs = [
            {"state": "seen", "category": "ai_cli",
             "product": "Claude Code", "vendor": "Anthropic",
             "detector": "binary", "basenames": []},
            {"state": "seen", "category": "active_process",
             "product": "Claude Desktop", "vendor": "Anthropic",
             "detector": "process", "basenames": []},
        ]
        rows = cmd_agent._summarize_ai_usage_signals_full(sigs)
        products = sorted(r["key"][2] for r in rows)
        self.assertEqual(products, ["Claude Code", "Claude Desktop"])

    def test_render_normalized_grouped_view_uses_plural_columns(self):
        """The default grouped table must rename Category/Detector to
        Categories/Detectors so operators see at a glance that each
        cell now lists multiple values."""
        from defenseclaw.commands import cmd_agent

        payload = {
            "enabled": True,
            "summary": {"active_signals": 2, "scanned_at": "now",
                        "files_scanned": 1},
            "signals": [
                {"state": "seen", "category": "ai_cli",
                 "product": "Claude Code", "vendor": "Anthropic",
                 "detector": "binary", "basenames": []},
                {"state": "seen", "category": "mcp_server",
                 "product": "Claude Code", "vendor": "Anthropic",
                 "detector": "mcp", "basenames": []},
            ],
        }
        out = cmd_agent._render_ai_usage_table(payload)
        self.assertIn("Categories", out)
        self.assertIn("Detectors", out)
        # Single rolled-up Claude Code row.
        self.assertEqual(out.count("Claude"), 1, out)
        # And the column should show both detectors (Rich may
        # truncate them, so check the prefix only).
        self.assertIn("binary", out)
        self.assertIn("mcp", out)

    def test_render_by_detector_flag_keeps_legacy_singular_columns(self):
        """--by-detector reverts to the per-detector splitting and
        keeps the legacy column headers so operators with shell
        aliases see the same shape they always did."""
        from defenseclaw.commands import cmd_agent

        payload = {
            "enabled": True,
            "summary": {"active_signals": 2, "scanned_at": "now",
                        "files_scanned": 1},
            "signals": [
                {"state": "seen", "category": "ai_cli",
                 "product": "Claude Code", "vendor": "Anthropic",
                 "detector": "binary", "basenames": []},
                {"state": "seen", "category": "mcp_server",
                 "product": "Claude Code", "vendor": "Anthropic",
                 "detector": "mcp", "basenames": []},
            ],
        }
        out = cmd_agent._render_ai_usage_table(payload, by_detector=True)
        # Singular headers (regression target).
        self.assertIn("Category", out)
        self.assertIn("Detector", out)
        # And two Claude rows (one per detector) instead of one.
        self.assertEqual(out.count("Claude"), 2, out)

    def test_detail_view_blanks_confidence_after_first_row_in_group(self):
        """Per-component confidence is computed once per (ecosystem,
        name); repeating it on every row was misleading. Only the
        first row of each contiguous group should carry the cell."""
        from defenseclaw.commands import cmd_agent

        sigs = [
            {
                "state": "new",
                "category": "package_dependency",
                "product": "Anthropic Claude",
                "vendor": "Anthropic",
                "detector": "package_manifest",
                "basenames": ["pkg_a.json"],
                "component": {
                    "ecosystem": "npm",
                    "name": "@anthropic-ai/sdk",
                    "version": "0.20.0",
                },
                "identity_score": 0.91,
                "identity_band": "high",
                "presence_score": 0.78,
                "presence_band": "medium",
            },
            {
                "state": "new",
                "category": "package_dependency",
                "product": "Anthropic Claude",
                "vendor": "Anthropic",
                "detector": "package_manifest",
                "basenames": ["pkg_b.json"],
                "component": {
                    "ecosystem": "npm",
                    "name": "@anthropic-ai/sdk",
                    "version": "0.20.0",
                },
                "identity_score": 0.91,
                "identity_band": "high",
                "presence_score": 0.78,
                "presence_band": "medium",
            },
        ]
        payload = {
            "enabled": True,
            "summary": {"active_signals": 2, "new_signals": 2,
                        "changed_signals": 0, "gone_signals": 0,
                        "scanned_at": "2026-05-05T00:00:00Z",
                        "files_scanned": 2},
            "signals": sigs,
        }
        out = cmd_agent._render_ai_usage_table(payload, detail=True)
        # Both pkg_*.json files appear (per-signal table). Rich
        # truncates long cells with "…", so we assert on the unique
        # prefix of each filename.
        self.assertIn("pkg_a", out)
        self.assertIn("pkg_b", out)
        # The band/% must show exactly once per pair, not twice.
        # We check the percentage token (uniquely identifying the
        # score) instead of the full "<band> (XX%)" string because
        # Rich may line-wrap a single cell.
        self.assertEqual(out.count("91%"), 1, out)
        self.assertEqual(out.count("78%"), 1, out)


class AiUsageCommandFlagsTests(unittest.TestCase):
    """End-to-end flag wiring for ``defenseclaw agent usage``.

    These complement the rendering unit tests by ensuring Click parses
    the new flags and forwards them to the renderer.
    """

    def setUp(self):
        self.runner = CliRunner()

    def _invoke(self, app, args):
        class FakeClient:
            def __init__(self, **_kwargs):
                pass

            def ai_usage(self):
                return _wide_payload()

        with patch("defenseclaw.commands.cmd_agent.OrchestratorClient", FakeClient):
            return self.runner.invoke(
                agent,
                ["usage", *args],
                obj=app,
                catch_exceptions=False,
            )

    def test_default_renders_grouped_summary(self):
        app, tmp_dir, db_path = make_app_context()
        app.cfg.gateway.token = "secret-token-123"
        try:
            result = self._invoke(app, [])
        finally:
            cleanup_app(app, db_path, tmp_dir)
        self.assertEqual(result.exit_code, 0, result.output)
        # One grouped row instead of 488 — the original bug fix.
        self.assertEqual(result.output.count("package_dependency"), 1)
        self.assertIn("488", result.output)
        self.assertIn("Sample evidence", result.output)

    def test_detail_flag_shows_full_table(self):
        app, tmp_dir, db_path = make_app_context()
        app.cfg.gateway.token = "secret-token-123"
        try:
            result = self._invoke(app, ["--detail"])
        finally:
            cleanup_app(app, db_path, tmp_dir)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(result.output.count("package_dependency"), 488)

    def test_state_flag_validates_choice(self):
        app, tmp_dir, db_path = make_app_context()
        app.cfg.gateway.token = "secret-token-123"
        try:
            result = self._invoke(app, ["--state", "bogus"])
        finally:
            cleanup_app(app, db_path, tmp_dir)
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Invalid value for '--state'", result.output)

    def test_negative_limit_is_rejected(self):
        app, tmp_dir, db_path = make_app_context()
        app.cfg.gateway.token = "secret-token-123"
        try:
            result = self._invoke(app, ["--limit", "-1"])
        finally:
            cleanup_app(app, db_path, tmp_dir)
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("--limit", result.output)


if __name__ == "__main__":
    unittest.main()
