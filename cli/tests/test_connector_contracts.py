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

"""Tests for setup-time connector hook compatibility checks."""

from __future__ import annotations

import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_setup import (
    _apply_hook_connector_setup,
    _check_connector_version_supported_for_setup,
    _print_connector_observability_banner,
)
from defenseclaw.connector_contracts import (
    HOOK_CONTRACT_MANIFEST,
    HOOK_CONTRACTS,
    PROXY_CONNECTORS,
    STATUS_KNOWN,
    STATUS_NOT_GATED,
    STATUS_UNKNOWN,
    STATUS_UNVERSIONED,
    _load_contracts_from_manifest,
    resolve_connector_contract,
)
from defenseclaw.connector_paths import KNOWN_CONNECTORS

from tests.helpers import cleanup_app, make_app_context


def _discovery(connector: str, *, installed: bool, version: str, error: str = ""):
    return SimpleNamespace(
        agents={
            connector: SimpleNamespace(
                installed=installed,
                version=version,
                error=error,
            )
        }
    )


class TestConnectorContractManifest(unittest.TestCase):
    """The packaged JSON manifest is the setup-time source of truth."""

    def test_manifest_covers_every_connector(self) -> None:
        self.assertEqual(HOOK_CONTRACT_MANIFEST["schema_version"], 2)
        self.assertEqual(
            set(HOOK_CONTRACT_MANIFEST["connectors"]),
            set(KNOWN_CONNECTORS),
        )

    def test_proxy_connectors_are_not_hook_gated(self) -> None:
        self.assertEqual(PROXY_CONNECTORS, frozenset({"openclaw", "zeptoclaw"}))
        for connector in PROXY_CONNECTORS:
            compat = resolve_connector_contract(connector, "9.9.9")
            self.assertEqual(compat.status, STATUS_NOT_GATED)
            self.assertTrue(compat.supported)

    def test_antigravity_cli_alias_resolves_without_becoming_gemini_cli(self) -> None:
        antigravity = resolve_connector_contract("agy", "Antigravity CLI v1.1.9")
        self.assertEqual(antigravity.connector, "antigravity")
        self.assertEqual(antigravity.status, STATUS_KNOWN)
        self.assertEqual(antigravity.contract.contract_id, "antigravity-hooks-v2")
        expected_max_version = "" if sys.platform == "win32" else "1.1.10"
        self.assertEqual(antigravity.contract.max_agent_version, expected_max_version)
        self.assertNotEqual(antigravity.connector, "geminicli")

        future = resolve_connector_contract("agy", "Antigravity CLI v1.1.10")
        if sys.platform == "win32":
            self.assertEqual(future.status, STATUS_KNOWN)
            self.assertTrue(future.supported)
        else:
            self.assertEqual(future.status, STATUS_UNKNOWN)
            self.assertFalse(future.supported)

    def test_codex_version_range_matches_contract(self) -> None:
        expected = (
            (
                "0.124.0",
                "codex-hooks-v1",
                (
                    "SessionStart",
                    "UserPromptSubmit",
                    "PreToolUse",
                    "PermissionRequest",
                    "PostToolUse",
                    "Stop",
                ),
            ),
            (
                "0.128.99",
                "codex-hooks-v1",
                (
                    "SessionStart",
                    "UserPromptSubmit",
                    "PreToolUse",
                    "PermissionRequest",
                    "PostToolUse",
                    "Stop",
                ),
            ),
            (
                "0.129.0",
                "codex-hooks-v2",
                (
                    "SessionStart",
                    "UserPromptSubmit",
                    "PreToolUse",
                    "PermissionRequest",
                    "PostToolUse",
                    "PreCompact",
                    "PostCompact",
                    "Stop",
                ),
            ),
            (
                "0.132.99",
                "codex-hooks-v2",
                (
                    "SessionStart",
                    "UserPromptSubmit",
                    "PreToolUse",
                    "PermissionRequest",
                    "PostToolUse",
                    "PreCompact",
                    "PostCompact",
                    "Stop",
                ),
            ),
            (
                "0.133.0",
                "codex-hooks-v3",
                (
                    "SessionStart",
                    "UserPromptSubmit",
                    "PreToolUse",
                    "PermissionRequest",
                    "PostToolUse",
                    "SubagentStart",
                    "SubagentStop",
                    "PreCompact",
                    "PostCompact",
                    "Stop",
                ),
            ),
            (
                "0.144.99",
                "codex-hooks-v3",
                (
                    "SessionStart",
                    "UserPromptSubmit",
                    "PreToolUse",
                    "PermissionRequest",
                    "PostToolUse",
                    "SubagentStart",
                    "SubagentStop",
                    "PreCompact",
                    "PostCompact",
                    "Stop",
                ),
            ),
            (
                "0.145.0",
                "codex-hooks-v4",
                (
                    "SessionStart",
                    "UserPromptSubmit",
                    "PreToolUse",
                    "PermissionRequest",
                    "PostToolUse",
                    "SubagentStart",
                    "SubagentStop",
                    "PreCompact",
                    "PostCompact",
                    "Stop",
                    "SessionEnd",
                ),
            ),
        )
        for version, contract_id, events in expected:
            with self.subTest(version=version):
                known = resolve_connector_contract("codex", f"codex {version}")
                self.assertEqual(known.status, STATUS_KNOWN)
                self.assertEqual(known.normalized_version, version)
                self.assertEqual(known.contract.contract_id, contract_id)
                self.assertEqual(known.contract.events, events)
                self.assertEqual(known.contract.hook_script_version, "v6")
                self.assertIn("~/.codex/config.toml", known.contract.hook_config_path_templates)
                self.assertIn(
                    "~/.codex/managed_config.toml",
                    known.contract.hook_config_path_templates,
                )
                self.assertIn("tool_call", known.contract.aid_surfaces)

        unversioned = resolve_connector_contract("codex", "")
        self.assertEqual(unversioned.status, STATUS_UNVERSIONED)
        self.assertEqual(unversioned.contract.contract_id, "codex-hooks-v4")
        self.assertTrue(unversioned.contract.default_for_unversioned)
        self.assertTrue(unversioned.contract.native_otlp)
        self.assertEqual(unversioned.contract.native_otlp_auth, "header-token")
        self.assertEqual(
            unversioned.contract.native_otlp_signals,
            ("logs", "metrics", "traces"),
        )
        self.assertEqual(
            unversioned.contract.native_otlp_endpoint_template,
            "/v1/<signal>",
        )
        self.assertNotIn("<scoped-token>", unversioned.contract.native_otlp_endpoint_template)

        older = resolve_connector_contract("codex", "codex 0.123.0")
        self.assertEqual(older.status, STATUS_UNKNOWN)
        self.assertFalse(older.supported)

    def test_codex_setup_banner_describes_scoped_otlp_routes(self) -> None:
        with patch("defenseclaw.commands.cmd_setup.click.echo") as echo:
            _print_connector_observability_banner("codex")
        rendered = "\n".join(str(call.args[0]) for call in echo.call_args_list if call.args)
        self.assertIn("scoped bearer + source header on /v1/<signal>", rendered)
        self.assertNotIn("/otlp/codex/<token>", rendered)

    def test_claude_aliases_resolve_to_claudecode(self) -> None:
        compat = resolve_connector_contract("claude-code", "Claude Code 2.1.154")
        self.assertEqual(compat.status, STATUS_KNOWN)
        self.assertEqual(compat.connector, "claudecode")
        self.assertEqual(compat.contract.contract_id, "claudecode-hooks-v1")
        self.assertEqual(compat.contract.hook_script_version, "v7")
        self.assertIn("event_content", compat.contract.aid_surfaces)

    def test_copilot_platform_contract_preserves_windows_selection(self) -> None:
        darwin = resolve_connector_contract("copilot", "", platform_name="darwin")
        windows = resolve_connector_contract("copilot", "", platform_name="windows")

        self.assertEqual(darwin.contract.contract_id, "copilot-hooks-v2")
        self.assertTrue(darwin.contract.native_otlp)
        self.assertEqual(darwin.contract.native_otlp_auth, "otel-exporter-headers")
        self.assertEqual(darwin.contract.native_otlp_signals, ("metrics", "traces"))
        self.assertIn("userPromptTransformed", darwin.contract.events)
        self.assertTrue(
            any("does not configure that exporter" in note for note in darwin.contract.notes)
        )

        self.assertEqual(windows.contract.contract_id, "copilot-hooks-v2")
        self.assertFalse(windows.contract.native_otlp)
        self.assertEqual(windows.contract.native_otlp_auth, "")
        self.assertEqual(windows.contract.native_otlp_signals, ())
        self.assertIn("userPromptTransformed", windows.contract.events)

        current_darwin = resolve_connector_contract(
            "copilot", "GitHub Copilot CLI 1.0.76", platform_name="darwin"
        )
        current_windows = resolve_connector_contract(
            "copilot", "GitHub Copilot CLI 1.0.76", platform_name="windows"
        )
        latest_windows = resolve_connector_contract(
            "copilot", "GitHub Copilot CLI 1.0.77", platform_name="windows"
        )
        self.assertEqual(current_darwin.contract.contract_id, "copilot-hooks-v2")
        self.assertEqual(current_windows.contract.contract_id, "copilot-hooks-v2")
        self.assertEqual(latest_windows.contract.contract_id, "copilot-hooks-v2")

        historical = resolve_connector_contract(
            "copilot", "GitHub Copilot CLI 1.0.75", platform_name="darwin"
        )
        self.assertEqual(historical.contract.contract_id, "copilot-hooks-v1")
        self.assertNotIn("userPromptTransformed", historical.contract.events)

    def test_manifest_platform_overrides_preserve_windows_and_darwin_contracts(self) -> None:
        _, darwin = _load_contracts_from_manifest(
            HOOK_CONTRACT_MANIFEST,
            platform_name="darwin",
        )
        _, windows = _load_contracts_from_manifest(
            HOOK_CONTRACT_MANIFEST,
            platform_name="windows",
        )

        def contract(contracts, connector, contract_id):
            return next(
                item for item in contracts[connector] if item.contract_id == contract_id
            )

        darwin_hermes = contract(darwin, "hermes", "hermes-hooks-v1")
        windows_hermes = contract(windows, "hermes", "hermes-hooks-v1")
        self.assertEqual(darwin_hermes.max_agent_version, "0.20.0")
        self.assertEqual(windows_hermes.max_agent_version, "")

        darwin_antigravity = contract(darwin, "antigravity", "antigravity-hooks-v2")
        windows_antigravity = contract(windows, "antigravity", "antigravity-hooks-v2")
        self.assertEqual(darwin_antigravity.max_agent_version, "1.1.10")
        self.assertEqual(windows_antigravity.max_agent_version, "")

        darwin_openhands = contract(darwin, "openhands", "openhands-hooks-v1")
        windows_openhands = contract(windows, "openhands", "openhands-hooks-v1")
        self.assertEqual(darwin_openhands.min_agent_version, "1.12.0")
        self.assertTrue(darwin_openhands.native_otlp)
        self.assertEqual(windows_openhands.min_agent_version, "0.0.0")
        self.assertFalse(windows_openhands.native_otlp)

        darwin_opencode = contract(darwin, "opencode", "opencode-hooks-v1")
        windows_opencode = contract(windows, "opencode", "opencode-hooks-v1")
        self.assertEqual(
            (
                darwin_opencode.min_agent_version,
                darwin_opencode.max_agent_version,
                darwin_opencode.default_for_unversioned,
                darwin_opencode.hook_script_version,
                len(darwin_opencode.events),
                darwin_opencode.aid_surfaces,
            ),
            (
                "1.16.2",
                "1.18.11",
                False,
                "v7",
                35,
                ("tool_call", "tool_result", "event_content"),
            ),
        )
        self.assertEqual(
            (
                windows_opencode.min_agent_version,
                windows_opencode.max_agent_version,
                windows_opencode.default_for_unversioned,
                windows_opencode.hook_script_version,
                len(windows_opencode.events),
                windows_opencode.aid_surfaces,
            ),
            ("0.0.0", "", True, "v6", 9, ("tool_call", "tool_result")),
        )

        for platform_contracts in (darwin, windows):
            copilot_v1 = contract(platform_contracts, "copilot", "copilot-hooks-v1")
            copilot_v2 = contract(platform_contracts, "copilot", "copilot-hooks-v2")
            self.assertEqual(
                (
                    copilot_v1.min_agent_version,
                    copilot_v1.max_agent_version,
                    copilot_v1.default_for_unversioned,
                    len(copilot_v1.events),
                ),
                ("1.0.18", "1.0.76", False, 13),
            )
            self.assertEqual(
                (
                    copilot_v2.min_agent_version,
                    copilot_v2.max_agent_version,
                    copilot_v2.default_for_unversioned,
                    len(copilot_v2.events),
                ),
                ("1.0.76", "", True, 14),
            )

    def test_unversioned_connectors_use_default_contract(self) -> None:
        compat = resolve_connector_contract("cursor", "")
        self.assertEqual(compat.status, STATUS_UNVERSIONED)
        self.assertTrue(compat.supported)
        self.assertEqual(compat.contract.contract_id, "cursor-hooks-v1")
        self.assertTrue(compat.contract.default_for_unversioned)

        self.assertIn("geminicli", HOOK_CONTRACTS)
        gemini = resolve_connector_contract("gemini-cli", "")
        self.assertEqual(gemini.connector, "geminicli")
        self.assertEqual(gemini.status, STATUS_UNVERSIONED)

    def test_cursor_current_preview_contract_is_pinned_to_exact_agent_build(self) -> None:
        for raw_version in (
            "2026.07.23-e383d2b",
            "agent v2026.07.23-e383d2b",
            "cursor-agent 2026.07.23-e383d2b",
        ):
            with self.subTest(raw_version=raw_version):
                compat = resolve_connector_contract("cursor", raw_version)
                self.assertEqual(compat.status, STATUS_KNOWN)
                self.assertEqual(compat.contract.contract_id, "cursor-hooks-v1")
                self.assertIn("subagentStart", compat.contract.capabilities["block_events"])
                self.assertNotIn("subagentStart", compat.contract.capabilities["ask_events"])

        for raw_version in (
            "cursor-agent 2026.07.23-deadbee",
            "cursor 3.13.21",
            "Cursor Agent 2026.07.23-e383d2b",
        ):
            with self.subTest(raw_version=raw_version):
                compat = resolve_connector_contract("cursor", raw_version)
                self.assertEqual(compat.status, STATUS_UNKNOWN)
                self.assertFalse(compat.supported)

    def test_openhands_cli_version_matches_documented_contract(self) -> None:
        compat = resolve_connector_contract("openhands", "OpenHands CLI 1.16.0")
        self.assertEqual(compat.status, STATUS_KNOWN)
        self.assertEqual(compat.normalized_version, "1.16.0")
        self.assertEqual(compat.contract.contract_id, "openhands-hooks-v1")
        self.assertEqual(compat.contract.hook_script_version, "v6")
        self.assertIn("<workspace>/.openhands/hooks.json", compat.contract.hook_config_path_templates)
        self.assertIn("~/.openhands/hooks.json", compat.contract.hook_config_path_templates)
        self.assertIn("event_content", compat.contract.aid_surfaces)

    def test_omnigent_contract_advertises_config_home_override(self) -> None:
        compat = resolve_connector_contract("omnigent", "")
        templates = compat.contract.hook_config_path_templates

        self.assertEqual(compat.status, STATUS_UNVERSIONED)
        self.assertEqual(compat.contract.min_agent_version, "0.7.0")
        self.assertIn("$OMNIGENT_CONFIG_HOME/config.yaml", templates)
        self.assertIn("~/.omnigent/config.yaml", templates)
        self.assertLess(
            templates.index("$OMNIGENT_CONFIG_HOME/config.yaml"),
            templates.index("~/.omnigent/config.yaml"),
        )

        before_floor = resolve_connector_contract("omnigent", "omnigent 0.6.99")
        self.assertFalse(before_floor.supported)
        self.assertEqual(before_floor.status, STATUS_UNKNOWN)

        proven = resolve_connector_contract("omnigent", "omnigent 0.7.0")
        self.assertTrue(proven.supported)
        self.assertEqual(proven.status, STATUS_KNOWN)
        self.assertEqual(proven.contract.contract_id, "omnigent-custom-policy-v1")

    def test_hermes_contract_advertises_native_windows_path_precedence(self) -> None:
        compat = resolve_connector_contract("hermes", "")

        self.assertEqual(
            compat.contract.hook_config_path_templates,
            (
                "$HERMES_HOME/config.yaml",
                "%LOCALAPPDATA%/hermes/config.yaml",
                "~/.hermes/config.yaml",
            ),
        )

    def test_manifest_loader_preserves_unversioned_default_marker(self) -> None:
        _, contracts = _load_contracts_from_manifest(
            {
                "connectors": {
                    "codex": {
                        "kind": "hook",
                        "compatibility_gate": "hook-contract",
                        "contracts": [
                            {
                                "contract_id": "codex-hooks-v1",
                                "agent_version": {"min_inclusive": "0.124.0"},
                            },
                            {
                                "contract_id": "codex-hooks-v2",
                                "agent_version": {"min_inclusive": "0.130.0"},
                                "default_for_unversioned": True,
                            },
                        ],
                    }
                }
            }
        )

        self.assertEqual(contracts["codex"][0].contract_id, "codex-hooks-v1")
        self.assertFalse(contracts["codex"][0].default_for_unversioned)
        self.assertTrue(contracts["codex"][1].default_for_unversioned)

    def test_manifest_loader_rejects_unknown_platform_override(self) -> None:
        manifest = {
            "connectors": {
                "codex": {
                    "contracts": [
                        {
                            "contract_id": "codex-hooks-v1",
                            "platform_overrides": {"plan9": {}},
                        }
                    ]
                }
            }
        }
        with self.assertRaisesRegex(ValueError, "unknown platform override 'plan9'"):
            _load_contracts_from_manifest(manifest, platform_name="darwin")

    def test_manifest_loader_rejects_invalid_platform_override(self) -> None:
        invalid_overrides = (
            ({"windows": []}, "must be an object"),
            ({"windows": {"contract_id": "replacement"}}, "unknown fields"),
            ({"windows": {"native_otlp": "false"}}, "must be a boolean"),
            (
                {"windows": {"agent_version": {"max_exclusive": 20}}},
                "must be a string",
            ),
            ({"windows": {"events": "event"}}, "must be a string list"),
        )
        for override, message in invalid_overrides:
            with self.subTest(override=override):
                manifest = {
                    "connectors": {
                        "codex": {
                            "contracts": [
                                {
                                    "contract_id": "codex-hooks-v1",
                                    "platform_overrides": override,
                                }
                            ]
                        }
                    }
                }
                with self.assertRaisesRegex(ValueError, message):
                    _load_contracts_from_manifest(manifest, platform_name="darwin")

    def test_manifest_loader_rejects_unknown_requested_platform(self) -> None:
        with self.assertRaisesRegex(ValueError, "darwin, linux, or windows"):
            _load_contracts_from_manifest(
                {"connectors": {}},
                platform_name="plan9",
            )


class TestSetupConnectorVersionGate(unittest.TestCase):
    """Setup commands should fail before mutation on unsupported action-mode hooks."""

    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.app.cfg.claw.mode = "openclaw"
        self.app.cfg.guardrail.connector = "openclaw"
        self.save_calls = 0

        def _save():
            self.save_calls += 1

        self.app.cfg.save = _save  # type: ignore[assignment]

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def test_action_mode_blocks_unsupported_installed_version_before_save(self) -> None:
        with patch(
            "defenseclaw.commands.cmd_setup.agent_discovery.discover_agents",
            return_value=_discovery("codex", installed=True, version="codex 0.123.0"),
        ), patch.dict(os.environ, {"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT": "0"}):
            ok = _apply_hook_connector_setup(
                self.app,
                connector="codex",
                mode="action",
                restart=False,
            )

        self.assertFalse(ok)
        self.assertEqual(self.save_calls, 0)
        self.assertEqual(self.app.cfg.claw.mode, "openclaw")
        self.assertEqual(self.app.cfg.guardrail.connector, "openclaw")

    def test_observe_mode_warns_but_allows_unsupported_installed_version(self) -> None:
        with patch(
            "defenseclaw.commands.cmd_setup.agent_discovery.discover_agents",
            return_value=_discovery("codex", installed=True, version="codex 0.123.0"),
        ), patch("defenseclaw.commands.cmd_setup._record_windows_setup_agent_selections"):
            ok = _apply_hook_connector_setup(
                self.app,
                connector="codex",
                mode="observe",
                restart=False,
            )

        self.assertTrue(ok)
        self.assertEqual(self.save_calls, 1)
        self.assertEqual(self.app.cfg.claw.mode, "codex")
        self.assertEqual(self.app.cfg.guardrail.mode, "observe")

    def test_alias_connector_writes_canonical_key(self) -> None:
        """Passing an alias (e.g. "claude-code") must persist the canonical
        registry name so guardrail.connectors / guardrail.connector never hold
        an alias that would collide with the canonical key (which
        GuardrailConfig.Validate now rejects at load)."""
        with patch(
            "defenseclaw.commands.cmd_setup.agent_discovery.discover_agents",
            return_value=_discovery("claudecode", installed=True, version="2.1.154"),
        ):
            ok = _apply_hook_connector_setup(
                self.app,
                connector="claude-code",
                mode="observe",
                restart=False,
            )

        self.assertTrue(ok)
        self.assertEqual(self.app.cfg.guardrail.connector, "claudecode")
        self.assertEqual(self.app.cfg.claw.mode, "claudecode")

    def test_action_mode_allows_supported_installed_version(self) -> None:
        with (
            patch(
                "defenseclaw.commands.cmd_setup.agent_discovery.discover_agents",
                return_value=_discovery("claudecode", installed=True, version="2.1.154"),
            ),
            patch("defenseclaw.commands.cmd_setup._sync_guardrail_hilt_to_opa") as sync_hilt,
        ):
            ok = _apply_hook_connector_setup(
                self.app,
                connector="claudecode",
                mode="action",
                restart=False,
            )

        self.assertTrue(ok)
        self.assertEqual(self.save_calls, 1)
        self.assertEqual(self.app.cfg.claw.mode, "claudecode")
        self.assertEqual(self.app.cfg.guardrail.mode, "action")
        sync_hilt.assert_called_once_with(self.app.cfg.policy_dir, self.app.cfg.guardrail)

    def test_action_mode_blocks_unversioned_installed_connector(self) -> None:
        with patch(
            "defenseclaw.commands.cmd_setup.agent_discovery.discover_agents",
            return_value=_discovery(
                "geminicli",
                installed=True,
                version="",
                error="version probe timed out",
            ),
        ), patch.dict(os.environ, {"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT": "0"}):
            ok = _check_connector_version_supported_for_setup(
                "gemini-cli",
                mode="action",
                emit=False,
            )

        self.assertFalse(ok)

    def test_action_mode_allows_unversioned_installed_connector_with_drift_override(self) -> None:
        with patch(
            "defenseclaw.commands.cmd_setup.agent_discovery.discover_agents",
            return_value=_discovery("geminicli", installed=True, version=""),
        ), patch.dict(os.environ, {"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT": "1"}):
            ok = _check_connector_version_supported_for_setup(
                "gemini-cli",
                mode="action",
                emit=False,
            )

        self.assertTrue(ok)

    def test_action_mode_fails_closed_when_hook_discovery_errors(self) -> None:
        with patch(
            "defenseclaw.commands.cmd_setup.agent_discovery.discover_agents",
            side_effect=RuntimeError("boom"),
        ), patch.dict(os.environ, {"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT": "0"}):
            ok = _check_connector_version_supported_for_setup(
                "codex",
                mode="action",
                emit=False,
            )

        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
