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

import json
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_setup import (
    _apply_hook_connector_setup,
    _check_connector_version_supported_for_setup,
    _connector_contract_upgrade_guidance,
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

REPO_ROOT = Path(__file__).resolve().parents[2]


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
        self.assertEqual(HOOK_CONTRACT_MANIFEST["schema_version"], 1)
        self.assertEqual(
            set(HOOK_CONTRACT_MANIFEST["connectors"]),
            set(KNOWN_CONNECTORS),
        )

    def test_live_e2e_pretool_goldens_follow_exact_default_contract(self) -> None:
        golden_root = REPO_ROOT / "scripts" / "live-connector-e2e" / "golden"
        for connector_dir in sorted(golden_root.iterdir()):
            manifest = HOOK_CONTRACT_MANIFEST["connectors"].get(connector_dir.name)
            if manifest is None:
                continue
            contracts = manifest.get("contracts", ())
            contract = next(
                (item for item in contracts if item.get("default_for_unversioned")),
                contracts[0],
            )
            structured = set(contract["tool_call_lifecycle"]["routing"]["structured_action_events"])
            blocked = set(contract["capabilities"]["block_events"])
            for fixture_name in ("pre_tool_allow.json", "pre_tool_block.json"):
                fixture = connector_dir / fixture_name
                if not fixture.is_file():
                    continue
                payload = json.loads(fixture.read_text(encoding="utf-8"))
                event = payload.get("hook_event_name")
                if event is None and connector_dir.name == "antigravity" and "toolCall" in payload:
                    event = "PreToolUse"
                with self.subTest(connector=connector_dir.name, fixture=fixture_name):
                    self.assertIsNotNone(event)
                    self.assertIn(event, structured)
                    if fixture_name == "pre_tool_block.json":
                        self.assertIn(event, blocked)

    def test_proxy_connectors_are_not_hook_gated(self) -> None:
        self.assertEqual(PROXY_CONNECTORS, frozenset({"openclaw", "zeptoclaw"}))
        for connector in PROXY_CONNECTORS:
            compat = resolve_connector_contract(connector, "9.9.9")
            self.assertEqual(compat.status, STATUS_NOT_GATED)
            self.assertTrue(compat.supported)

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
                "0.134.99",
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
                "0.135.0",
                "codex-hooks-v3-generic",
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
                "codex-hooks-v3-generic",
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

    def test_claude_directory_added_contract_boundary_is_exact(self) -> None:
        cases = (
            ("Claude Code 2.1.218", "claudecode-hooks-v1", 28, False),
            ("Claude Code 2.1.219", "claudecode-hooks-v2", 29, True),
            ("Claude Code 2.1.220", "claudecode-hooks-v2", 29, True),
        )
        for version, contract_id, event_count, has_directory_added in cases:
            with self.subTest(version=version):
                compat = resolve_connector_contract("claudecode", version)
                self.assertEqual(compat.status, STATUS_KNOWN)
                self.assertEqual(compat.contract.contract_id, contract_id)
                self.assertEqual(len(compat.contract.events), event_count)
                self.assertEqual(
                    "DirectoryAdded" in compat.contract.events,
                    has_directory_added,
                )
                self.assertNotIn(
                    "DirectoryAdded",
                    compat.contract.capabilities["block_events"],
                )
                self.assertNotIn(
                    "DirectoryAdded",
                    compat.contract.capabilities["ask_events"],
                )

    def test_copilot_contract_does_not_claim_native_otlp(self) -> None:
        compat = resolve_connector_contract("copilot", "")

        self.assertEqual(compat.contract.contract_id, "copilot-hooks-v2")
        self.assertFalse(compat.contract.native_otlp)
        self.assertEqual(compat.contract.native_otlp_auth, "")
        self.assertEqual(compat.contract.native_otlp_signals, ())
        self.assertEqual(compat.contract.native_otlp_endpoint_template, "")

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

    def test_cursor_current_supported_contract_is_pinned_to_exact_agent_build(self) -> None:
        for raw_version in (
            "2026.07.23-e383d2b",
            "agent v2026.07.23-e383d2b",
            "cursor-agent 2026.07.23-e383d2b",
        ):
            with self.subTest(raw_version=raw_version):
                compat = resolve_connector_contract("cursor", raw_version)
                self.assertEqual(compat.status, STATUS_KNOWN)
                self.assertEqual(compat.contract.contract_id, "cursor-hooks-v1")
                self.assertIn("subagentStart", compat.contract.events)
                self.assertEqual(
                    compat.contract.capabilities["block_events"],
                    [
                        "preToolUse",
                        "subagentStart",
                        "beforeShellExecution",
                        "beforeMCPExecution",
                        "beforeReadFile",
                        "beforeTabFileRead",
                        "beforeSubmitPrompt",
                    ],
                )
                self.assertEqual(compat.contract.capabilities["ask_events"], [])
                self.assertFalse(compat.contract.capabilities["can_ask_native"])

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
        self.assertEqual(compat.contract.max_agent_version, "0.8.0")
        self.assertIn("$OMNIGENT_CONFIG", templates)
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

        after_reviewed_range = resolve_connector_contract("omnigent", "omnigent 0.8.0")
        self.assertFalse(after_reviewed_range.supported)
        self.assertEqual(after_reviewed_range.status, STATUS_UNKNOWN)

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

        installed_but_unsupported = resolve_connector_contract(
            "hermes", "Hermes Agent v0.17.0"
        )
        self.assertEqual(installed_but_unsupported.normalized_version, "0.17.0")
        self.assertEqual(installed_but_unsupported.status, STATUS_UNKNOWN)
        self.assertFalse(installed_but_unsupported.supported)

        audited = resolve_connector_contract("hermes", "Hermes Agent v0.19.0")
        self.assertEqual(audited.status, STATUS_KNOWN)
        self.assertTrue(audited.supported)
        self.assertEqual(audited.contract.contract_id, "hermes-hooks-v1")

        latest_rechecked = resolve_connector_contract("hermes", "Hermes Agent v0.19.1")
        self.assertEqual(latest_rechecked.status, STATUS_KNOWN)
        self.assertTrue(latest_rechecked.supported)
        self.assertEqual(latest_rechecked.contract.contract_id, "hermes-hooks-v1")

        v020 = resolve_connector_contract("hermes", "Hermes Agent v0.20.0 (2026.8.3)")
        self.assertEqual(v020.normalized_version, "0.20.0")
        self.assertEqual(v020.status, STATUS_KNOWN)
        self.assertTrue(v020.supported)
        self.assertEqual(v020.contract.contract_id, "hermes-hooks-v1")

        unreviewed = resolve_connector_contract("hermes", "Hermes Agent v0.21.0")
        self.assertEqual(unreviewed.status, STATUS_UNKNOWN)
        self.assertFalse(unreviewed.supported)

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
        with (
            patch(
                "defenseclaw.commands.cmd_setup.agent_discovery.discover_agents",
                return_value=_discovery("codex", installed=True, version="codex 0.123.0"),
            ),
            patch.dict(os.environ, {"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT": "0"}),
        ):
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

    def test_hermes_action_mode_detects_but_rejects_v017_before_save(self) -> None:
        with patch(
            "defenseclaw.commands.cmd_setup.agent_discovery.discover_agents",
            return_value=_discovery(
                "hermes",
                installed=True,
                version="Hermes Agent v0.17.0",
            ),
        ), patch.dict(os.environ, {"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT": "0"}):
            ok = _apply_hook_connector_setup(
                self.app,
                connector="hermes",
                mode="action",
                restart=False,
            )

        self.assertFalse(ok)
        self.assertEqual(self.save_calls, 0)
        self.assertEqual(self.app.cfg.claw.mode, "openclaw")
        self.assertEqual(self.app.cfg.guardrail.connector, "openclaw")

    def test_peer_observe_mode_warns_and_stages_unsupported_installed_version(self) -> None:
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
        self.assertEqual(self.app.cfg.guardrail.connector, "codex")

    def test_opencode_11811_is_exactly_supported(self) -> None:
        resolved = resolve_connector_contract("opencode", "opencode 1.18.11")
        self.assertEqual(resolved.status, STATUS_KNOWN)
        self.assertEqual(resolved.contract.contract_id, "opencode-hooks-v1")

        with (
            patch(
                "defenseclaw.commands.cmd_setup.agent_discovery.discover_agents",
                return_value=_discovery("opencode", installed=True, version="opencode 1.18.11"),
            ),
            patch(
                "defenseclaw.commands.cmd_setup.platform_support.host_os",
                return_value="linux",
            ),
            patch("defenseclaw.commands.cmd_setup._record_windows_setup_agent_selections"),
        ):
            ok = _apply_hook_connector_setup(
                self.app,
                connector="opencode",
                mode="action",
                restart=False,
            )

        self.assertTrue(ok)
        self.assertEqual(self.save_calls, 1)
        self.assertEqual(self.app.cfg.guardrail.connector, "opencode")

    def test_opencode_version_guidance_distinguishes_old_from_new(self) -> None:
        old = _connector_contract_upgrade_guidance("opencode", "OpenCode", "1.18.9")
        current = _connector_contract_upgrade_guidance("opencode", "OpenCode", "1.18.12")

        self.assertIn("Upgrade OpenCode", old)
        self.assertIn("older than the validated minimum", old)
        self.assertNotIn("Upgrade OpenCode", current)
        self.assertIn("newer than DefenseClaw's validated range", current)

    def test_opencode_11812_is_refused_before_save_and_roster_mutation(self) -> None:
        with (
            patch(
                "defenseclaw.commands.cmd_setup.agent_discovery.discover_agents",
                return_value=_discovery("opencode", installed=True, version="opencode 1.18.12"),
            ),
            patch(
                "defenseclaw.commands.cmd_setup.platform_support.host_os",
                return_value="linux",
            ),
            patch.dict(os.environ, {"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT": "0"}),
        ):
            ok = _apply_hook_connector_setup(
                self.app,
                connector="opencode",
                mode="observe",
                restart=False,
            )

        self.assertFalse(ok)
        self.assertEqual(self.save_calls, 0)
        self.assertEqual(self.app.cfg.claw.mode, "openclaw")
        self.assertEqual(self.app.cfg.guardrail.connector, "openclaw")

    def test_alias_connector_writes_canonical_key(self) -> None:
        """Passing an alias (e.g. "claude-code") must persist the canonical
        registry name so guardrail.connectors / guardrail.connector never hold
        an alias that would collide with the canonical key (which
        GuardrailConfig.Validate now rejects at load)."""
        with patch(
            "defenseclaw.commands.cmd_setup.agent_discovery.discover_agents",
            return_value=_discovery("claudecode", installed=True, version="2.1.154"),
        ), patch("defenseclaw.commands.cmd_setup._record_windows_setup_agent_selections"):
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
            patch("defenseclaw.commands.cmd_setup._record_windows_setup_agent_selections"),
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
        with (
            patch(
                "defenseclaw.commands.cmd_setup.agent_discovery.discover_agents",
                return_value=_discovery(
                    "geminicli",
                    installed=True,
                    version="",
                    error="version probe timed out",
                ),
            ),
            patch.dict(os.environ, {"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT": "0"}),
        ):
            ok = _check_connector_version_supported_for_setup(
                "gemini-cli",
                mode="action",
                emit=False,
            )

        self.assertFalse(ok)

    def test_action_mode_allows_unversioned_installed_connector_with_drift_override(self) -> None:
        with (
            patch(
                "defenseclaw.commands.cmd_setup.agent_discovery.discover_agents",
                return_value=_discovery("geminicli", installed=True, version=""),
            ),
            patch.dict(os.environ, {"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT": "1"}),
        ):
            ok = _check_connector_version_supported_for_setup(
                "gemini-cli",
                mode="action",
                emit=False,
            )

        self.assertTrue(ok)

    def test_action_mode_fails_closed_when_hook_discovery_errors(self) -> None:
        with (
            patch(
                "defenseclaw.commands.cmd_setup.agent_discovery.discover_agents",
                side_effect=RuntimeError("boom"),
            ),
            patch.dict(os.environ, {"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT": "0"}),
        ):
            ok = _check_connector_version_supported_for_setup(
                "codex",
                mode="action",
                emit=False,
            )

        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
