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
        self.assertEqual(HOOK_CONTRACT_MANIFEST["schema_version"], 1)
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

    def test_codex_version_range_matches_contract(self) -> None:
        known = resolve_connector_contract("codex", "codex 0.124.0")
        self.assertEqual(known.status, STATUS_KNOWN)
        self.assertEqual(known.normalized_version, "0.124.0")
        self.assertEqual(known.contract.contract_id, "codex-hooks-v1")
        self.assertEqual(known.contract.hook_script_version, "v6")
        self.assertIn("~/.codex/config.toml", known.contract.hook_config_path_templates)
        self.assertIn("tool_call", known.contract.aid_surfaces)

        older = resolve_connector_contract("codex", "codex 0.123.0")
        self.assertEqual(older.status, STATUS_UNKNOWN)
        self.assertFalse(older.supported)

    def test_claude_aliases_resolve_to_claudecode(self) -> None:
        compat = resolve_connector_contract("claude-code", "Claude Code 2.1.144")
        self.assertEqual(compat.status, STATUS_KNOWN)
        self.assertEqual(compat.connector, "claudecode")
        self.assertEqual(compat.contract.contract_id, "claudecode-hooks-v1")
        self.assertIn("event_content", compat.contract.aid_surfaces)

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

        self.assertIn(
            "$OMNIGENT_CONFIG_HOME/config.yaml",
            compat.contract.hook_config_path_templates,
        )
        self.assertIn("~/.omnigent/config.yaml", compat.contract.hook_config_path_templates)

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
        ):
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
            return_value=_discovery("claudecode", installed=True, version="2.1.144"),
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
        with patch(
            "defenseclaw.commands.cmd_setup.agent_discovery.discover_agents",
            return_value=_discovery("claudecode", installed=True, version="2.1.144"),
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
