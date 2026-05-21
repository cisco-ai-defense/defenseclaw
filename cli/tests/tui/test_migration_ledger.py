# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Coverage guard for the Go-to-Textual migration ledger."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
LEDGER = ROOT / "docs/design/textual-tui-migration-ledger.json"
REQUIRED_FEATURE_TEST_GATES = {
    "go_oracle_reference",
    "unit_or_model_test",
    "textual_app_integration_test",
    "mouse_or_click_test_when_clickable",
    "snapshot_test_when_visible",
    "agent_tty_test_when_pty_or_child_process",
    "negative_or_empty_state_test",
    "test_command",
}


def test_migration_ledger_tracks_every_go_tui_file() -> None:
    payload = json.loads(LEDGER.read_text(encoding="utf-8"))
    entries = {entry["go_path"] for entry in payload["entries"]}

    prod = {
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "internal/tui").glob("*.go")
        if not path.name.endswith("_test.go")
    }
    tests = {path.relative_to(ROOT).as_posix() for path in (ROOT / "internal/tui").glob("*_test.go")}

    assert payload["schema_version"] == 1
    assert payload["design_spec"] == "docs/design/python-textual-tui-parity-spec.md"
    assert payload["go_oracle"]["production_file_count"] == len(prod) == 49
    assert payload["go_oracle"]["test_file_count"] == len(tests) == 62
    assert payload["go_oracle"]["test_function_count"] == 478
    assert payload["go_oracle"]["command_registry_count"] == 224
    assert entries == prod | tests


def test_migration_ledger_tracks_every_go_tui_test_function() -> None:
    payload = json.loads(LEDGER.read_text(encoding="utf-8"))
    inventory = {(item["go_path"], item["function"]) for item in payload["go_test_inventory"]}

    discovered: set[tuple[str, str]] = set()
    pattern = re.compile(r"^func\s+(Test\w+)\s*\(", re.MULTILINE)
    for path in (ROOT / "internal/tui").glob("*_test.go"):
        rel = path.relative_to(ROOT).as_posix()
        discovered.update((rel, match.group(1)) for match in pattern.finditer(path.read_text(encoding="utf-8")))

    assert inventory == discovered


def test_migration_ledger_requires_feature_level_test_gates() -> None:
    payload = json.loads(LEDGER.read_text(encoding="utf-8"))
    policy = payload["feature_test_gate_policy"]
    gate_names = set(policy["required_for_every_feature"])

    assert REQUIRED_FEATURE_TEST_GATES <= gate_names
    assert "cannot be marked parity-complete" in policy["completion_rule"]
    assert "same implementation step" in policy["test_first_rule"]

    gates = payload["feature_test_gates"]
    expected_features = {
        "shared_shell_and_navigation",
        "overview_dashboard",
        "alerts_panel",
        "skills_mcps_plugins_tools_catalogs",
        "inventory_panel",
        "policy_panel",
        "logs_panel",
        "audit_panel",
        "activity_panel_and_command_output",
        "ai_discovery_panel",
        "registries_panel",
        "setup_panel_and_first_run",
        "command_palette_preview_and_action_menus",
        "mode_picker_and_connector_setup",
        "hint_engine_and_status_feedback",
    }

    assert expected_features <= {gate["feature"] for gate in gates}

    for gate in gates:
        required_tests = gate["required_tests"]
        assert set(required_tests) == REQUIRED_FEATURE_TEST_GATES
        assert gate["go_oracle"], gate["feature"]
        assert gate["python_targets"], gate["feature"]
        assert gate["test_command"].startswith("uv run pytest -q ")
        assert gate["test_command"].endswith(" -rxX")
        assert gate["status"] == "active-gate"
        assert all(
            value == "required" or value.startswith("not_applicable:")
            for value in required_tests.values()
        )
