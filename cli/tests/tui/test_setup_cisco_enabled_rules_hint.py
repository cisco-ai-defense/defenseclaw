# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Setup hint for Cisco AI Defense rule selection."""

from pathlib import Path

import pytest
from defenseclaw.tui.panels.setup import _cisco_ai_defense_fields


def test_enabled_rules_hint_names_entry_format_and_api_key_scope() -> None:
    field = next(field for field in _cisco_ai_defense_fields(None) if field.key == "cisco_ai_defense.enabled_rules")
    assert "Comma-separated" in field.hint
    assert "blank uses the connection policy" in field.hint
    assert "API-key" in field.hint
    assert "CSV" not in field.hint


def test_enabled_rules_hint_matches_macos_config_editor() -> None:
    swift = (Path(__file__).resolve().parents[3] /
             "macos/DefenseClawMac/DefenseClawMac/Features/ConfigEditorDefinitions.swift")
    if not swift.is_file():
        pytest.skip("macOS Config Editor source is absent from this layout")
    field = next(field for field in _cisco_ai_defense_fields(None) if field.key == "cisco_ai_defense.enabled_rules")
    assert f'hint: "{field.hint}"' in swift.read_text()
