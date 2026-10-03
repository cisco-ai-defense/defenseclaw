# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI UX batch 9 (ux2): config editor values (GAP-2253)."""

from __future__ import annotations

import os

from defenseclaw.tui.app import _config_display_value, _validation_label
from defenseclaw.tui.panels.setup import ConfigField, build_setup_sections


def _section(cfg: dict, name: str):
    return next(section for section in build_setup_sections(cfg) if section.name == name)


def test_claw_paths_are_unused_for_a_non_openclaw_mode() -> None:
    claw = {f.key: f for f in _section({"claw": {"mode": "codex", "home_dir": "~/.openclaw"}}, "Claw").fields}
    for key in ("claw.home_dir", "claw.config_file"):
        assert claw[key].value == "(not used: Mode is codex)"
        assert ".openclaw" not in claw[key].value and _validation_label(claw[key]) == "read-only"
    openclaw = {f.key: f for f in _section({"claw": {"mode": "openclaw", "home_dir": "~/.openclaw"}}, "Claw").fields}
    assert openclaw["claw.home_dir"].kind == "string" and openclaw["claw.home_dir"].value == "~/.openclaw"


def test_legacy_inspect_llm_unset_fields_read_unset() -> None:
    fields = _section({}, "Inspect LLM (legacy - read-only)").fields
    assert fields and all(field.value == "(unset)" for field in fields)


def test_home_paths_show_with_tilde() -> None:
    home = os.path.expanduser("~")
    path = os.path.join(home, ".defenseclaw", "audit.db")
    shown = _config_display_value(ConfigField("Audit DB", "audit_db", "string", path, path))
    assert shown == "~" + path[len(home) :]
    assert _config_display_value(ConfigField("Host", "gateway.host", "string", "127.0.0.1", "")) == "127.0.0.1"
