# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Final-cert TUI UX batch 18 (GAP-2275, GAP-2296)."""

from __future__ import annotations

import json
from pathlib import Path

from defenseclaw.db import Store
from defenseclaw.models import Event
from defenseclaw.tui.panels.audit import _row_details_label, _row_target_label, _search_haystack
from defenseclaw.tui.panels.logs import FILTER_NO_NOISE, LogsPanelModel


def test_audit_summary_rows_carry_the_operator_target_and_diff(tmp_path: Path) -> None:
    # GAP-2275: the table and search read list_event_summaries, which dropped
    # the admin target and diff, so TARGET was blank and "llm" found nothing.
    store = Store(str(tmp_path / "audit.db"))
    store.init()
    store.log_event(
        Event(
            action="config-update",
            actor="cli:operator",
            details="config.change.applied",
            structured={
                "defenseclaw.admin.target_ref": "config:llm:guardrail.judge",
                "defenseclaw.admin.diff": json.dumps(
                    [{"path": "model", "op": "replace", "before": "haiku", "after": "sonnet"}]
                ),
                "defenseclaw.admin.after_state": "x" * 4000,
            },
        )
    )
    row = store.list_event_summaries(5)[0]
    assert "defenseclaw.admin.after_state" not in row.structured
    assert _row_target_label(row) == "config:llm:guardrail.judge"
    assert _row_details_label(row).startswith("model: haiku")
    assert "guardrail.judge" in _search_haystack(row)


def test_logs_digits_are_left_to_the_panel_keys() -> None:
    # GAP-2296: 1-8 changed the Logs filter instead of opening the panel.
    panel = LogsPanelModel()
    for key in "12345678":
        assert panel.handle_key(key).handled is False
    assert panel.filter_mode == FILTER_NO_NOISE
    assert all(chip.shortcut == "" for chip in panel.filter_chip_group().chips)
    assert "1-8" not in panel.summary_text()
    assert panel.handle_key("f").handled is True
