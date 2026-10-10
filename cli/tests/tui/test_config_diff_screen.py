# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Config diff modal screen tests."""

from __future__ import annotations

from defenseclaw.tui.screens.config_diff import ConfigDiffModalModel
from defenseclaw.tui.services.setup_state import ConfigDiffEntry


def _diff_entries() -> tuple[ConfigDiffEntry, ...]:
    return (
        ConfigDiffEntry("gateway.port", "8080", "9090"),
        ConfigDiffEntry("llm.api_key", "****wxyz", "****1234", True),
    )


def test_config_diff_model_renders_mask_marker_and_no_pending_state() -> None:
    model = ConfigDiffModalModel(_diff_entries())
    preview = model.preview_text()

    assert "Review Config Changes" not in preview
    assert "gateway.port" in preview
    assert "before: 8080" in preview
    assert "llm.api_key (masked)" in preview
    assert "****1234" in preview
    assert ConfigDiffModalModel(()).preview_text() == "No pending changes."


def test_config_diff_model_truncates_and_reports_extra_rows() -> None:
    entries = tuple(ConfigDiffEntry(f"field.{index}", "before-value", "after-value") for index in range(3))
    preview = ConfigDiffModalModel(entries).preview_text(max_entries=2, value_width=8)

    assert "before: before-" in preview
    assert "... 1 more changes" in preview


def test_config_diff_offers_a_restart_only_for_keys_read_at_start() -> None:
    hot = ConfigDiffModalModel((ConfigDiffEntry("ai_discovery.scan_interval_min", "5", "6"),))
    assert hot.save_label == "Save"
    assert ConfigDiffModalModel(_diff_entries()).save_label == "Save and queue restart"


def test_secure_client_hot_key_offers_queued_restart() -> None:
    hot = ConfigDiffModalModel(
        (ConfigDiffEntry("asset_policy.mode", "observe", "action"),),
        secure_client=True,
    )
    assert hot.save_label == "Save and queue restart"
