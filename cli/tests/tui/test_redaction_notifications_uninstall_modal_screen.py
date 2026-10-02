# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Notifications and uninstall modal parity tests."""

from __future__ import annotations

from defenseclaw.tui.screens.notifications import (
    build_notifications_model,
    desired_notifications_action,
    notifications_command,
)
from defenseclaw.tui.screens.uninstall import (
    UninstallOption,
    build_uninstall_model,
    uninstall_command_for_option,
)


def test_notifications_model_matches_go_oracle_copy_and_argv() -> None:
    assert desired_notifications_action(True) == "off"
    assert notifications_command(True).args == ("setup", "notifications", "off", "--yes")
    assert desired_notifications_action(False) == "on"
    assert notifications_command(False).args == ("setup", "notifications", "on", "--yes")

    on_model = build_notifications_model(False, "Linux")
    on_copy = "\n".join((on_model.summary, *on_model.details, on_model.consequence))
    assert "asset-policy blocks" in on_copy
    assert "would-blocks" in on_copy
    assert "HITL approval" in on_copy
    assert "does not approve" in on_copy

    off_model = build_notifications_model(True, "Darwin")
    off_copy = "\n".join((off_model.summary, *off_model.details))
    assert "Event history" in off_copy
    assert "telemetry destinations" in off_copy
    assert "webhooks" in off_copy
    assert "not affected" in off_copy


def test_windows_notifications_model_is_native_and_has_toggle_command() -> None:
    model = build_notifications_model(True, "Windows")
    assert model.title == "Desktop notifications"
    assert "Will become:" in model.summary
    assert model.actions[0].label == "Confirm"
    assert model.actions[0].command == notifications_command(True)


def test_uninstall_model_defaults_to_dry_run_and_maps_all_argv() -> None:
    model = build_uninstall_model()

    assert model.default_action().action_id == UninstallOption.DRY_RUN.value
    assert uninstall_command_for_option(UninstallOption.DRY_RUN).args == ("uninstall", "--dry-run")
    assert uninstall_command_for_option(UninstallOption.KEEP_DATA).args == ("uninstall", "--yes")
    assert uninstall_command_for_option(UninstallOption.WIPE_DATA).args == ("uninstall", "--all", "--yes")
    # The one row that removes everything, binaries included.
    assert uninstall_command_for_option(UninstallOption.WIPE_ALL).args == (
        "uninstall",
        "--all",
        "--binaries",
        "--yes",
    )
    wipe_all = model.action_for_hotkey("e")
    assert wipe_all is not None and wipe_all.danger and wipe_all.action_id == UninstallOption.WIPE_ALL.value
    assert "--yes" in "\n".join((*model.details, model.consequence))
    assert "dry-run" in model.actions[0].description
