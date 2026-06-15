# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Uninstall confirmation modal."""

from __future__ import annotations

from enum import Enum

from defenseclaw.tui.screens.consequence import (
    CommandSpec,
    ConsequenceAction,
    ConsequenceModalModel,
    ConsequenceModalScreen,
)
from defenseclaw.tui.theme import DEFAULT_TOKENS


class UninstallOption(str, Enum):
    """Go parity uninstall choices."""

    DRY_RUN = "dry-run"
    KEEP_DATA = "keep-data"
    WIPE_DATA = "wipe-data"


def uninstall_command_for_option(option: UninstallOption) -> CommandSpec:
    """Return the CLI argv for an uninstall choice."""

    if option is UninstallOption.DRY_RUN:
        args = ("uninstall", "--dry-run")
        display = "uninstall dry-run"
    elif option is UninstallOption.KEEP_DATA:
        args = ("uninstall", "--yes")
        display = "uninstall --yes"
    else:
        args = ("uninstall", "--all", "--yes")
        display = "uninstall --all --yes"
    return CommandSpec(binary="defenseclaw", args=args, display_name=display)


def build_uninstall_model() -> ConsequenceModalModel:
    """Build the guarded uninstall modal model."""

    return ConsequenceModalModel(
        title="Uninstall DefenseClaw",
        summary="Choose what the TUI should run. The default is preview-only.",
        details=(
            "Destructive rows pass --yes because this modal is the confirmation step.",
            "Use the dry-run row first if you want to inspect the plan.",
        ),
        consequence="Uninstall can remove hooks, plugin integration, config, audit DB, and secrets.",
        actions=(
            ConsequenceAction(
                action_id=UninstallOption.DRY_RUN.value,
                hotkey="p",
                label="Preview plan",
                description="Runs uninstall --dry-run and changes nothing.",
                command=uninstall_command_for_option(UninstallOption.DRY_RUN),
            ),
            ConsequenceAction(
                action_id=UninstallOption.KEEP_DATA.value,
                hotkey="u",
                label="Uninstall, keep data",
                description="Reverts hooks/plugin integration and keeps ~/.defenseclaw.",
                command=uninstall_command_for_option(UninstallOption.KEEP_DATA),
                variant="error",
                danger=True,
            ),
            ConsequenceAction(
                action_id=UninstallOption.WIPE_DATA.value,
                hotkey="a",
                label="Uninstall and wipe data",
                description="Also deletes ~/.defenseclaw audit DB, config, and secrets.",
                command=uninstall_command_for_option(UninstallOption.WIPE_DATA),
                variant="error",
                danger=True,
            ),
        ),
        default_action_id=UninstallOption.DRY_RUN.value,
        border_color=DEFAULT_TOKENS.accent_red,
    )


class UninstallScreen(ConsequenceModalScreen):
    """Textual modal for the Overview uninstall flow."""

    def __init__(self) -> None:
        super().__init__(build_uninstall_model())
