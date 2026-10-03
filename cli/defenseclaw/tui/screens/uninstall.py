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
    WIPE_ALL = "wipe-all"


def uninstall_command_for_option(option: UninstallOption) -> CommandSpec:
    """Return the CLI argv for an uninstall choice."""

    if option is UninstallOption.DRY_RUN:
        args = ("uninstall", "--dry-run")
        display = "uninstall dry-run"
    elif option is UninstallOption.KEEP_DATA:
        args = ("uninstall", "--yes")
        display = "uninstall --yes"
    elif option is UninstallOption.WIPE_DATA:
        args = ("uninstall", "--all", "--yes")
        display = "uninstall --all --yes"
    else:
        args = ("uninstall", "--all", "--binaries", "--yes")
        display = "uninstall --all --binaries --yes"
    return CommandSpec(binary="defenseclaw", args=args, display_name=display)


# Rows that remove ~/.defenseclaw. Uninstall refuses that while a TUI is open
# (the TUI keeps writing there, GAP-2576), so the TUI cannot run them: it names
# the terminal command to run after quitting instead (GAP-2585).
TERMINAL_ONLY_OPTIONS = frozenset({UninstallOption.WIPE_DATA.value, UninstallOption.WIPE_ALL.value})


def terminal_command_for_option(option_id: str) -> str:
    """The command to type in a terminal for a terminal-only row ('' otherwise)."""

    if option_id not in TERMINAL_ONLY_OPTIONS:
        return ""
    args = uninstall_command_for_option(UninstallOption(option_id)).args
    return " ".join(("defenseclaw", *(arg for arg in args if arg != "--yes")))


def build_uninstall_model() -> ConsequenceModalModel:
    """Build the guarded uninstall modal model."""

    return ConsequenceModalModel(
        title="Uninstall DefenseClaw",
        # The header said "Choose what the TUI should run" and explained
        # "--yes", though rows a and e only show a command (GAP-2608).
        summary="Preview the plan, or uninstall and keep your data. The default is preview-only.",
        details=("Deleting data or binaries is done from a terminal after you quit (rows a and e show the command).",),
        consequence="Uninstall here removes the DefenseClaw hooks and plugin integration and keeps ~/.defenseclaw.",
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
                # The TUI cannot remove the data it keeps open, so this row
                # only shows a command and needs no danger confirm (GAP-2595).
                description=(
                    "The TUI cannot do this. Quit, then "
                    f"`{terminal_command_for_option(UninstallOption.WIPE_DATA.value)}` deletes ~/.defenseclaw."
                ),
                command=uninstall_command_for_option(UninstallOption.WIPE_DATA),
                variant="error",
            ),
            ConsequenceAction(
                action_id=UninstallOption.WIPE_ALL.value,
                hotkey="e",
                label="Uninstall everything",
                description=(
                    "The TUI cannot do this. Quit, then "
                    f"`{terminal_command_for_option(UninstallOption.WIPE_ALL.value)}` "
                    "deletes ~/.defenseclaw and the binaries."
                ),
                command=uninstall_command_for_option(UninstallOption.WIPE_ALL),
                variant="error",
            ),
        ),
        default_action_id=UninstallOption.DRY_RUN.value,
        border_color=DEFAULT_TOKENS.accent_red,
        hint="p previews  ·  a/e show the command to run after quitting  ·  u, then enter twice, uninstalls  ·  esc cancel",
    )


class UninstallScreen(ConsequenceModalScreen):
    """Textual modal for the Overview uninstall flow."""

    def __init__(self) -> None:
        super().__init__(build_uninstall_model())
