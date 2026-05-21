# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Redaction toggle consequence modal."""

from __future__ import annotations

from defenseclaw.tui.screens.consequence import (
    CommandSpec,
    ConsequenceAction,
    ConsequenceModalModel,
    ConsequenceModalScreen,
)
from defenseclaw.tui.theme import DEFAULT_TOKENS


def desired_redaction_action(currently_disabled: bool) -> str:
    """Return the `setup redaction` subcommand for the next state."""

    return "on" if currently_disabled else "off"


def redaction_command(currently_disabled: bool) -> CommandSpec:
    """Build the CLI command for the confirmed redaction flip."""

    action = desired_redaction_action(currently_disabled)
    return CommandSpec(
        binary="defenseclaw",
        args=("setup", "redaction", action, "--yes"),
        display_name=f"setup redaction {action}",
    )


def build_redaction_model(currently_disabled: bool) -> ConsequenceModalModel:
    """Build the redaction modal model from the cached current state."""

    desired = desired_redaction_action(currently_disabled)
    current_label = "RAW (full prompts to all sinks)" if currently_disabled else "REDACTED (placeholders only)"
    desired_label = "REDACTED (placeholders only)" if currently_disabled else "RAW (full prompts to all sinks)"
    if desired == "off":
        details = (
            "Disabling redaction writes RAW content to:",
            "SQLite audit DB",
            "Splunk HEC, OTel log exporters, webhooks",
            "gateway.log and the Logs panel",
        )
        consequence = "Only proceed if every downstream sink lives in the same trust boundary as this install."
        border = DEFAULT_TOKENS.accent_red
    else:
        details = (
            "Re-enables redaction; placeholders return on the next sidecar boot.",
            "Existing already-emitted audit rows/events remain as written.",
        )
        consequence = ""
        border = DEFAULT_TOKENS.accent_green

    return ConsequenceModalModel(
        title="Redaction kill-switch",
        summary=f"Current state: {current_label}\nWill become:   {desired_label}",
        details=details,
        consequence=consequence,
        actions=(
            ConsequenceAction(
                action_id="confirm",
                label="Confirm",
                description=f"Runs defenseclaw setup redaction {desired} --yes.",
                command=redaction_command(currently_disabled),
                variant="error" if desired == "off" else "success",
                danger=desired == "off",
            ),
        ),
        default_action_id="confirm",
        border_color=border,
    )


class RedactionToggleScreen(ConsequenceModalScreen):
    """Textual modal for the Logs/Overview redaction toggle."""

    def __init__(self, currently_disabled: bool) -> None:
        super().__init__(build_redaction_model(currently_disabled))
