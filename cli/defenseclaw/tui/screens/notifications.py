# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Desktop notifications toggle consequence modal."""

from __future__ import annotations

from defenseclaw.notification_capabilities import desktop_notification_capability
from defenseclaw.tui.screens.consequence import (
    CommandSpec,
    ConsequenceAction,
    ConsequenceModalModel,
    ConsequenceModalScreen,
)
from defenseclaw.tui.theme import DEFAULT_TOKENS


def desired_notifications_action(currently_enabled: bool) -> str:
    """Return the `setup notifications` subcommand for the next state."""

    return "off" if currently_enabled else "on"


def notifications_command(currently_enabled: bool) -> CommandSpec:
    """Build the CLI command for the confirmed notifications flip."""

    action = desired_notifications_action(currently_enabled)
    return CommandSpec(
        binary="defenseclaw",
        args=("setup", "notifications", action, "--yes"),
        display_name=f"setup notifications {action}",
    )


def build_notifications_model(currently_enabled: bool, system: str | None = None) -> ConsequenceModalModel:
    """Build the notifications modal model from the cached current state."""

    capability = desktop_notification_capability(system)
    if not capability.supported:
        configured = "ON (legacy setting retained)" if currently_enabled else "OFF"
        return ConsequenceModalModel(
            title="Desktop notifications — unsupported",
            summary=f"Configured state: {configured}\nNative desktop delivery: INACTIVE",
            details=(
                capability.unsupported_reason,
                "Windows toast delivery cannot be enabled in this release.",
                "Audit DB, Splunk, OTel, webhooks, files, and terminal output are unchanged.",
                "Any delivery fallback is labelled as terminal fallback, never desktop success.",
            ),
            consequence="Use `defenseclaw setup notifications off` to clear a legacy enabled setting.",
            actions=(
                ConsequenceAction(
                    action_id="close",
                    label="Close",
                    description="No configuration will be changed.",
                    command=None,
                ),
            ),
            default_action_id="close",
            border_color=DEFAULT_TOKENS.accent_amber,
        )

    desired = desired_notifications_action(currently_enabled)
    current_label = "ON (toasts on every block / approval)" if currently_enabled else "OFF (audit unchanged)"
    desired_label = "OFF (no toasts; audit unchanged)" if currently_enabled else "ON (block / approval toasts)"
    if desired == "on":
        details = (
            "Turning notifications ON surfaces:",
            "Hook / guardrail / asset-policy blocks",
            "Observe-mode would-blocks",
            "Pending HITL approval prompts",
            "Clicking a notification does not approve anything.",
        )
        consequence = "Reply in chat or the TUI for approval decisions."
        border = DEFAULT_TOKENS.accent_green
        variant = "success"
    else:
        details = (
            "Turning notifications OFF stops the toaster only.",
            "Event history, telemetry destinations, and webhooks are not affected.",
            "They continue to record blocks and approvals.",
        )
        consequence = "Per-category and per-source filters can silence only some toasts."
        border = DEFAULT_TOKENS.accent_amber
        variant = "warning"

    return ConsequenceModalModel(
        title="Desktop notifications",
        summary=f"Current state: {current_label}\nWill become:   {desired_label}",
        details=details,
        consequence=consequence,
        actions=(
            ConsequenceAction(
                action_id="confirm",
                label="Confirm",
                description=f"Runs defenseclaw setup notifications {desired} --yes.",
                command=notifications_command(currently_enabled),
                variant=variant,
            ),
        ),
        default_action_id="confirm",
        border_color=border,
    )


class NotificationsToggleScreen(ConsequenceModalScreen):
    """Textual modal for the Logs/Overview notifications toggle."""

    def __init__(self, currently_enabled: bool, system: str | None = None) -> None:
        super().__init__(build_notifications_model(currently_enabled, system))
