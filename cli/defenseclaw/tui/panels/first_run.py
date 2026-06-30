# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Pure first-run Setup fallback model for the Textual TUI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from defenseclaw.platform_support import connector_preview_on_os, supported_connectors
from defenseclaw.tui.services.setup_state import SetupCommandIntent

FirstRunKind = Literal["choice", "bool"]
FirstRunOutcome = Literal["unavailable", "handed", "declined"]

CONNECTOR_CHOICES: tuple[str, ...] = (
    "codex",
    "claudecode",
    "zeptoclaw",
    "openclaw",
    "hermes",
    "cursor",
    "windsurf",
    "geminicli",
    "copilot",
    "openhands",
    "antigravity",
    "opencode",
    "omnigent",
)


def visible_connector_choices(os_name: str | None = None) -> tuple[str, ...]:
    """``CONNECTOR_CHOICES`` supported on *os_name*.

    Drops unsupported connectors on Windows; a no-op on macOS/Linux.
    """
    return tuple(supported_connectors(CONNECTOR_CHOICES, os_name))


PROFILE_CHOICES: tuple[str, ...] = ("observe", "action")
SCANNER_MODE_CHOICES: tuple[str, ...] = ("local", "remote", "both")
FAIL_MODE_CHOICES: tuple[str, ...] = ("open", "closed")
HILT_SEVERITY_CHOICES: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


@dataclass(frozen=True)
class FirstRunField:
    label: str
    kind: FirstRunKind
    value: str
    options: tuple[str, ...] = ()
    hint: str = ""

    @property
    def display_value(self) -> str:
        if self.kind != "bool":
            if self.label == "Connector" and connector_preview_on_os(self.value):
                return f"{self.value} (preview)"
            return self.value
        return "on" if self.value == "true" else "off"


@dataclass(frozen=True)
class FirstRunAction:
    handled: bool
    intent: SetupCommandIntent | None = None


@dataclass(frozen=True)
class FirstRunPromptDecision:
    outcome: FirstRunOutcome
    should_spawn_init: bool = False
    prompt: str = ""
    message: str = ""


class FirstRunPanelModel:
    """Missing-config bootstrap form matching Go's embedded FirstRunPanel."""

    def __init__(self, *, active: bool = True) -> None:
        self.active = active
        self.fields: list[FirstRunField] = list(default_first_run_fields())
        self.cursor = 0
        self.width = 0
        self.height = 0

    def set_size(self, width: int, height: int) -> None:
        self.width = width
        self.height = height

    def value(self, label: str) -> str:
        for field in self.fields:
            if field.label == label:
                return field.value
        return ""

    def args(self) -> tuple[str, ...]:
        args: list[str] = ["init", "--non-interactive", "--yes", "--json-summary"]
        args.extend(
            (
                "--connector",
                self.value("Connector"),
                "--profile",
                self.value("Profile"),
                "--scanner-mode",
                self.value("Scanner Mode"),
            ),
        )
        args.append("--with-judge" if self.value("LLM Judge") == "true" else "--no-judge")
        # Hook fail mode is always passed; CLI default mirrors ours.
        if fail_mode := self.value("Hook Fail Mode"):
            args.extend(("--fail-mode", fail_mode))
        # HITL only makes sense in action profile; skip the flags
        # entirely in observe so CLI preserves any existing setting.
        if self.value("Profile") == "action":
            hitl_on = self.value("HITL") == "true"
            args.append("--human-approval" if hitl_on else "--no-human-approval")
            if hitl_on and (severity := self.value("HITL Min Severity")):
                args.extend(("--hilt-min-severity", severity))
        args.append("--start-gateway" if self.value("Start Gateway") == "true" else "--no-start-gateway")
        args.append("--verify" if self.value("Verify") == "true" else "--no-verify")
        return tuple(args)

    def intent(self) -> SetupCommandIntent:
        return SetupCommandIntent(
            label="init first-run",
            args=self.args(),
            binary="defenseclaw",
            category="setup",
            origin="first-run",
        )

    def handle_key(self, key: str) -> FirstRunAction:
        if key in {"up", "k"}:
            self.cursor = max(0, self.cursor - 1)
            return FirstRunAction(True)
        if key in {"down", "j"}:
            self.cursor = min(len(self.fields) - 1, self.cursor + 1)
            return FirstRunAction(True)
        if key in {"left", "h"}:
            self.cycle(-1)
            return FirstRunAction(True)
        if key in {"right", "l", "enter", " "}:
            self.cycle(1)
            return FirstRunAction(True)
        if key == "ctrl+r":
            return FirstRunAction(True, self.intent())
        return FirstRunAction(False)

    def cycle(self, delta: int = 1) -> None:
        if self.cursor < 0 or self.cursor >= len(self.fields):
            return
        field = self.fields[self.cursor]
        if field.kind == "bool":
            self.fields[self.cursor] = _replace_field(field, value="false" if field.value == "true" else "true")
            return
        if field.kind == "choice" and field.options:
            try:
                current = field.options.index(field.value)
            except ValueError:
                current = 0
            next_value = field.options[(current + delta) % len(field.options)]
            self.fields[self.cursor] = _replace_field(field, value=next_value)

    def empty_state(self) -> str:
        return "No config.yaml was found. Pick the basics, then press Ctrl+R to apply."


def default_first_run_fields() -> tuple[FirstRunField, ...]:
    return (
        FirstRunField(
            "Connector",
            "choice",
            "codex",
            visible_connector_choices(),
            "Agent framework to protect. OpenClaw is optional, not assumed.",
        ),
        FirstRunField("Profile", "choice", "observe", PROFILE_CHOICES, "observe=detect/log; action=block."),
        FirstRunField(
            "Scanner Mode",
            "choice",
            "local",
            SCANNER_MODE_CHOICES,
            "local needs no Cisco key; remote/both probe Cisco AI Defense.",
        ),
        FirstRunField(
            "LLM Judge",
            "bool",
            "false",
            hint="Enable LLM adjudication now. Requires a configured LLM key/model.",
        ),
        FirstRunField(
            "Hook Fail Mode",
            "choice",
            "open",
            FAIL_MODE_CHOICES,
            "On response-layer failure: open=allow+log (recommended), closed=block.",
        ),
        FirstRunField(
            "HITL",
            "bool",
            "false",
            hint="Action mode only: require operator approval before risky tool calls.",
        ),
        FirstRunField(
            "HITL Min Severity",
            "choice",
            "HIGH",
            HILT_SEVERITY_CHOICES,
            "Lowest finding severity that triggers a HITL approval prompt.",
        ),
        FirstRunField("Start Gateway", "bool", "false", hint="Start the sidecar after writing config."),
        FirstRunField("Verify", "bool", "true", hint="Run targeted readiness checks before landing on Overview."),
    )


def decide_first_run_prompt(
    answer: str | None,
    *,
    skip: bool = False,
    tty_ok: bool = True,
    spawn_error: Exception | None = None,
) -> FirstRunPromptDecision:
    """Pure decision helper for the pre-TUI first-run prompt.

    The caller owns actual stdin/stdout and subprocess execution. This
    mirrors Go's three outcomes so app bootstrap can decide whether to
    show the embedded panel.
    """

    if skip or not tty_ok:
        return FirstRunPromptDecision("unavailable")

    prompt = first_run_prompt_text()
    normalized = "" if answer is None else answer.strip().lower()
    if normalized in {"n", "no"}:
        return FirstRunPromptDecision(
            "declined",
            prompt=prompt,
            message="OK - opening the TUI without running the wizard. Run it later anytime with: defenseclaw init",
        )
    if normalized not in {"", "y", "yes"}:
        return FirstRunPromptDecision(
            "unavailable",
            prompt=prompt,
            message=f'Could not parse "{normalized}" - opening the TUI without running the wizard.',
        )
    if spawn_error is not None:
        return FirstRunPromptDecision(
            "unavailable",
            should_spawn_init=True,
            prompt=prompt,
            message=f"defenseclaw init: {spawn_error}",
        )
    return FirstRunPromptDecision("handed", should_spawn_init=True, prompt=prompt, message="Launching defenseclaw init")


def first_run_prompt_text(config_path: str = "~/.defenseclaw/config.yaml") -> str:
    return (
        "DefenseClaw isn't configured yet - no config.yaml was found at\n"
        f"{config_path}\n\n"
        "The setup wizard collects your connector, profile, fail-mode, and\n"
        "optional Human-In-the-Loop policy in a few short prompts. The TUI\n"
        "embeds a shorter version of the same flow, but the wizard surfaces\n"
        "every option (recommended for first-time installs).\n\n"
        "Run the setup wizard now? [Y/n]"
    )


def _replace_field(field: FirstRunField, *, value: str) -> FirstRunField:
    return FirstRunField(field.label, field.kind, value, field.options, field.hint)
