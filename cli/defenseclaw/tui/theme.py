# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Theme tokens for the Python Textual TUI migration.

The palette follows ``docs/design/python-textual-tui-parity-spec.md``.
Keep visual changes centralized here so panel code does not hard-code
decorative colors.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class ThemeTokens:
    """Reusable design constants for Textual widgets and CSS."""

    surface_base: str = "#070A12"
    surface_panel: str = "#0D1220"
    surface_raised: str = "#121A2B"
    surface_hover: str = "#18233A"
    surface_selected: str = "#203251"
    border_muted: str = "#27324A"
    border_active: str = "#38BDF8"
    text_primary: str = "#E6F1FF"
    text_secondary: str = "#9FB2CC"
    text_muted: str = "#64748B"
    accent_cyan: str = "#22D3EE"
    accent_blue: str = "#60A5FA"
    accent_violet: str = "#A78BFA"
    accent_green: str = "#34D399"
    accent_amber: str = "#FBBF24"
    accent_orange: str = "#FB923C"
    accent_red: str = "#F87171"
    accent_pink: str = "#F472B6"

    border: str = "round"
    modal_padding: tuple[int, int] = (1, 2)
    status_padding: tuple[int, int] = (0, 1)


DEFAULT_TOKENS = ThemeTokens()

SEVERITY_STYLES: Mapping[str, str] = {
    "CRITICAL": DEFAULT_TOKENS.accent_red,
    "HIGH": DEFAULT_TOKENS.accent_orange,
    "MEDIUM": DEFAULT_TOKENS.accent_amber,
    "LOW": DEFAULT_TOKENS.accent_blue,
    "INFO": DEFAULT_TOKENS.text_secondary,
}

STATE_STYLES: Mapping[str, str] = {
    "active": DEFAULT_TOKENS.accent_green,
    "allowed": DEFAULT_TOKENS.accent_green,
    "clean": DEFAULT_TOKENS.accent_green,
    "enabled": DEFAULT_TOKENS.accent_green,
    "running": DEFAULT_TOKENS.accent_green,
    "blocked": DEFAULT_TOKENS.accent_red,
    "rejected": DEFAULT_TOKENS.accent_red,
    "error": DEFAULT_TOKENS.accent_red,
    "stopped": DEFAULT_TOKENS.accent_red,
    "warning": DEFAULT_TOKENS.accent_amber,
    "warn": DEFAULT_TOKENS.accent_amber,
    "reconnecting": DEFAULT_TOKENS.accent_amber,
    "starting": DEFAULT_TOKENS.accent_amber,
    "quarantined": DEFAULT_TOKENS.accent_pink,
    "disabled": DEFAULT_TOKENS.text_muted,
    "offline": DEFAULT_TOKENS.text_muted,
    "unknown": DEFAULT_TOKENS.text_muted,
}

STATE_DOTS: Mapping[str, str] = {
    "active": "●",
    "running": "●",
    "enabled": "●",
    "clean": "●",
    "allowed": "●",
    "reconnecting": "●",
    "starting": "●",
    "warning": "●",
    "warn": "●",
    "blocked": "●",
    "error": "●",
    "rejected": "●",
    "stopped": "●",
}


def severity_color(severity: str, tokens: ThemeTokens = DEFAULT_TOKENS) -> str:
    """Return the theme color for a scan severity."""

    styles = {
        "CRITICAL": tokens.accent_red,
        "HIGH": tokens.accent_orange,
        "MEDIUM": tokens.accent_amber,
        "LOW": tokens.accent_blue,
        "INFO": tokens.text_secondary,
    }
    return styles.get(severity.upper(), tokens.text_secondary)


def state_color(state: str, tokens: ThemeTokens = DEFAULT_TOKENS) -> str:
    """Return the theme color for a service or policy state."""

    normalized = state.lower()
    if normalized in {"active", "allowed", "clean", "enabled", "running"}:
        return tokens.accent_green
    if normalized in {"blocked", "error", "rejected", "stopped"}:
        return tokens.accent_red
    if normalized in {"reconnecting", "starting", "warn", "warning"}:
        return tokens.accent_amber
    if normalized == "quarantined":
        return tokens.accent_pink
    return tokens.text_muted


def state_dot(state: str) -> str:
    """Return the parity dot glyph for a service state."""

    return STATE_DOTS.get(state.lower(), "○")


def css_variables(tokens: ThemeTokens = DEFAULT_TOKENS) -> dict[str, str]:
    """Return Textual CSS variable names for the current theme."""

    return {
        "dc-surface-base": tokens.surface_base,
        "dc-surface-panel": tokens.surface_panel,
        "dc-surface-raised": tokens.surface_raised,
        "dc-surface-hover": tokens.surface_hover,
        "dc-surface-selected": tokens.surface_selected,
        "dc-border-muted": tokens.border_muted,
        "dc-border-active": tokens.border_active,
        "dc-text-primary": tokens.text_primary,
        "dc-text-secondary": tokens.text_secondary,
        "dc-text-muted": tokens.text_muted,
        "dc-accent-cyan": tokens.accent_cyan,
        "dc-accent-blue": tokens.accent_blue,
        "dc-accent-violet": tokens.accent_violet,
        "dc-accent-green": tokens.accent_green,
        "dc-accent-amber": tokens.accent_amber,
        "dc-accent-orange": tokens.accent_orange,
        "dc-accent-red": tokens.accent_red,
        "dc-accent-pink": tokens.accent_pink,
    }


def textual_css(tokens: ThemeTokens = DEFAULT_TOKENS) -> str:
    """Return a small Textual CSS block for the initial app shell."""

    return f"""
Screen {{
    color: {tokens.text_primary};
    background: {tokens.surface_base};
}}

.dc-panel {{
    border: {tokens.border} {tokens.border_muted};
    background: {tokens.surface_panel};
}}

.dc-title {{
    color: {tokens.accent_cyan};
    text-style: bold;
}}

.dc-hint-bar {{
    color: {tokens.accent_cyan};
    text-style: italic;
    height: 1;
}}

.dc-status-strip {{
    background: {tokens.surface_raised};
    color: {tokens.text_secondary};
    height: 1;
}}

.dc-status-label {{
    background: {tokens.accent_cyan};
    color: {tokens.surface_base};
    text-style: bold;
}}
""".strip()


TEXTUAL_CSS = textual_css()
