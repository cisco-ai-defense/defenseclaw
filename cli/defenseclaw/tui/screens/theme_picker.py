# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Theme picker modal.

Lets the operator switch the Textual app theme at runtime. Each theme
swaps the default color palette used by Textual's built-in widgets
(buttons, inputs, tabs, scrollbars). Our custom panel chrome is
hex-coded via ``theme.py`` tokens, so panels look identical across
themes — what *does* change is the widget chrome the operator
interacts with most often: input field outlines, tab underlines,
button accents, and (when ``App.ansi_color = None``) the rich named
colors like ``red``/``green``/``yellow`` that some panel detail
rendering uses.

The two ``ansi-*`` themes (Textual 8.2.5) are the headline pick: they
defer to the user's terminal palette, so anyone who's customized
their terminal to Solarized / Tokyo Night / Dracula / etc. gets that
look reflected in the TUI without us shipping a separate theme.

Choice is persisted in :class:`TUIState.theme` so the picker is a
one-time operation per workstation.
"""

from __future__ import annotations

from dataclasses import dataclass

from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import Static

from defenseclaw.tui.theme import DEFAULT_TOKENS


@dataclass(frozen=True)
class ThemeChoice:
    """One row in the theme picker."""

    name: str  # Textual theme id (e.g. ``"tokyo-night"``)
    label: str  # Human label (e.g. ``"Tokyo Night"``)
    group: str  # ``"ANSI"`` / ``"Dark"`` / ``"Light"`` for visual grouping.


# Hand-curated subset of the 21 Textual >=8.2.7 built-in themes. We
# expose the two ANSI themes first (they're the most distinctive
# operator-visible change), then dark themes, then light themes. Keeping
# the list literal (vs. importing ``textual.theme.BUILTIN_THEMES``) lets
# us:
#   * Pin the order — alphabetical would scatter dark/light themes.
#   * Provide human-friendly labels independent of upstream ids.
#   * Filter out themes that look identical to our default ``theme.py``
#     palette and would be confusing.
THEME_CHOICES: tuple[ThemeChoice, ...] = (
    # ANSI — defer to the operator's terminal palette.
    ThemeChoice("ansi-dark", "ANSI (Dark terminal)", "ANSI"),
    ThemeChoice("ansi-light", "ANSI (Light terminal)", "ANSI"),
    # Dark themes.
    ThemeChoice("textual-dark", "Textual Dark (default)", "Dark"),
    ThemeChoice("tokyo-night", "Tokyo Night", "Dark"),
    ThemeChoice("nord", "Nord", "Dark"),
    ThemeChoice("gruvbox", "Gruvbox", "Dark"),
    ThemeChoice("dracula", "Dracula", "Dark"),
    ThemeChoice("monokai", "Monokai", "Dark"),
    ThemeChoice("flexoki", "Flexoki", "Dark"),
    ThemeChoice("solarized-dark", "Solarized Dark", "Dark"),
    ThemeChoice("rose-pine", "Rosé Pine", "Dark"),
    ThemeChoice("rose-pine-moon", "Rosé Pine Moon", "Dark"),
    ThemeChoice("atom-one-dark", "Atom One Dark", "Dark"),
    ThemeChoice("catppuccin-mocha", "Catppuccin Mocha", "Dark"),
    ThemeChoice("catppuccin-frappe", "Catppuccin Frappé", "Dark"),
    ThemeChoice("catppuccin-macchiato", "Catppuccin Macchiato", "Dark"),
    # Light themes.
    ThemeChoice("textual-light", "Textual Light", "Light"),
    ThemeChoice("solarized-light", "Solarized Light", "Light"),
    ThemeChoice("catppuccin-latte", "Catppuccin Latte", "Light"),
    ThemeChoice("rose-pine-dawn", "Rosé Pine Dawn", "Light"),
    ThemeChoice("atom-one-light", "Atom One Light", "Light"),
)


class ThemePickerScreen(ModalScreen[str | None]):
    """Modal that lists themes and dismisses with the chosen id.

    Returns ``None`` if the operator cancels (Escape/clicks outside),
    otherwise returns the Textual theme id (e.g. ``"tokyo-night"``)
    that the caller should pass to ``App.theme``.

    Live preview: as the operator scrolls Up/Down the modal calls
    ``self.app.theme = <id>`` so they see the change immediately
    against the rest of the shell. Cancel rolls back to the theme
    that was active when the modal opened.
    """

    CSS = f"""
    ThemePickerScreen {{
        align: center middle;
    }}

    #theme-picker-dialog {{
        width: 60;
        height: auto;
        max-height: 80%;
        padding: 1 2;
        border: round {DEFAULT_TOKENS.border_active};
        background: {DEFAULT_TOKENS.surface_panel};
        color: {DEFAULT_TOKENS.text_primary};
    }}

    #theme-picker-title {{
        height: 1;
        margin-bottom: 1;
        color: {DEFAULT_TOKENS.accent_cyan};
        text-style: bold;
    }}

    #theme-picker-list {{
        height: auto;
        max-height: 22;
    }}

    #theme-picker-hint {{
        margin-top: 1;
        color: {DEFAULT_TOKENS.text_secondary};
    }}
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=False),
        Binding("up", "cursor_up", "Up", show=False),
        Binding("down", "cursor_down", "Down", show=False),
        Binding("enter", "choose", "Choose", show=False),
    ]

    selected_index: reactive[int] = reactive(0)

    def __init__(self, current_theme: str = "textual-dark") -> None:
        super().__init__()
        self._original_theme = current_theme
        # Start the cursor on whatever the app currently uses so the
        # operator sees their existing choice highlighted on open. Fall
        # back to index 0 (first ANSI theme) for unknown themes.
        self.selected_index = next(
            (
                index
                for index, choice in enumerate(THEME_CHOICES)
                if choice.name == current_theme
            ),
            0,
        )

    def compose(self) -> ComposeResult:
        with Vertical(id="theme-picker-dialog"):
            yield Static("Choose theme", id="theme-picker-title")
            yield Static("", id="theme-picker-list", markup=True)
            yield Static(
                "Up/Down preview · Enter apply · Esc cancel",
                id="theme-picker-hint",
            )

    def on_mount(self) -> None:
        self._refresh_list()

    def action_cursor_up(self) -> None:
        self.selected_index = (self.selected_index - 1) % len(THEME_CHOICES)
        self._apply_preview()
        self._refresh_list()

    def action_cursor_down(self) -> None:
        self.selected_index = (self.selected_index + 1) % len(THEME_CHOICES)
        self._apply_preview()
        self._refresh_list()

    def action_choose(self) -> None:
        choice = THEME_CHOICES[self.selected_index]
        self.dismiss(choice.name)

    def action_pick(self, index: int) -> None:
        """Select + live-preview a clicked theme row.

        Bound to the per-row ``[@click=screen.pick(i)]`` markup so mouse
        users can select a theme (Enter still applies, Esc still cancels) —
        previously the list was a single Static and clicking a name did
        nothing.
        """
        if 0 <= index < len(THEME_CHOICES):
            self.selected_index = index
            self._apply_preview()
            self._refresh_list()

    def action_cancel(self) -> None:
        # Roll back to whatever the app had before the modal opened so
        # cancelling visually reverts the preview. Best-effort: a theme
        # that no longer exists in this Textual version is silently
        # swallowed so we don't crash the modal during dismissal.
        try:
            self.app.theme = self._original_theme
        except Exception:  # noqa: BLE001 - preview rollback is cosmetic
            pass
        self.dismiss(None)

    def on_key(self, event: events.Key) -> None:
        # Forward Enter / Escape even when the modal hasn't captured
        # focus to a specific child widget — matches the panel jumper's
        # convention.
        if event.key == "enter":
            event.stop()
            self.action_choose()
        elif event.key == "escape":
            event.stop()
            self.action_cancel()

    def on_click(self, event: events.Click) -> None:
        if event.widget is self:
            event.stop()
            self.action_cancel()

    def _apply_preview(self) -> None:
        """Set ``app.theme`` to the highlighted choice for live preview."""

        choice = THEME_CHOICES[self.selected_index]
        try:
            self.app.theme = choice.name
        except Exception:  # noqa: BLE001 - bad theme id should not crash
            pass

    def _refresh_list(self) -> None:
        target = self.query_one("#theme-picker-list", Static)
        lines: list[str] = []
        last_group: str | None = None
        for index, choice in enumerate(THEME_CHOICES):
            if choice.group != last_group:
                # Visual section break between ANSI / Dark / Light
                # groups so the operator can pattern-match the list
                # at a glance without reading every label.
                lines.append(f"[#475569]── {choice.group} ──[/]")
                last_group = choice.group
            marker = ">" if index == self.selected_index else " "
            if index == self.selected_index:
                inner = f"[#22D3EE bold]{choice.label}[/]  [#475569]({choice.name})[/]"
            else:
                inner = f"{choice.label}  [#475569]({choice.name})[/]"
            # Wrap each row in a click action link so clicking it selects +
            # previews that theme (handled by ``action_pick``).
            lines.append(f"{marker} [@click=screen.pick({index})]{inner}[/]")
        target.update("\n".join(lines))


__all__ = [
    "THEME_CHOICES",
    "ThemeChoice",
    "ThemePickerScreen",
]
