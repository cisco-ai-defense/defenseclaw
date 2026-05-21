# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Phase 10: Quick Start ModalScreen.

Thin Textual shell around ``QuickStartWizardModel``. The model is
where every cursor-movement / toggle / validation rule lives so this
screen can stay focused on layout and Rich rendering. The screen
returns a fully-realized ``Policy`` via ``ModalScreen.dismiss`` when
the operator hits Save, or ``None`` on Cancel - the calling Policy
panel can then write the policy via ``PolicyDraftModel``.
"""

from __future__ import annotations

from rich.markup import escape as rich_escape
from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from defenseclaw.tui.creator.answers import (
    ALLOW_CARDS,
    BLOCK_CARDS,
    BLOCK_CATEGORIES,
    BLOCK_DISPLAY_ORDER,
    POSTURES,
    RESPONSES,
    SINK_CARDS,
    Answers,
)
from defenseclaw.tui.creator.types import Policy
from defenseclaw.tui.creator.validators import summarize
from defenseclaw.tui.creator.wizard import (
    WIZARD_STEPS,
    QuickStartWizardModel,
)
from defenseclaw.tui.theme import DEFAULT_TOKENS


class QuickStartScreen(ModalScreen[Policy | None]):
    """Six-step Quick Start interview.

    Returns the derived ``Policy`` on save, ``None`` on cancel.
    """

    CSS = f"""
    QuickStartScreen {{
        align: center middle;
    }}

    #quickstart-dialog {{
        width: 110;
        height: 38;
        padding: 1 2;
        border: round {DEFAULT_TOKENS.border_active};
        background: {DEFAULT_TOKENS.surface_panel};
        color: {DEFAULT_TOKENS.text_primary};
    }}

    #quickstart-title {{
        height: 1;
        margin-bottom: 1;
        color: {DEFAULT_TOKENS.accent_cyan};
        text-style: bold;
    }}

    #quickstart-stepper {{
        height: auto;
        margin-bottom: 1;
        color: {DEFAULT_TOKENS.text_secondary};
    }}

    #quickstart-body {{
        height: 1fr;
        color: {DEFAULT_TOKENS.text_primary};
        scrollbar-color: {DEFAULT_TOKENS.border_muted};
        scrollbar-color-active: {DEFAULT_TOKENS.accent_cyan};
        scrollbar-color-hover: {DEFAULT_TOKENS.accent_cyan};
        scrollbar-size-vertical: 1;
    }}

    #quickstart-body-static {{
        height: auto;
        color: {DEFAULT_TOKENS.text_primary};
    }}

    #quickstart-status {{
        height: 2;
        margin-top: 1;
        color: {DEFAULT_TOKENS.text_secondary};
    }}

    #quickstart-buttons {{
        height: 3;
        align: right middle;
    }}

    #quickstart-buttons Button {{
        margin: 0 1;
        min-width: 10;
        background: {DEFAULT_TOKENS.surface_raised};
        color: {DEFAULT_TOKENS.text_primary};
        border: tall {DEFAULT_TOKENS.border_muted};
    }}

    #quickstart-buttons Button:hover {{
        background: {DEFAULT_TOKENS.surface_hover};
        border: tall {DEFAULT_TOKENS.accent_cyan};
    }}

    #quickstart-buttons Button:focus {{
        border: tall {DEFAULT_TOKENS.accent_cyan};
        text-style: bold;
    }}

    #quickstart-buttons Button.qs-btn-primary {{
        background: {DEFAULT_TOKENS.surface_selected};
        color: {DEFAULT_TOKENS.accent_cyan};
        text-style: bold;
    }}

    #quickstart-buttons Button.-disabled {{
        color: {DEFAULT_TOKENS.text_muted};
    }}
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel", show=False),
    ]

    def __init__(self, answers: Answers | None = None) -> None:
        super().__init__()
        self._model = QuickStartWizardModel(answers)

    # --- Textual lifecycle -------------------------------------------------

    def on_mount(self) -> None:
        # ``_update_button_state`` reads ``is_savable`` etc., which
        # depend on the live ``answers``. Run once on mount so the
        # button row is correct before the operator presses anything.
        self._update_button_state()

    def compose(self) -> ComposeResult:
        with Vertical(id="quickstart-dialog"):
            yield Static("Quick Start: Build a Policy", id="quickstart-title")
            yield Static(self._render_stepper(), id="quickstart-stepper")
            with VerticalScroll(id="quickstart-body"):
                yield Static(self._render_body(), id="quickstart-body-static")
            yield Static(self._render_status(), id="quickstart-status")
            with Horizontal(id="quickstart-buttons"):
                yield Button("< Back", id="qs-btn-back")
                yield Button("Next >", id="qs-btn-next", classes="qs-btn-primary")
                yield Button("Save", id="qs-btn-save")
                yield Button("Cancel", id="qs-btn-cancel")

    def on_key(self, event: events.Key) -> None:
        # Map Textual key names back to the model's expected vocabulary.
        # Most are 1:1; the printable-character case gets an explicit
        # rebind via ``event.character`` so typing into URL/env-var
        # fields works.
        key = event.key
        if event.character and len(event.character) == 1 and event.character.isprintable() and key not in {"enter", "tab", "escape"}:
            key = event.character
        action = self._model.handle_key(key)
        self._dispatch_action(action, event)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""
        if bid == "qs-btn-back":
            action = self._model.handle_key("ctrl+left")
            self._dispatch_action(action, event)
        elif bid == "qs-btn-next":
            action = self._model.handle_key("ctrl+right")
            self._dispatch_action(action, event)
        elif bid == "qs-btn-save":
            if self._model.is_savable():
                event.stop()
                self.dismiss(self._model.derive_policy())
        elif bid == "qs-btn-cancel":
            event.stop()
            self.dismiss(None)

    def on_click(self, event: events.Click) -> None:
        # Only forward clicks that landed on the body itself; button
        # clicks are routed via ``on_button_pressed`` and we don't
        # want a click on a button to also fire a body-click.
        target = event.widget
        if target is None or getattr(target, "id", "") != "quickstart-body-static":
            return
        action = self._handle_body_click(event.y)
        if action is None:
            return
        self._dispatch_action(action, event)

    def action_cancel(self) -> None:
        self.dismiss(None)

    # --- shared dispatch -------------------------------------------------

    def _dispatch_action(
        self,
        action: object,
        event: events.Event,
    ) -> None:
        """Apply the result of a key/button/click event to the screen.

        ``action`` is duck-typed: anything with ``outcome`` and
        ``policy`` attributes (i.e. the wizard's ``WizardAction``)
        works. Centralizing the cancel/save/refresh branches keeps
        the three input paths from drifting.
        """

        outcome = getattr(action, "outcome", "ignored")
        if outcome == "cancel":
            event.stop()
            self.dismiss(None)
            return
        if outcome == "save" and getattr(action, "policy", None) is not None:
            event.stop()
            self.dismiss(action.policy)  # type: ignore[attr-defined]
            return
        if outcome != "ignored":
            event.stop()
            self._refresh_views()

    def _refresh_views(self) -> None:
        self.query_one("#quickstart-stepper", Static).update(self._render_stepper())
        self.query_one("#quickstart-body-static", Static).update(self._render_body())
        self.query_one("#quickstart-status", Static).update(self._render_status())
        self._update_button_state()
        self._scroll_to_cursor()

    def _update_button_state(self) -> None:
        try:
            back = self.query_one("#qs-btn-back", Button)
            nxt = self.query_one("#qs-btn-next", Button)
            save = self.query_one("#qs-btn-save", Button)
        except Exception:  # pragma: no cover - defensive; happens during teardown
            return
        back.disabled = self._model.is_first
        nxt.disabled = self._model.is_last
        save.disabled = not self._model.is_savable()
        # Highlight whichever forward action is the natural next step
        # so the operator always knows which button takes them deeper.
        if self._model.is_savable() and self._model.is_last:
            save.add_class("qs-btn-primary")
            nxt.remove_class("qs-btn-primary")
        else:
            nxt.add_class("qs-btn-primary")
            save.remove_class("qs-btn-primary")

    # --- body click routing ----------------------------------------------

    def _handle_body_click(self, line: int) -> object | None:
        """Translate a click at ``line`` (0-indexed within the body
        Text) into a model mutation. Returns the resulting
        :class:`WizardAction` so :meth:`_dispatch_action` can
        finish the cancel/save/refresh handling.

        The line→card-index inverse is computed per step using the
        same iteration order as the renderer, so a click always
        targets the row the operator visually pointed at.
        """

        step_id = self._model.step.id
        if step_id == "block":
            mapping = _block_lines_to_card_idx(self._model)
            if line in mapping:
                return self._model.click_block_card(mapping[line])
        elif step_id == "posture":
            mapping = _posture_lines_to_idx(self._model)
            if line in mapping:
                return self._model.click_posture(mapping[line])
        elif step_id == "response":
            mapping = _response_lines_to_idx(self._model)
            if line in mapping:
                return self._model.click_response(mapping[line])
        elif step_id == "allow":
            mapping = _allow_lines_to_idx(self._model)
            if line in mapping:
                return self._model.click_allow_card(mapping[line])
        elif step_id == "sinks":
            mapping = _sinks_lines_to_idx(self._model)
            if line in mapping:
                return self._model.click_sink_card(mapping[line])
        return None

    def _scroll_to_cursor(self) -> None:
        """Scroll the body container so the active card stays visible.

        Each step renderer reports a "cursor line" (0-indexed line
        within the body Text). The Multi-step block category sits
        below the natural fold, so without this hook the operator
        could press ``down`` past the end of what's painted and never
        see those cards. We approximate with the per-step heuristic in
        :func:`_cursor_line_for_step` rather than re-parsing the
        rendered Text - the heuristic matches the renderer 1:1.
        """

        line = self._cursor_line_for_step()
        if line is None:
            return
        try:
            scroller = self.query_one("#quickstart-body", VerticalScroll)
        except Exception:  # pragma: no cover - defensive
            return
        # Add a few-line lead so the highlighted card isn't pinned to
        # the very bottom of the viewport when the user pages down.
        scroller.scroll_to(y=max(0, line - 4), animate=False)

    def _cursor_line_for_step(self) -> int | None:
        step_id = self._model.step.id
        if step_id == "block":
            return _block_cursor_line(self._model)
        if step_id == "allow":
            return _allow_cursor_line(self._model)
        if step_id == "sinks":
            return _sinks_cursor_line(self._model)
        return None

    # --- rendering ---------------------------------------------------------

    def _render_stepper(self) -> Text:
        out = Text()
        for i, step in enumerate(WIZARD_STEPS):
            if i == self._model.step_idx:
                out.append(f"[{i + 1} {step.label}]", style="bold reverse")
            elif i < self._model.step_idx:
                out.append(f" {i + 1} {step.label} ", style="dim")
            else:
                out.append(f" {i + 1} {step.label} ")
            if i < len(WIZARD_STEPS) - 1:
                out.append(" > ", style="dim")
        return out

    def _render_body(self) -> Text:
        step_id = self._model.step.id
        if step_id == "posture":
            return _render_posture(self._model)
        if step_id == "block":
            return _render_block(self._model)
        if step_id == "allow":
            return _render_allow(self._model)
        if step_id == "response":
            return _render_response(self._model)
        if step_id == "sinks":
            return _render_sinks(self._model)
        return _render_review(self._model)

    def _render_status(self) -> Text:
        out = Text()
        out.append(
            f"Step {self._model.step_idx + 1}/{len(WIZARD_STEPS)}",
            style=f"bold {DEFAULT_TOKENS.accent_cyan}",
        )
        # Keyboard shortcuts stay in the status line for power users;
        # the buttons below cover the click path.
        nav_hints: list[str] = []
        if not self._model.is_first:
            nav_hints.append("ctrl+left back")
        if not self._model.is_last:
            nav_hints.append("ctrl+right next")
        if self._model.is_savable():
            nav_hints.append("ctrl+s save")
        nav_hints.append("esc cancel")
        out.append("   ")
        out.append("   ".join(nav_hints), style="dim")
        summary = summarize(self._model.validate())
        if summary.errors or summary.warnings:
            out.append("\n")
            out.append("Validation: ", style="dim")
            if summary.errors:
                out.append(
                    f"{summary.errors} error(s) ",
                    style=f"bold {DEFAULT_TOKENS.accent_red}",
                )
            if summary.warnings:
                out.append(
                    f"{summary.warnings} warning(s) ",
                    style=DEFAULT_TOKENS.accent_amber,
                )
        return out

    # Back-compat alias - older tests imported ``_render_footer``.
    _render_footer = _render_status


# --- step renderers --------------------------------------------------------


def _render_posture(model: QuickStartWizardModel) -> Text:
    out = Text()
    out.append("What posture should we start from?\n\n", style="bold")
    cur_idx = next(
        (i for i, p in enumerate(POSTURES) if p.id == model.selected_posture().id),
        1,
    )
    for i, posture in enumerate(POSTURES):
        marker = ">" if i == cur_idx else " "
        active = "*" if model.answers.posture == posture.id else " "
        title_style = "bold" if i == cur_idx else ""
        # Parentheses (not square brackets) are deliberate: square
        # brackets risk being parsed as Rich style tags downstream.
        out.append(f" {marker} ({active}) ")
        out.append(f"{posture.title}\n", style=title_style)
        out.append(f"      {posture.description}\n\n", style="dim")
    out.append(
        "up/down move  enter pick & next  p/d/s shortcuts",
        style="dim",
    )
    return out


def _render_block(model: QuickStartWizardModel) -> Text:
    out = Text()
    out.append("What should we block?\n\n", style="bold")
    cursor = model.block_cursor()
    for cat in BLOCK_CATEGORIES:
        # Use ``BLOCK_DISPLAY_ORDER`` rather than re-grouping inline
        # so render and navigation stay locked to the same iteration
        # order.
        idxs = [i for i in BLOCK_DISPLAY_ORDER if BLOCK_CARDS[i].category == cat.id]
        if not idxs:
            continue
        out.append(f"  {cat.title}\n", style="bold")
        out.append(f"    {cat.blurb}\n\n", style="dim")
        for i in idxs:
            card = BLOCK_CARDS[i]
            marker = ">" if i == cursor else " "
            checked = "x" if card.id in model.answers.block else " "
            line_style = "bold" if i == cursor else ""
            out.append(f"   {marker} ({checked}) ", style=line_style)
            out.append(f"{rich_escape(card.title)}\n", style=line_style)
        out.append("\n")
    out.append(
        "up/down move  enter/space toggle  ctrl+right next",
        style="dim",
    )
    return out


def _block_cursor_line(model: QuickStartWizardModel) -> int:
    """Return the 0-indexed line in the block body where the cursor
    sits, taking the category headers and blurbs into account.

    Layout per category (when present):
        line 0:  ``  <Title>``
        line 1:  ``    <blurb>``
        line 2:  blank
        line 3+: one card per line
        line N:  blank between categories
    Body header costs 2 lines (title + blank).
    """

    cursor = model.block_cursor()
    for line, idx in _block_lines_to_card_idx(model).items():
        if idx == cursor:
            return line
    return 2


def _block_lines_to_card_idx(model: QuickStartWizardModel) -> dict[int, int]:
    """Inverse of :func:`_block_cursor_line` for click routing.

    Walks the same iteration as :func:`_render_block` so a click on
    line ``L`` lands on whichever ``BLOCK_CARDS`` index is rendered
    on that line.
    """

    out: dict[int, int] = {}
    line = 2  # "What should we block?" + blank
    for cat in BLOCK_CATEGORIES:
        idxs = [i for i in BLOCK_DISPLAY_ORDER if BLOCK_CARDS[i].category == cat.id]
        if not idxs:
            continue
        line += 3  # title + blurb + blank
        for i in idxs:
            out[line] = i
            line += 1
        line += 1
    return out


def _posture_lines_to_idx(_model: QuickStartWizardModel) -> dict[int, int]:
    """Map clickable lines to ``POSTURES`` indices.

    Each posture renders as a title row + (Rich-wrapped) description
    + blank. Description wrapping is width-dependent and we don't
    know the body width here, so we register the title row alone as
    the click hot zone. Clicks on description rows fall through to
    a no-op, which is the conservative choice (no accidental picks).
    """

    out: dict[int, int] = {}
    line = 2  # "What posture should we start from?" + blank
    for i in range(len(POSTURES)):
        out[line] = i
        line += 3  # title + description + blank
    return out


def _response_lines_to_idx(_model: QuickStartWizardModel) -> dict[int, int]:
    """Same shape as :func:`_posture_lines_to_idx`; each response
    row is title + description + blank.
    """

    out: dict[int, int] = {}
    line = 2  # "When something risky happens..." + blank
    for i in range(len(RESPONSES)):
        out[line] = i
        line += 3
    return out


def _allow_lines_to_idx(model: QuickStartWizardModel) -> dict[int, int]:
    """Map clickable lines in the toggle region to ``ALLOW_CARDS``
    indices.

    Layout (cursor.mode == "allow"):
        line 0: header
        line 1: blank
        line 2: "  Region: <label>"
        line 3: blank
        line 4..4+N-1: one card per line

    We register only the toggle-region rows so a click on the
    Domain / First-party panels (which contain free-text inputs)
    doesn't accidentally toggle a card.
    """

    cur = model.allow_cursor_state()
    if cur.mode != "allow":
        return {}
    out: dict[int, int] = {}
    line = 4  # header + blank + region label + blank
    for i in range(len(ALLOW_CARDS)):
        out[line] = i
        line += 1
    return out


def _sinks_lines_to_idx(model: QuickStartWizardModel) -> dict[int, int]:
    """Each sink renders as title + description + blank, plus
    one extra line per visible config field when the sink is
    enabled. We expose the title line for click-to-toggle so a
    click on a URL/env-var input row doesn't toggle and clobber
    the operator's typing.
    """

    out: dict[int, int] = {}
    line = 2  # "Where should events go?" + blank
    for row, card in enumerate(SINK_CARDS):
        ans = model.answers.sinks.get(card.id)
        enabled = bool(ans and ans.enabled)
        out[line] = row
        rows = 3 + (len(card.config_fields) if enabled and card.config_fields else 0)
        line += rows + 1
    return out


def _render_allow(model: QuickStartWizardModel) -> Text:
    out = Text()
    out.append("What should we allow even when flagged?\n\n", style="bold")
    cursor = model.allow_cursor_state()
    mode_label = {
        "allow": "Toggles",
        "domain": "Allow domains",
        "first_party": "First-party globs",
    }[cursor.mode]
    out.append(f"  Region: {mode_label}\n\n", style="bold")

    for i, card in enumerate(ALLOW_CARDS):
        active_marker = ">" if cursor.mode == "allow" and i == cursor.index else " "
        checked = "x" if card.id in model.answers.allow else " "
        out.append(f"   {active_marker} ({checked}) {rich_escape(card.title)}\n")
    out.append("\n")

    out.append(
        f"  Domains (firewall.allowed_domains): {len(model.answers.domains_extra)}\n",
        style="bold" if cursor.mode == "domain" else "",
    )
    for d in model.answers.domains_extra:
        out.append(f"    - {rich_escape(d)}\n", style="dim")
    if cursor.mode == "domain":
        out.append(f"    >> {rich_escape(cursor.domain_input)}_\n", style="bold")

    out.append(
        f"\n  First-party globs: {len(model.answers.first_party_extra)}\n",
        style="bold" if cursor.mode == "first_party" else "",
    )
    for fp in model.answers.first_party_extra:
        out.append(f"    - {rich_escape(fp)}\n", style="dim")
    if cursor.mode == "first_party":
        out.append(f"    >> {rich_escape(cursor.first_party_input)}_\n", style="bold")

    out.append(
        "\nup/down move  enter toggle/commit  tab switch region  delete remove last",
        style="dim",
    )
    return out


def _allow_cursor_line(model: QuickStartWizardModel) -> int:
    """Approximate the line offset of the cursor on the Allow step.

    Header (3 lines) + Region label (2 lines) + cursor index in the
    Toggle region. Domain/First-party regions live below the toggle
    block and have variable counts; we surface them at the start of
    that block which is good enough for "scroll into view".
    """

    cursor = model.allow_cursor_state()
    base = 5  # header + region label
    if cursor.mode == "allow":
        return base + cursor.index
    if cursor.mode == "domain":
        return base + len(ALLOW_CARDS) + 2
    return base + len(ALLOW_CARDS) + 4 + len(model.answers.domains_extra)


def _sinks_cursor_line(model: QuickStartWizardModel) -> int:
    """Each sink card uses 3 lines (title + blurb + blank). Enabled
    cards expand by their config-field count. Header is 2 lines.
    """

    cur = model.sink_cursor_state()
    line = 2
    for row, card in enumerate(SINK_CARDS):
        ans = model.answers.sinks.get(card.id)
        enabled = bool(ans and ans.enabled)
        rows = 3 + (len(card.config_fields) if enabled and card.config_fields else 0)
        if row == cur.row:
            return line
        line += rows + 1
    return line


def _render_response(model: QuickStartWizardModel) -> Text:
    out = Text()
    out.append(
        "When something risky happens, what should we do?\n\n", style="bold"
    )
    selected = model.selected_response()
    for response in RESPONSES:
        marker = ">" if response.id == selected.id else " "
        active = "*" if model.answers.response == response.id else " "
        out.append(f" {marker} ({active}) {response.title}\n")
        out.append(f"      {rich_escape(response.description)}\n\n", style="dim")
    out.append("up/down move  enter pick & next", style="dim")
    return out


def _render_sinks(model: QuickStartWizardModel) -> Text:
    out = Text()
    out.append("Where should events go?\n\n", style="bold")
    cur = model.sink_cursor_state()
    for row, card in enumerate(SINK_CARDS):
        ans = model.answers.sinks.get(card.id)
        enabled = ans.enabled if ans else False
        toggle = "(x)" if enabled else "( )"
        row_marker = ">" if row == cur.row else " "
        cell_marker = "*" if row == cur.row and cur.cell == 0 else " "
        out.append(f" {row_marker} {cell_marker}{toggle} {rich_escape(card.title)}\n")
        out.append(f"      {rich_escape(card.description)}\n", style="dim")
        if enabled and card.config_fields:
            for j, fld in enumerate(card.config_fields):
                value = (ans.url if fld.key == "url" else ans.secret_env) if ans else ""
                cell_marker = "*" if row == cur.row and cur.cell == j + 1 else " "
                out.append(
                    f"      {cell_marker}{fld.label}: {rich_escape(value or fld.placeholder)}\n",
                    style="bold" if cell_marker == "*" else "dim",
                )
        out.append("\n")
    out.append(
        "up/down rows  left/right cells  enter toggle  type to fill",
        style="dim",
    )
    return out


def _render_review(model: QuickStartWizardModel) -> Text:
    out = Text()
    out.append("Review your policy\n\n", style="bold")
    policy = model.derive_policy()
    out.append(f"  name:     {rich_escape(policy.name)}\n")
    out.append(f"  basedOn:  {rich_escape(policy.basedOn)}\n")
    out.append(
        f"  block:    {len(model.answers.block)} card(s) selected\n"
    )
    out.append(
        f"  allow:    {len(model.answers.allow)} card(s) selected\n"
    )
    out.append(f"  response: {model.answers.response}\n")
    enabled_sinks = [
        sid for sid, s in model.answers.sinks.items() if s.enabled
    ]
    out.append(
        f"  sinks:    {len(enabled_sinks)} enabled "
        f"({', '.join(enabled_sinks) if enabled_sinks else 'none'})\n\n"
    )
    findings = model.validate()
    summary = summarize(findings)
    if summary.errors:
        out.append(
            f"  {summary.errors} validation error(s) - fix before saving:\n",
            style=f"bold {DEFAULT_TOKENS.accent_red}",
        )
        for f in findings:
            if f.level != "error":
                continue
            # Code is rendered with parens (not brackets) to keep the
            # token off the Rich-markup parser path.
            out.append(f"    - ({f.code}) {rich_escape(f.message)}\n", style="dim")
    elif summary.warnings:
        out.append(
            f"  {summary.warnings} warning(s) - safe to save:\n",
            style=DEFAULT_TOKENS.accent_amber,
        )
    else:
        out.append("  No validation findings - ready to save.\n", style="dim")

    out.append("\npress enter or ctrl+s to save", style="dim")
    return out


__all__ = ["QuickStartScreen"]
