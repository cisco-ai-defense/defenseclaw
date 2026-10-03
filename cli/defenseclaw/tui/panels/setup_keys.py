# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The one list of Setup keys, per Setup view.

Setup has five views: the wizard list, a wizard's goal menu, the wizard
form, the config editor and the first-run form. Each view's keymap here
feeds the hint bar, the ``?`` help sheet and which Setup buttons are shown,
so the three can't disagree. Keys that only apply sometimes (restart keys
while a restart is queued, the list editor on list-backed sections, the
Credentials shortcuts on the Credentials row) carry a ``when`` condition.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Literal

SetupView = Literal["wizards", "goals", "form", "config", "first-run"]
SETUP_VIEWS: tuple[SetupView, ...] = ("wizards", "goals", "form", "config", "first-run")

# Conditions a KeySpec can depend on (see ``setup_conditions``).
Condition = Literal["", "restart_pending", "credentials", "list_editor", "secret_field"]


@dataclass(frozen=True)
class KeySpec:
    """One advertised key.

    ``key`` is how the key is written for people, ``label`` the short hint
    bar text, ``description`` the help sheet text and ``button_id`` the
    Setup button that does the same thing (None when there is none).
    ``presses`` are the key names the Setup handlers receive for it (tests
    press each one); ``when`` names the condition under which it applies and
    ``in_hint`` keeps rarely used keys out of the two-line hint bar.
    """

    key: str
    label: str
    description: str
    button_id: str | None = None
    presses: tuple[str, ...] = ()
    when: Condition = ""
    in_hint: bool = True


_RESTART = (
    KeySpec(
        "G",
        "restart gateway",
        "Restart the gateway now (a restart is queued)",
        "setup-restart",
        ("G",),
        when="restart_pending",
    ),
    KeySpec(
        "C",
        "clear restart",
        "Forget the queued gateway restart",
        "setup-clear-restart",
        ("C",),
        when="restart_pending",
        in_hint=False,
    ),
)

SETUP_KEYMAPS: dict[SetupView, tuple[KeySpec, ...]] = {
    # The task list has no button bar: the nav list (or the one-line group
    # switcher) and a double-click on a task do what its buttons did.
    "wizards": (
        KeySpec("↑/↓", "choose", "Move between setup tasks (on into the next group)", None, ("up", "down", "j", "k")),
        KeySpec(
            "←/→",
            "group",
            "Previous / next task group (also [ and ]); → after the last group opens the config editor",
            None,
            ("left", "right", "[", "]"),
        ),
        KeySpec("Enter", "open", "Open the selected task", None, ("enter",)),
        KeySpec("i", "details", "Readiness checks and what the selected task runs", None, ("i",)),
        KeySpec("c", "config", "Edit config.yaml fields directly (config editor)", None, ("c",)),
        KeySpec("f", "fill missing", "Prompt for every missing required key", None, ("f",), when="credentials"),
        KeySpec("s", "set key", "Set one API key", None, ("s",), when="credentials"),
        # Shown on the API keys task, where the list it reloads is (GAP-2061).
        KeySpec("r", "reload", "Reload the list of stored API keys", None, ("r",), when="credentials"),
        *_RESTART,
    ),
    "goals": (
        KeySpec("↑/↓", "choose", "Move between goals", None, ("up", "down", "j", "k")),
        KeySpec("Enter", "open", "Open the form for this goal", None, ("enter",)),
        KeySpec("Esc", "back", "Back to the task list", None, ("esc",)),
    ),
    "form": (
        KeySpec("↑/↓", "field", "Move between fields (Tab and Shift+Tab too)", None, ("up", "down")),
        KeySpec("Shift+Tab", "previous field", "Previous field", "setup-wizard-prev", ("shift+tab",), in_hint=False),
        KeySpec("Tab", "next field", "Next field", "setup-wizard-next", ("tab",), in_hint=False),
        KeySpec("Enter", "edit field", "Edit the field, flip a yes/no or step a choice", None, ("enter",)),
        KeySpec("←/→", "change choice", "Step through a field's choices", None, ("left", "right")),
        KeySpec("Ctrl+R", "run", "Run the command shown under Will run", "setup-wizard-run", ("ctrl+r",)),
        KeySpec(
            "Ctrl+T",
            "show secrets",
            "Show or hide secret values",
            "setup-wizard-reveal",
            ("ctrl+t",),
            when="secret_field",
            in_hint=False,
        ),
        KeySpec("Ctrl+U", "clear field", "Clear the field", "setup-wizard-clear", ("ctrl+u",), in_hint=False),
        KeySpec("Esc", "cancel", "Close the form without running", "setup-wizard-cancel", ("esc",)),
    ),
    "config": (
        KeySpec("↑/↓", "field", "Move between fields", None, ("up", "down", "j", "k")),
        KeySpec("Enter", "edit", "Edit the field, flip true/false or step a choice", None, ("enter",)),
        KeySpec(
            "Tab/Shift+Tab",
            "section",
            "Next / previous section (also ←/→)",
            None,
            ("tab", "shift+tab", "left", "right"),
        ),
        KeySpec("g", "sections", "List every section by group", None, ("g",)),
        KeySpec("/", "find field", "Find a field by name or key in any section", None, ("/",)),
        KeySpec("E", "list editor", "Edit this section's list entries", "setup-edit-list", ("E",), when="list_editor"),
        KeySpec("S", "review & save", "Review the changes, then save config.yaml", "setup-save", ("S",)),
        KeySpec("R", "revert", "Drop unsaved changes", "setup-revert", ("R",)),
        KeySpec("w", "wizards", "Back to the setup tasks", "setup-mode-wizards", ("w",)),
        *_RESTART,
    ),
    "first-run": (
        KeySpec("↑/↓", "field", "Move between fields", None, ("up", "down", "j", "k")),
        KeySpec("←/→", "change", "Change the value", None, ("left", "right", "enter")),
        KeySpec("Ctrl+R", "apply", "Write the config with these choices", None, ("ctrl+r",)),
    ),
}

# Every button in the Setup bars, so views can hide the ones they don't use.
SETUP_BUTTON_IDS: tuple[str, ...] = (
    "setup-mode-wizards",
    "setup-edit-list",
    "setup-save",
    "setup-revert",
    "setup-restart",
    "setup-clear-restart",
)
SETUP_WIZARD_BUTTON_IDS: tuple[str, ...] = (
    "setup-wizard-run",
    "setup-wizard-cancel",
    "setup-wizard-prev",
    "setup-wizard-next",
    "setup-wizard-reveal",
    "setup-wizard-clear",
)
LIST_EDITOR_SECTIONS = frozenset({"Observability", "Webhooks", "Trusted Paths"})


def setup_view(model: Any, *, first_run: bool = False) -> SetupView:
    """Which Setup view ``model`` (a SetupPanelModel) is showing."""

    if first_run:
        return "first-run"
    if getattr(model, "goal_active", False):
        return "goals"
    if getattr(model, "form_active", False):
        return "form"
    if getattr(model, "mode", "wizards") == "config":
        return "config"
    return "wizards"


def setup_conditions(model: Any) -> frozenset[str]:
    """The conditions that currently hold for ``model``."""

    from defenseclaw.tui.panels.setup import SetupWizard

    held: set[str] = set()
    queue = getattr(model, "restart_queue", None)
    if getattr(queue, "pending", False):
        held.add("restart_pending")
    if getattr(model, "active_wizard", None) == SetupWizard.CREDENTIALS:
        held.add("credentials")
    current = model.current_section() if hasattr(model, "current_section") else None
    if current is not None and current.name in LIST_EDITOR_SECTIONS:
        held.add("list_editor")
    if any(getattr(field, "kind", "") == "password" for field in getattr(model, "form_fields", ()) or ()):
        held.add("secret_field")
    return frozenset(held)


def keymap(view: SetupView, conditions: Iterable[str] = ()) -> tuple[KeySpec, ...]:
    """The keys that apply in ``view`` given the conditions that hold."""

    held = set(conditions)
    return tuple(spec for spec in SETUP_KEYMAPS[view] if not spec.when or spec.when in held)


# The task list's hint is one row at 80 columns (the bar pads one cell on
# each side); it has no button bar to fall back on.
HINT_WIDTH = 78
ONE_ROW_VIEWS: frozenset[str] = frozenset({"wizards"})
# "? all keys" read as "show all API keys" on the API keys task (GAP-2061).
MORE_KEYS = "? help"


def keys_hint(view: SetupView, conditions: Iterable[str] = ()) -> str:
    """Hint bar text: ``↑/↓ choose · Enter open · …``.

    On the task list the keys of the selected task (``f``, ``s``, ``G``) win
    over the general ones: those go from the end until the line fits one
    80-column row, and ``? help`` points at the help sheet that still
    lists them (GAP-1825). ``Enter open`` is the task list's main key, so it
    stays while ``←/→``, ``i`` and ``c`` give way.
    """

    specs = [spec for spec in keymap(view, conditions) if spec.in_hint]

    def join(items: list[KeySpec], *more: str) -> str:
        return " · ".join([*(f"{spec.key} {spec.label}" for spec in items), *more])

    text = join(specs)
    if view not in ONE_ROW_VIEWS or len(text) <= HINT_WIDTH:
        return text
    # The general keys go first, then r (reload) and last Enter.
    droppable = [spec for spec in reversed(specs[1:]) if not spec.when and spec.key != "Enter"]
    droppable += [spec for key in ("r", "Enter") for spec in specs[1:] if spec.key == key]
    for spec in droppable:
        specs.remove(spec)
        text = join(specs, MORE_KEYS)
        if len(text) <= HINT_WIDTH:
            break
    return text


def help_rows(view: SetupView, conditions: Iterable[str] = ()) -> list[tuple[str, str]]:
    """``?`` help sheet rows for ``view``."""

    return [(spec.key, spec.description) for spec in keymap(view, conditions)]


def visible_buttons(view: SetupView, conditions: Iterable[str] = ()) -> frozenset[str]:
    """Setup buttons that belong on screen in ``view``."""

    return frozenset(spec.button_id for spec in keymap(view, conditions) if spec.button_id)


__all__ = [
    "LIST_EDITOR_SECTIONS",
    "SETUP_BUTTON_IDS",
    "SETUP_KEYMAPS",
    "SETUP_VIEWS",
    "SETUP_WIZARD_BUTTON_IDS",
    "KeySpec",
    "SetupView",
    "help_rows",
    "keymap",
    "keys_hint",
    "setup_conditions",
    "setup_view",
    "visible_buttons",
]
