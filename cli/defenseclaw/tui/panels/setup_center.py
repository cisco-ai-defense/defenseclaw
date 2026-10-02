# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The Setup center: what the Setup panel draws around its tables.

The task list shows one group at a time. The nav lists the groups (task
count, ``!`` when a task needs attention) and the config editor; the table
lists the selected group's tasks with a Status column; the detail tells what
the selected task does, where it stands now, what needs fixing and what it
runs. In the config editor the nav lists the sections by group instead.

Everything here is pure: the app hands in the ``SetupPanelModel`` and draws
the result through the shared split layout (``widgets/panel_split.py``).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from rich.text import Text

from defenseclaw.tui.panels import setup_catalog
from defenseclaw.tui.panels.setup import (
    WIZARD_DESCRIPTIONS,
    WIZARD_HOW_TO,
    SetupWizard,
    wizard_goals,
    wizard_state_summary,
)
from defenseclaw.tui.panels.setup_catalog import TaskStatus
from defenseclaw.tui.services.setup_state import (
    is_config_env_name_field,
    is_secret_config_field,
    looks_like_secret_value,
    validate_config_field,
)
from defenseclaw.tui.theme import DEFAULT_TOKENS
from defenseclaw.tui.widgets.panel_split import Aside, NavItem

TOKENS = DEFAULT_TOKENS

NAV_CONFIG = "config"
NAV_TASKS = "tasks"
_GROUP = "group:"
_SECTION = "section:"

_STATE_STYLES: Mapping[str, str] = {
    "ok": TOKENS.accent_green,
    "attention": TOKENS.accent_amber,
    "off": TOKENS.text_muted,
    "na": TOKENS.text_muted,
}


def glyph_style(label: str) -> str:
    """Colour for a Status cell, from its leading glyph ("" if it has none)."""

    for state, glyph in setup_catalog.TASK_GLYPHS.items():
        if label.startswith(f"{glyph} "):
            return _STATE_STYLES[state]
    return ""


# --- statuses ---------------------------------------------------------------


def task_statuses(model: Any) -> dict[SetupWizard, TaskStatus]:
    """Every task's status for ``model`` (a SetupPanelModel)."""

    readiness = tuple(getattr(model, "readiness_checks", ()) or ())
    return {
        wizard: setup_catalog.task_status(
            wizard,
            model.config,
            readiness,
            credentials=getattr(model, "credential_snapshot", None),
            observability=getattr(model, "observability_status", None),
            observability_error=getattr(model, "observability_status_error", ""),
            available=model.wizard_available(wizard),
        )
        for wizard in setup_catalog.display_order()
    }


def status_cell(model: Any, wizard: SetupWizard, status: TaskStatus) -> str:
    """The Status cell: a running or failed run wins over the config state."""

    run = str(getattr(model, "wizard_status", {}).get(wizard, "") or "")
    if run.startswith("running"):
        info = next((info for info in model.wizard_infos() if info.wizard == wizard), None)
        return f"… {(info.status if info else run).rstrip('.')}"
    if run == "failed":
        return "! last run failed"
    if run == "done":
        return f"{status.label} · ran ok"
    return status.label


def header_counts(statuses: Mapping[SetupWizard, TaskStatus]) -> tuple[int, int]:
    """``(ok, need attention)`` task counts for the Setup header line."""

    values = tuple(statuses.values())
    return (
        sum(1 for status in values if status.state == "ok"),
        sum(1 for status in values if status.state == "attention"),
    )


# --- task table ---------------------------------------------------------------


def active_group(model: Any) -> str:
    return setup_catalog.wizard_group(model.active_wizard)


def task_rows(model: Any, statuses: Mapping[SetupWizard, TaskStatus]) -> tuple[tuple[str, str], ...]:
    """``(Task, Status)`` rows of the selected group."""

    return tuple(
        (setup_catalog.wizard_label(wizard), status_cell(model, wizard, statuses[wizard]))
        for wizard in setup_catalog.group_tasks(active_group(model))
    )


# --- nav ------------------------------------------------------------------------


def task_nav(model: Any, statuses: Mapping[SetupWizard, TaskStatus]) -> tuple[NavItem, ...]:
    """Task groups (count, ``!`` for attention) and the config editor."""

    current = active_group(model)
    items: list[NavItem] = []
    for title in setup_catalog.GROUP_TITLES:
        tasks = setup_catalog.group_tasks(title)
        attention = any(statuses[wizard].state == "attention" for wizard in tasks)
        badge = f"{len(tasks)} !" if attention else str(len(tasks))
        items.append(NavItem(f"{_GROUP}{title}", title, badge, active=title == current))
    items.append(NavItem(NAV_CONFIG, "Config editor"))
    return tuple(items)


def config_nav(model: Any) -> tuple[NavItem, ...]:
    """Back to the tasks, then the config sections under their groups."""

    sections = tuple(getattr(model, "sections", ()) or ())
    items = [NavItem(NAV_TASKS, "‹ Setup tasks")]
    for index in setup_catalog.section_order(sections):
        section = sections[index]
        counts = setup_catalog.section_counts(section)
        badge = " ".join(
            part for part in (f"{counts.changed}✎" if counts.changed else "", "!" if counts.errors else "") if part
        )
        items.append(
            NavItem(
                f"{_SECTION}{index}",
                section.name,
                badge,
                active=index == model.active_section,
                group=setup_catalog.section_group(section.name),
            )
        )
    return tuple(items)


def select_nav(model: Any, key: str) -> bool:
    """Apply a Setup nav choice to ``model``; False for keys it doesn't know.

    A group shows that group's tasks (keeping the selected task if it is in
    the group), ``config`` opens the config editor, ``tasks`` goes back to
    the task list and ``section:N`` opens section N. A goal menu closes first;
    an open wizard form is never discarded.
    """

    if getattr(model, "form_active", False):
        return False
    if key.startswith(_GROUP):
        group = key[len(_GROUP) :]
        tasks = setup_catalog.group_tasks(group)
        if not tasks:
            return False
        _close_goals(model)
        model.mode = "wizards"
        if model.active_wizard not in tasks:
            model.active_wizard = tasks[0]
        return True
    if key == NAV_CONFIG:
        _close_goals(model)
        if model.mode != "config":
            model.mode = "config"
            model.active_line = model.first_editable_line()
        return True
    if key == NAV_TASKS:
        model.mode = "wizards"
        return True
    if key.startswith(_SECTION):
        try:
            index = int(key[len(_SECTION) :])
        except ValueError:
            return False
        if not 0 <= index < len(getattr(model, "sections", ()) or ()):
            return False
        model.mode = "config"
        model.select_section(index)
        return True
    return False


def _close_goals(model: Any) -> None:
    if getattr(model, "goal_active", False):
        model.goal_active = False
        model.goals = ()
        model.active_goal = None


# --- detail ---------------------------------------------------------------------


def _line(text: Text, label: str, value: str, style: str = "") -> None:
    if text.plain:
        text.append("\n")
    text.append(f"{label} ", style=f"bold {TOKENS.text_secondary}")
    text.append(value, style=style or TOKENS.text_primary)


def _status_problems(model: Any, wizard: SetupWizard, status: TaskStatus) -> list[tuple[str, str]]:
    """Attention items that come from the task's own state, not readiness."""

    if status.state != "attention":
        return []
    if wizard == SetupWizard.REDACTION:
        return [("Redaction is turned off, so logs and exports keep secrets.", "defenseclaw setup redaction")]
    if wizard == SetupWizard.CREDENTIALS:
        error = str(getattr(getattr(model, "credential_snapshot", None), "error", "") or "")
        if error:
            return [(f"Couldn't list the API keys: {error}", "defenseclaw keys list")]
    if wizard == SetupWizard.OBSERVABILITY:
        error = str(getattr(model, "observability_status_error", "") or "")
        if error:
            return [(error, "defenseclaw observability validate")]
    return []


def task_detail(model: Any, wizard: SetupWizard, status: TaskStatus) -> Text:
    """Description, Now, what needs attention (with fixes), Runs, and goals."""

    how_to = WIZARD_HOW_TO[int(wizard)]
    text = Text(" ".join(WIZARD_DESCRIPTIONS[int(wizard)].split()), style=TOKENS.text_primary)
    if not model.wizard_available(wizard):
        _line(text, "Unavailable:", model.wizard_unavailable_reason(wizard), TOKENS.accent_amber)
        return text
    # The wizard's own summary says more than the Status cell when it has one.
    summary = " ".join(wizard_state_summary(wizard, model.config).split())
    if summary:
        _line(text, "Now:", summary)
    else:
        _line(text, "Now:", status.label, glyph_style(status.label))
    problems = _status_problems(model, wizard, status)
    for problem in setup_catalog.task_problems(wizard, tuple(model.readiness_checks), model.config):
        detail = " ".join(problem.check.detail.split()).rstrip(".")
        if not problem.owned:
            detail = f"{problem.check.title}: {detail} ({problem.why})"
        problems.append((detail, problem.fix))
    for detail, fix in problems:
        _line(text, "Needs attention:", detail, TOKENS.accent_amber)
        if fix:
            text.append(" — fix: ", style=TOKENS.text_secondary)
            text.append(fix, style=TOKENS.accent_green)
    how_to = " ".join(how_to.split())
    if how_to.startswith("Runs:"):
        _line(text, "Runs:", how_to[len("Runs:") :].strip())
    elif how_to:
        text.append("\n")
        text.append(how_to, style=TOKENS.text_primary)
    goals = [goal.label for goal in wizard_goals(wizard, model.config)]
    if goals:
        text.append("\n")
        text.append("You can:", style=f"bold {TOKENS.text_secondary}")
        for label in goals:
            text.append("\n• ", style=TOKENS.accent_cyan)
            text.append(label, style=TOKENS.text_primary)
    return text


def task_aside(model: Any, statuses: Mapping[SetupWizard, TaskStatus]) -> Aside:
    wizard = model.active_wizard
    return Aside(setup_catalog.wizard_label(wizard), task_detail(model, wizard, statuses[wizard]))


def _secret(field: Any, value: str) -> bool:
    # A secret pasted into an *_env name field is masked too (setup_state's rule).
    return (
        getattr(field, "kind", "") == "password"
        or is_secret_config_field(field)
        or (is_config_env_name_field(field) and looks_like_secret_value(value))
    )


def _masked(field: Any, value: str) -> str:
    if not value:
        return "(empty)"
    return "****" if _secret(field, value) else value


def config_aside(model: Any) -> Aside | None:
    """The open section and the focused field (value, hint, validation)."""

    section = model.current_section()
    if section is None:
        return None
    text = Text(" ".join(str(section.summary or "").split()), style=TOKENS.text_secondary)
    field = model.current_field()
    if field is not None and not (field.kind == "header" and not field.key and not field.value):
        name = f"{field.label} ({field.key})" if field.key else field.label
        _line(text, "Field:", name)
        value = _masked(field, str(field.value or ""))
        original = str(field.original or "")
        if (
            field.value != field.original
            and not _secret(field, str(field.value or ""))
            and not _secret(field, original)
        ):
            value += f"  (was {original or '(empty)'})"
        _line(text, "Value:", value)
        hint = " ".join(str(field.hint or section.help or "").split())
        if hint:
            text.append("\n")
            text.append(hint, style=TOKENS.text_muted)
        result = validate_config_field(field)
        if result.message:
            style = TOKENS.accent_red if result.severity == "error" else TOKENS.accent_amber
            _line(text, "Check:", result.message, style)
    elif section.help:
        text.append("\n")
        text.append(" ".join(section.help.split()), style=TOKENS.text_muted)
    return Aside(section.name, text)


__all__ = [
    "NAV_CONFIG",
    "NAV_TASKS",
    "active_group",
    "config_aside",
    "config_nav",
    "glyph_style",
    "header_counts",
    "select_nav",
    "status_cell",
    "task_aside",
    "task_detail",
    "task_nav",
    "task_rows",
    "task_statuses",
]
