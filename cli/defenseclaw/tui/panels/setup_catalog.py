# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""How the Setup panel groups and names its wizards and config sections.

``SetupWizard`` values are stable ids (tests, intents and saved state use
them), so the display order lives here instead: ``display_rows()`` lists
group header rows and wizard rows in the order the table shows them, and
``row_for`` / ``wizard_at`` map between table rows and wizards.

The config editor's sections get the same treatment: ``section_groups``
sorts them into a handful of groups for the ``g`` section list, and
``field_entries`` / ``filter_field_entries`` back the ``/`` field finder.
All of this is pure so it is unit-tested without Textual.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from defenseclaw.tui.panels.setup import WIZARD_NAMES, SetupWizard
from defenseclaw.tui.services.setup_state import ConfigSection, validate_config_field

# (group title, ((wizard, friendly label), ...)). Every SetupWizard member
# appears exactly once; test_setup_catalog.py enforces it.
WIZARD_GROUPS: tuple[tuple[str, tuple[tuple[SetupWizard, str], ...]], ...] = (
    (
        "Get protected",
        (
            (SetupWizard.CONNECTOR_SETUP, "Protect an agent"),
            (SetupWizard.CREDENTIALS, "API keys & secrets"),
            (SetupWizard.LLM, "LLM for scanners & judge"),
        ),
    ),
    (
        "Guardrail & scanning",
        (
            (SetupWizard.GUARDRAIL, "Guardrail"),
            (SetupWizard.GUARDRAIL_ACTIONS, "Guardrail on/off, fail mode, approvals"),
            (SetupWizard.SKILL_SCANNER, "Skill Scanner"),
            (SetupWizard.MCP_SCANNER, "MCP Scanner"),
            (SetupWizard.REDACTION, "Redaction"),
            (SetupWizard.TRUSTED_PATHS, "Trusted agent binaries"),
            (SetupWizard.REGISTRIES, "Approved catalogs"),
            (SetupWizard.ACP_GUARD, "Editor agents (ACP)"),
            (SetupWizard.SANDBOX, "Sandboxes (OpenShell)"),
        ),
    ),
    (
        "Alerts & telemetry",
        (
            (SetupWizard.NOTIFICATIONS_ROUTING, "What notifies you"),
            (SetupWizard.WEBHOOKS, "Chat & paging webhooks"),
            (SetupWizard.OBSERVABILITY, "Export telemetry"),
            (SetupWizard.SPLUNK, "Splunk"),
            (SetupWizard.SPLUNK_DASHBOARDS, "Splunk Dashboards"),
            (SetupWizard.LOCAL_OBSERVABILITY, "Local observability stack"),
        ),
    ),
    (
        "Gateway & advanced",
        (
            (SetupWizard.GATEWAY, "Gateway"),
            (SetupWizard.TOKEN_ROTATION, "Rotate gateway tokens"),
            (SetupWizard.CUSTOM_PROVIDERS, "Custom LLM providers"),
            (SetupWizard.AI_DISCOVERY, "AI usage discovery"),
        ),
    ),
)

_LABELS: dict[SetupWizard, str] = {wizard: label for _title, items in WIZARD_GROUPS for wizard, label in items}
_GROUP_OF: dict[SetupWizard, str] = {wizard: title for title, items in WIZARD_GROUPS for wizard, _label in items}


def wizard_label(wizard: SetupWizard | int) -> str:
    """Plain name for a wizard (falls back to the historical name)."""

    wizard = SetupWizard(wizard)
    return _LABELS.get(wizard) or WIZARD_NAMES[int(wizard)]


def wizard_group(wizard: SetupWizard | int) -> str:
    return _GROUP_OF.get(SetupWizard(wizard), "")


RowKind = Literal["header", "wizard"]


@dataclass(frozen=True)
class SetupDisplayRow:
    kind: RowKind
    label: str
    group: str
    wizard: SetupWizard | None = None

    @property
    def selectable(self) -> bool:
        return self.kind == "wizard"


def _build_rows() -> tuple[SetupDisplayRow, ...]:
    rows: list[SetupDisplayRow] = []
    for title, items in WIZARD_GROUPS:
        rows.append(SetupDisplayRow("header", title, title))
        rows.extend(SetupDisplayRow("wizard", label, title, wizard) for wizard, label in items)
    return tuple(rows)


_ROWS = _build_rows()
_ROW_OF: dict[SetupWizard, int] = {row.wizard: index for index, row in enumerate(_ROWS) if row.wizard is not None}
_ORDER: tuple[SetupWizard, ...] = tuple(row.wizard for row in _ROWS if row.wizard is not None)


def display_rows() -> tuple[SetupDisplayRow, ...]:
    """Header and wizard rows in table order."""

    return _ROWS


def display_order() -> tuple[SetupWizard, ...]:
    """Wizards in the order the table shows them."""

    return _ORDER


def row_for(wizard: SetupWizard | int) -> int:
    """Table row that shows ``wizard``."""

    return _ROW_OF[SetupWizard(wizard)]


def wizard_at(row: int) -> SetupWizard | None:
    """Wizard shown on table ``row``; None for a group header or out of range."""

    if 0 <= row < len(_ROWS):
        return _ROWS[row].wizard
    return None


def nearest_wizard(row: int, *, prefer_down: bool = True) -> SetupWizard:
    """Wizard on ``row``, or the closest one when ``row`` is a group header.

    Used when the table cursor lands on a header (mouse click, DataTable
    arrow keys): it moves on in the direction of travel, or back when there
    is nothing further that way.
    """

    row = max(0, min(row, len(_ROWS) - 1))
    if (wizard := wizard_at(row)) is not None:
        return wizard
    steps = (1, -1) if prefer_down else (-1, 1)
    for step in steps:
        index = row + step
        while 0 <= index < len(_ROWS):
            if (wizard := wizard_at(index)) is not None:
                return wizard
            index += step
    return _ORDER[0]


def step_wizard(wizard: SetupWizard | int, delta: int, *, wrap: bool = False) -> SetupWizard:
    """Next/previous wizard in display order (headers are skipped)."""

    index = _ORDER.index(SetupWizard(wizard)) + delta
    if wrap:
        return _ORDER[index % len(_ORDER)]
    return _ORDER[max(0, min(index, len(_ORDER) - 1))]


def setup_detail_pairs(model: object) -> tuple[tuple[str, str], ...]:
    """What ``i`` shows on the wizard list: the selected task, then readiness.

    ``model`` is a SetupPanelModel. Checks that need attention come first,
    each with the command that fixes it when there is one.
    """

    info = model.active_wizard_info()  # type: ignore[attr-defined]
    pairs: list[tuple[str, str]] = [
        ("Task", f"{wizard_label(info.wizard)} ({wizard_group(info.wizard)})"),
        ("What it does", info.description),
        ("How it works", info.how_to),
        ("Command", " ".join(info.argv)),
    ]
    if info.status == "unsupported":
        pairs.append(("Unavailable", model.wizard_unavailable_reason(info.wizard)))  # type: ignore[attr-defined]
    checks = tuple(getattr(model, "readiness_checks", ()) or ())
    ranked = sorted(checks, key=lambda check: {"fail": 0, "warn": 1}.get(check.status, 2))
    for check in ranked:
        value = f"{check.status.upper()} · {check.detail}"
        fix = getattr(check, "fix", None)
        if fix is not None and check.status != "pass":
            value += f" · fix: {getattr(fix, 'binary', 'defenseclaw')} {' '.join(fix.args)}"
        pairs.append((check.title, value))
    snapshot = getattr(model, "credential_snapshot", None)
    if getattr(snapshot, "error", ""):
        pairs.append(("API keys", f"Could not list keys: {snapshot.error}"))
    elif not getattr(snapshot, "rows", ()):
        pairs.append(("API keys", "Not loaded yet; press r on the task list to load them."))
    return tuple(pairs)


# --- config sections -------------------------------------------------------

SECTION_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Core", ("General", "Agent", "Claw", "Gateway", "Gateway Watcher", "Gateway Watchdog")),
    (
        "Protection",
        (
            "Guardrail",
            "Scanners",
            "Asset Policy",
            "Skill Actions",
            "MCP Actions",
            "Plugin Actions",
            "Cisco AI Defense",
            "Firewall",
            "Trusted Paths",
            "OpenShell Sandboxes",
            "Watch",
        ),
    ),
    ("Hooks (read-only)", ("Agent Hooks", "Connector Hooks")),
    ("Observability", ("Observability", "Webhooks", "Notifications", "AI Discovery")),
    ("Legacy", ("Inspect LLM (legacy - read-only)",)),
)
_DEFAULT_SECTION_GROUP = "Core"
_LEGACY_GROUP = "Legacy"


def section_group(name: str) -> str:
    for title, names in SECTION_GROUPS:
        if name in names:
            return title
    if "legacy" in name.lower():
        return _LEGACY_GROUP
    return _DEFAULT_SECTION_GROUP


def section_order(sections: Sequence[ConfigSection]) -> tuple[int, ...]:
    """Section indices in grouped order (Core first, Legacy last)."""

    group_rank = {title: rank for rank, (title, _names) in enumerate(SECTION_GROUPS)}
    name_rank = {name: rank for _title, names in SECTION_GROUPS for rank, name in enumerate(names)}
    return tuple(
        sorted(
            range(len(sections)),
            key=lambda index: (
                group_rank.get(section_group(sections[index].name), 0),
                name_rank.get(sections[index].name, len(name_rank) + index),
                index,
            ),
        )
    )


def step_section(sections: Sequence[ConfigSection], current: int, delta: int) -> int:
    """Next/previous section index in grouped order, wrapping around."""

    order = section_order(sections)
    if not order:
        return 0
    position = order.index(current) if current in order else 0
    return order[(position + delta) % len(order)]


def section_position(sections: Sequence[ConfigSection], current: int) -> tuple[int, int]:
    """1-based position of ``current`` in grouped order, and the total."""

    order = section_order(sections)
    if current not in order:
        return (0, len(order))
    return (order.index(current) + 1, len(order))


@dataclass(frozen=True)
class SectionCounts:
    changed: int = 0
    errors: int = 0


def section_counts(section: ConfigSection) -> SectionCounts:
    changed = 0
    errors = 0
    for field in section.fields:
        if field.kind == "header":
            continue
        if field.value != field.original:
            changed += 1
        if validate_config_field(field).severity == "error":
            errors += 1
    return SectionCounts(changed, errors)


@dataclass(frozen=True)
class PickerRow:
    """One row of a Setup picker: a selectable entry or a group header."""

    row_id: str
    label: str
    detail: str = ""
    selectable: bool = True
    search_text: str = ""


def section_picker_rows(sections: Sequence[ConfigSection], active: int = -1) -> tuple[PickerRow, ...]:
    """Grouped section list for ``g``; row ids are section indices."""

    rows: list[PickerRow] = []
    group = None
    for index in section_order(sections):
        section = sections[index]
        title = section_group(section.name)
        if title != group:
            rows.append(PickerRow(f"group:{title}", title, selectable=False))
            group = title
        counts = section_counts(section)
        facts = []
        if counts.changed:
            facts.append(f"{counts.changed} changed")
        if counts.errors:
            facts.append(f"{counts.errors} to fix")
        if index == active:
            facts.append("open")
        rows.append(
            PickerRow(
                str(index),
                section.name,
                " · ".join(facts),
                search_text=section.name.lower(),
            )
        )
    return tuple(rows)


@dataclass(frozen=True)
class FieldEntry:
    section_index: int
    line: int
    section: str
    label: str
    key: str

    @property
    def row_id(self) -> str:
        return f"{self.section_index}:{self.line}"


def field_entries(sections: Sequence[ConfigSection]) -> tuple[FieldEntry, ...]:
    """Every real field across all sections (separator rows left out)."""

    entries: list[FieldEntry] = []
    for index in section_order(sections):
        section = sections[index]
        for line, field in enumerate(section.fields):
            if field.kind == "header" and not field.key and not field.value:
                continue
            entries.append(FieldEntry(index, line, section.name, field.label, field.key))
    return tuple(entries)


def filter_field_entries(query: str, entries: Sequence[FieldEntry]) -> tuple[FieldEntry, ...]:
    """Entries whose key or label contains every word of ``query``.

    Ranked: exact key, key prefix, label prefix, then anything else, keeping
    the section order within a rank.
    """

    words = query.strip().lower().split()
    if not words:
        return tuple(entries)
    ranked: list[tuple[int, int, FieldEntry]] = []
    for position, entry in enumerate(entries):
        key = entry.key.lower()
        label = entry.label.lower()
        haystack = f"{key} {label} {entry.section.lower()}"
        if not all(word in haystack for word in words):
            continue
        whole = " ".join(words)
        if key == whole:
            rank = 0
        elif key.startswith(whole) or key.rsplit(".", 1)[-1].startswith(whole):
            rank = 1
        elif label.startswith(whole):
            rank = 2
        else:
            rank = 3
        ranked.append((rank, position, entry))
    ranked.sort(key=lambda item: (item[0], item[1]))
    return tuple(entry for _rank, _position, entry in ranked)


def field_picker_rows(entries: Sequence[FieldEntry]) -> tuple[PickerRow, ...]:
    return tuple(
        PickerRow(
            entry.row_id,
            entry.label,
            f"{entry.section} · {entry.key}" if entry.key else entry.section,
        )
        for entry in entries
    )


__all__ = [
    "SECTION_GROUPS",
    "WIZARD_GROUPS",
    "FieldEntry",
    "PickerRow",
    "SectionCounts",
    "SetupDisplayRow",
    "display_order",
    "display_rows",
    "field_entries",
    "field_picker_rows",
    "filter_field_entries",
    "nearest_wizard",
    "row_for",
    "section_counts",
    "section_group",
    "section_order",
    "section_picker_rows",
    "section_position",
    "setup_detail_pairs",
    "step_section",
    "step_wizard",
    "wizard_at",
    "wizard_group",
    "wizard_label",
]
