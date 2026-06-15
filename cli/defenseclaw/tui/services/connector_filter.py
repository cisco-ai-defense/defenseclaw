# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Shared connector-filter state for the multi-connector TUI.

This is the Python equivalent of the ``connector_label.go`` helpers in the
8.13 design. Rather than the old "focus one connector at a time" modal, the
TUI keeps a single connector-filter selection (``""`` = All connectors) that
every pane honours: the Overview tiles + CONNECTORS table, the
Alerts/Audit/Logs row filters, and (pass 2) the merged catalog/inventory rows.

The module is intentionally pure (no Textual / Rich imports) so the cycle and
match logic stay unit-testable in isolation.
"""

from __future__ import annotations

# Sentinel for "no connector filter" (show every connector). Empty string so
# it threads cleanly through code paths that already treat "" as "unset".
ALL = ""

# Operator-facing label for the ALL selection in the chip.
ALL_LABEL = "All"


def active_connector_names(connector_modes: tuple[tuple[str, str], ...]) -> list[str]:
    """Active connector names from ``OverviewConfig.connector_modes``.

    Mirrors Go's ``ActiveConnectorNames``. Returns the names in roster order,
    dropping blanks. Single-connector installs yield a one-element list (or
    empty when nothing is configured), so callers can treat ``len <= 1`` as
    "no multi-connector chrome".
    """

    return [c for c, _mode in connector_modes if c]


def active_connector_name(connector_modes: tuple[tuple[str, str], ...]) -> str:
    """Primary connector name (first active), or ``""`` when none.

    Mirrors Go's ``ActiveConnectorName`` = ``ActiveConnectorNames()[0]`` but
    is null-safe for the no-connector case.
    """

    names = active_connector_names(connector_modes)
    return names[0] if names else ""


def normalize_filter(current: str, names: list[str]) -> str:
    """Clamp a filter selection to a still-valid connector or ALL.

    If the previously-selected connector is no longer active (e.g. it was
    torn down), fall back to ALL so the UI never filters to a dead connector.
    """

    current = (current or "").strip().lower()
    if not current:
        return ALL
    return current if current in names else ALL


def cycle_filter(current: str, names: list[str], delta: int = 1) -> str:
    """Step the filter through ``All -> name0 -> name1 -> ... -> All``.

    ``delta`` may be negative to cycle backwards. With no/one connector the
    selection collapses to ALL (there is nothing to cycle through).
    """

    if len(names) <= 1:
        return ALL
    order = [ALL, *names]
    current = normalize_filter(current, names)
    try:
        index = order.index(current)
    except ValueError:
        index = 0
    return order[(index + delta) % len(order)]


def chip_segments(current: str, names: list[str]) -> list[tuple[str, bool]]:
    """Return ``[(label, is_active)]`` for the chip: ``All`` then each name.

    Pure data so the renderer (app.py) owns styling. ``is_active`` marks the
    currently-selected segment. Returns ``[]`` for ≤1 connector so the chip
    is hidden on single-connector installs.
    """

    if len(names) <= 1:
        return []
    current = normalize_filter(current, names)
    segments: list[tuple[str, bool]] = [(ALL_LABEL, current == ALL)]
    for name in names:
        segments.append((name, current == name))
    return segments


def filter_allows(current: str, connector: str) -> bool:
    """True when a row/event for ``connector`` should be shown under ``current``.

    ALL shows everything. Otherwise the row's attributed connector must match
    the selection exactly (case-insensitive). ``current`` is always a full
    connector name here — it comes from the chip / connector-filter picker, not
    free-text — so an exact compare is correct and avoids cross-matching
    overlapping names (e.g. a ``"claw"``-style selection bleeding into
    ``"openclaw"``/``"zeptoclaw"``). A row whose attributed connector is empty
    is hidden under an explicit filter.
    """

    current = (current or "").strip().lower()
    if not current:
        return True
    return current == (connector or "").strip().lower()
