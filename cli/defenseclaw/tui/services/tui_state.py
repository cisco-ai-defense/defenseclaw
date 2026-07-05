# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Persistent session state for the Textual TUI.

Stores small, non-sensitive operator preferences in
``<data_dir>/tui-state.json`` (mode 0600) so the TUI remembers the
recently used commands and per-panel "last seen" cursors across
restarts. Tokens, secrets, and credentials NEVER live here — only
opaque panel names, command aliases, and timestamps. The legacy
``active_panel`` field is still loaded for compatibility, but plain
TUI launches intentionally start on Overview.

The serializer is tolerant: missing files yield default state and a
corrupt payload is quarantined as ``tui-state.json.bak`` so the next
run starts clean instead of crashing the TUI.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path

from defenseclaw.file_permissions import atomic_write_private_bytes, reject_reparse_path

PALETTE_MRU_LIMIT = 5
STATE_FILENAME = "tui-state.json"


@dataclass(frozen=True)
class TUIState:
    """Snapshot of the operator's TUI session preferences."""

    # Retained for compatibility with existing state files and panel-visit
    # bookkeeping. ``DefenseClawTUI`` does not use it as a launch preference.
    active_panel: str = "overview"
    palette_mru: tuple[str, ...] = ()
    panel_last_seen: dict[str, str] = field(default_factory=dict)
    panel_filters: dict[str, str] = field(default_factory=dict)
    # Count of "interesting items" the operator had already seen the
    # last time they visited each panel. Used by the tab-badge renderer
    # to show "(N)" when more rows/alerts/log lines have arrived since.
    # Distinct from ``panel_last_seen`` (a timestamp) because counts
    # don't strictly correspond to wall-clock — e.g. log rotation can
    # shrink the on-disk count without time travelling.
    panel_seen_counts: dict[str, int] = field(default_factory=dict)
    # Operator-chosen Textual theme id (e.g. ``"tokyo-night"``,
    # ``"ansi-dark"``). Empty string means "use the app default"
    # (``textual-dark``) and is the migration value for existing state
    # files that pre-date the theme picker.
    theme: str = ""

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["palette_mru"] = list(self.palette_mru)
        return data

    @classmethod
    def from_dict(cls, payload: object) -> TUIState:
        if not isinstance(payload, dict):
            return cls()
        active = payload.get("active_panel", "overview")
        if not isinstance(active, str) or not active:
            active = "overview"
        mru_raw = payload.get("palette_mru", [])
        mru: tuple[str, ...] = ()
        if isinstance(mru_raw, list):
            cleaned: list[str] = []
            for item in mru_raw:
                if isinstance(item, str) and item.strip():
                    cleaned.append(item.strip())
                if len(cleaned) >= PALETTE_MRU_LIMIT:
                    break
            mru = tuple(cleaned)
        seen_raw = payload.get("panel_last_seen", {})
        seen: dict[str, str] = {}
        if isinstance(seen_raw, dict):
            for key, value in seen_raw.items():
                if isinstance(key, str) and isinstance(value, str):
                    seen[key] = value
        filters_raw = payload.get("panel_filters", {})
        filters: dict[str, str] = {}
        if isinstance(filters_raw, dict):
            for key, value in filters_raw.items():
                if isinstance(key, str) and isinstance(value, str):
                    filters[key] = value
        counts_raw = payload.get("panel_seen_counts", {})
        counts: dict[str, int] = {}
        if isinstance(counts_raw, dict):
            for key, value in counts_raw.items():
                if not isinstance(key, str):
                    continue
                # Tolerate JSON that round-trips ints as floats or
                # strings — strict typing would reject reasonable
                # values and silently lose the cursor.
                try:
                    counts[key] = max(0, int(value))
                except (TypeError, ValueError):
                    continue
        # Theme id: opaque string. We don't validate against the
        # Textual built-in list here because Textual versions ship
        # different sets of themes — letting the caller fall back to
        # the default at apply time keeps the state file forward-
        # compatible.
        theme_raw = payload.get("theme", "")
        theme = theme_raw.strip() if isinstance(theme_raw, str) else ""
        return cls(
            active_panel=active,
            palette_mru=mru,
            panel_last_seen=seen,
            panel_filters=filters,
            panel_seen_counts=counts,
            theme=theme,
        )


def _state_path_for(data_dir: Path | str | None) -> Path | None:
    """Return the persistence path, or ``None`` to disable persistence.

    We deliberately do NOT fall back to ``~/.defenseclaw`` when the
    caller passes ``data_dir=None``. Two reasons:

    * Tests and short-lived CLI invocations should not leak state into
      the operator's home directory.
    * The Go TUI follows the same rule (no data_dir -> no state file),
      so we match its behaviour.
    """

    if data_dir is None:
        return None
    return Path(data_dir) / STATE_FILENAME


class TUIStateStore:
    """Read-through / atomic-write store for :class:`TUIState`.

    Failures degrade gracefully: a missing file yields default state,
    invalid JSON is quarantined to ``<name>.bak`` and replaced with
    defaults on the next save, and write failures are swallowed so a
    read-only filesystem cannot crash the TUI.

    When constructed with ``data_dir=None`` the store runs in
    "ephemeral" mode: ``load`` returns defaults, ``save`` is a no-op.
    This keeps tests deterministic and avoids touching ``$HOME``.
    """

    def __init__(self, data_dir: Path | str | None = None) -> None:
        self._path = _state_path_for(data_dir)
        self._state = TUIState()

    @property
    def path(self) -> Path | None:
        return self._path

    @property
    def state(self) -> TUIState:
        return self._state

    @property
    def persistent(self) -> bool:
        return self._path is not None

    def load(self) -> TUIState:
        """Return the persisted state, defaulting on missing/corrupt input."""

        if self._path is None:
            self._state = TUIState()
            return self._state
        try:
            reject_reparse_path(self._path)
            raw = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            self._state = TUIState()
            return self._state
        except OSError:
            self._state = TUIState()
            return self._state
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            self._quarantine_corrupt(raw)
            self._state = TUIState()
            return self._state
        self._state = TUIState.from_dict(payload)
        return self._state

    def save(self, state: TUIState | None = None) -> bool:
        """Persist ``state`` (or the cached state) atomically.

        The file is created with mode 0600 — identical to the dotenv
        and audit-trail writers elsewhere in the project. Returns
        ``True`` on success. When the store was constructed without a
        ``data_dir`` the save is a deliberate no-op (returns ``False``).
        """

        target = state if state is not None else self._state
        self._state = target
        if self._path is None:
            return False
        try:
            body = json.dumps(target.to_dict(), indent=2, sort_keys=True)
            atomic_write_private_bytes(self._path, body.encode("utf-8"))
            return True
        except OSError:
            return False

    def record_command(self, tui_name: str) -> TUIState:
        """Bump ``tui_name`` to the front of the palette MRU queue."""

        name = (tui_name or "").strip()
        if not name:
            return self._state
        remaining = [entry for entry in self._state.palette_mru if entry != name]
        updated = (name, *remaining)[:PALETTE_MRU_LIMIT]
        self._state = replace(self._state, palette_mru=updated)
        return self._state

    def mark_seen(self, panel: str, now: datetime | None = None) -> TUIState:
        """Stamp ``panel`` with the latest "operator looked at this" cursor."""

        if not panel:
            return self._state
        stamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()
        seen = dict(self._state.panel_last_seen)
        seen[panel] = stamp
        self._state = replace(self._state, panel_last_seen=seen)
        return self._state

    def record_seen_count(self, panel: str, count: int) -> TUIState:
        """Snapshot the per-panel item count when the operator opens it.

        Pairs with ``mark_seen`` to support tab unread-badges: the
        timestamp tells us *when* they last visited, while this count
        tells us *how many* items they saw. If new items land later,
        ``current_count - seen_count`` is the badge number.

        Negative counts are clamped to 0 so callers can pass
        ``len(model.entries)`` without first checking for emptiness.
        """

        if not panel:
            return self._state
        counts = dict(self._state.panel_seen_counts)
        counts[panel] = max(0, int(count))
        self._state = replace(self._state, panel_seen_counts=counts)
        return self._state

    def get_seen_count(self, panel: str) -> int:
        return int(self._state.panel_seen_counts.get(panel, 0))

    def set_active_panel(self, panel: str) -> TUIState:
        if not panel:
            return self._state
        if panel == self._state.active_panel:
            return self._state
        self._state = replace(self._state, active_panel=panel)
        return self._state

    def set_theme(self, theme: str) -> TUIState:
        """Persist the operator's chosen Textual theme id.

        Empty / whitespace-only input clears the override so the next
        TUI start falls back to the built-in default. We accept any
        opaque string here; theme-validity is enforced at apply time
        in ``app.py`` so the state file stays forward-compatible with
        future Textual releases that ship new themes.
        """

        cleaned = (theme or "").strip()
        if cleaned == self._state.theme:
            return self._state
        self._state = replace(self._state, theme=cleaned)
        return self._state

    def get_theme(self) -> str:
        return self._state.theme

    def set_panel_filter(self, panel: str, filter_value: str) -> TUIState:
        if not panel:
            return self._state
        filters = dict(self._state.panel_filters)
        if filter_value:
            filters[panel] = filter_value
        else:
            filters.pop(panel, None)
        self._state = replace(self._state, panel_filters=filters)
        return self._state

    def get_panel_filter(self, panel: str) -> str:
        return self._state.panel_filters.get(panel, "")

    def get_last_seen(self, panel: str) -> datetime | None:
        raw = self._state.panel_last_seen.get(panel, "")
        if not raw:
            return None
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None

    def _quarantine_corrupt(self, raw: str) -> None:
        """Best-effort rename of a corrupt state file out of the way."""

        if self._path is None:
            return
        try:
            backup = self._path.with_suffix(self._path.suffix + ".bak")
            atomic_write_private_bytes(backup, raw.encode("utf-8"))
            self._path.unlink()
        except OSError:
            pass
