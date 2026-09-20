# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Activity panel model for command history and gateway mutations."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from defenseclaw.tui.services.event_models import ActivityMutation, timestamp_label
from defenseclaw.tui.services.v8_event_history import (
    V8EventHistoryRow,
    load_v8_event_history,
    payload_text,
)

ActivityTab = Literal["commands", "mutations"]


def activity_mutations_from_v8_history(
    rows: tuple[V8EventHistoryRow, ...],
) -> tuple[ActivityMutation, ...]:
    """Project Activity mutations without touching SQLite."""

    return tuple(
        ActivityMutation(
            actor=payload_text(row.payload, "defenseclaw.operator.id", "enduser.id")
            or row.actor
            or row.source,
            action=row.action or row.event_name,
            target_type=row.bucket,
            target_id=payload_text(
                row.payload,
                "defenseclaw.config.path",
                "defenseclaw.policy.id",
                "defenseclaw.approval.id",
                "defenseclaw.enforcement.id",
                "defenseclaw.finding.target_ref",
            )
            or row.event_name,
            version_from=payload_text(
                row.payload,
                "defenseclaw.config.generation.previous",
                "defenseclaw.policy.version.previous",
            ),
            version_to=payload_text(
                row.payload,
                "defenseclaw.config.generation",
                "defenseclaw.policy.version",
            ),
            reason=payload_text(
                row.payload,
                "defenseclaw.guardrail.reason",
                "defenseclaw.enforcement.failure_class",
                "defenseclaw.error.summary",
            )
            or row.details,
            timestamp=row.timestamp,
        )
        for row in rows
        if row.bucket in {"compliance.activity", "enforcement.action"}
    )


@dataclass
class ActivityEntry:
    """One command execution entry.

    The ``masked_argv`` / ``config_reloaded`` / ``restart_completed``
    / ``doctor_cache_refreshed`` / ``suggested_next_action`` fields
    mirror the Go TUI's ``CommandResultMeta`` (see
    ``internal/tui/command_intent.go``). They feed the activity meta
    footer so operators can see at a glance whether a command actually
    changed gateway state, refreshed the doctor cache, or what they
    should try next — without having to scroll through raw output.
    """

    command: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    output: list[str] = field(default_factory=list)
    exit_code: int | None = None
    duration: timedelta = timedelta()
    done: bool = False
    expanded: bool = True
    cancelled: bool = False
    masked_argv: tuple[str, ...] = ()
    config_reloaded: bool = False
    restart_completed: bool = False
    doctor_cache_refreshed: bool = False
    suggested_next_action: str = ""

    @property
    def status_label(self) -> str:
        if not self.done:
            return "running"
        if self.cancelled:
            return f"cancelled ({self.duration})"
        if self.exit_code == 0:
            return f"exit 0 ({self.duration})"
        return f"exit {self.exit_code} ({self.duration})"

    @property
    def meta_footer(self) -> str:
        """Render the structured-meta line for the activity panel.

        Returns an empty string when no meta is set so callers can
        skip the footer rather than render an empty parenthetical.
        Order is deterministic so screenshot/snapshot tests are
        stable: side-effects first (state changes), then the next
        action hint at the end where eyes land last.
        """

        parts: list[str] = []
        if self.config_reloaded:
            parts.append("config reloaded")
        if self.restart_completed:
            parts.append("gateway restarted")
        if self.doctor_cache_refreshed:
            parts.append("doctor cache refreshed")
        if self.suggested_next_action:
            parts.append(f"next: {self.suggested_next_action}")
        return " · ".join(parts)


class ActivityPanelModel:
    """Pure activity panel state used by Textual widgets and tests."""

    def __init__(
        self,
        data_dir: Path | None = None,
        *,
        store: object | None = None,
    ) -> None:
        self.data_dir = data_dir
        self.store = store
        self.tab: ActivityTab = "commands"
        self.entries: list[ActivityEntry] = []
        self.cursor = 0
        self.term_mode = False
        self.term_scroll = 0
        self.mutations: list[ActivityMutation] = []
        self.mutation_cursor = 0
        self.diff_open: set[int] = set()

    def set_data_dir(self, data_dir: str | Path | None) -> None:
        """Late-bind the data dir so the app can wire it from config."""

        self.data_dir = Path(data_dir) if data_dir else None

    def set_store(self, store: object | None) -> None:
        self.store = store

    @property
    def count(self) -> int:
        return len(self.entries)

    @property
    def last_command(self) -> str:
        return self.entries[-1].command if self.entries else ""

    @property
    def is_running(self) -> bool:
        return bool(self.entries and not self.entries[-1].done)

    def set_tab(self, tab: ActivityTab) -> None:
        self.tab = tab

    def add_entry(
        self,
        command: str,
        *,
        started_at: datetime | None = None,
        masked_argv: tuple[str, ...] | None = None,
    ) -> None:
        self.entries.append(
            ActivityEntry(
                command=command,
                started_at=started_at or datetime.now(timezone.utc),
                masked_argv=tuple(masked_argv) if masked_argv else (),
            )
        )
        self.cursor = len(self.entries) - 1
        self.term_mode = True
        self.term_scroll = 0

    def append_output(self, line: str) -> None:
        if not self.entries:
            return
        self.entries[-1].output.append(line)

    def finish_entry(
        self,
        exit_code: int,
        duration: timedelta = timedelta(),
        *,
        cancelled: bool = False,
        config_reloaded: bool = False,
        restart_completed: bool = False,
        doctor_cache_refreshed: bool = False,
        suggested_next_action: str = "",
    ) -> None:
        if not self.entries:
            return
        entry = self.entries[-1]
        entry.done = True
        entry.exit_code = exit_code
        entry.duration = duration
        entry.cancelled = cancelled
        # Side-effect flags mirror Go's CommandResultMeta — only flip
        # when the caller positively observed the side effect (e.g.
        # gateway started_at advanced) so a quiet success doesn't
        # over-claim "config reloaded".
        entry.config_reloaded = bool(config_reloaded)
        entry.restart_completed = bool(restart_completed)
        entry.doctor_cache_refreshed = bool(doctor_cache_refreshed)
        entry.suggested_next_action = suggested_next_action or ""

    def select_entry(self, index: int) -> None:
        if not self.entries:
            self.cursor = 0
            return
        self.cursor = max(0, min(index, len(self.entries) - 1))

    def clear_history(self) -> int:
        """Drop completed Activity entries and reset cursors.

        Returns the number of entries removed so callers can surface a
        confirmation message. A running entry (last entry, not yet
        ``done``) is preserved so clicking Clear during a live command
        doesn't orphan the executor's output stream — the user almost
        always wants Clear to mean "wipe history", not "abort what's
        running".
        """

        if not self.entries:
            return 0
        keep_running = self.entries[-1] if not self.entries[-1].done else None
        removed = len(self.entries) - (1 if keep_running else 0)
        self.entries = [keep_running] if keep_running else []
        self.cursor = 0
        self.term_scroll = 0
        return removed

    def scroll_by(self, delta: int) -> None:
        if self.term_mode:
            self.term_scroll = max(0, self.term_scroll - delta)
            if 0 <= self.cursor < len(self.entries):
                self.term_scroll = min(self.term_scroll, len(self.entries[self.cursor].output))
            return
        self.select_entry(self.cursor + delta)

    def handle_key(self, key: str) -> None:
        if key == "1":
            self.set_tab("commands")
            return
        if key == "2":
            self.set_tab("mutations")
            return
        if self.tab == "mutations":
            self._handle_mutation_key(key)
            return
        if self.term_mode:
            self._handle_terminal_key(key)
            return
        if key in {"up", "k"}:
            self.select_entry(self.cursor - 1)
        elif key in {"down", "j"}:
            self.select_entry(self.cursor + 1)
        elif key == "enter" and self.entries:
            self.term_mode = True
            self.term_scroll = 0
        elif key == "t" and self.entries:
            self.cursor = len(self.entries) - 1
            self.term_mode = True
            self.term_scroll = 0

    def _handle_terminal_key(self, key: str) -> None:
        if key in {"esc", "q"}:
            self.term_mode = False
        elif key in {"up", "k"}:
            self.term_scroll += 1
        elif key in {"down", "j"}:
            self.term_scroll = max(0, self.term_scroll - 1)

    def _handle_mutation_key(self, key: str) -> None:
        if key in {"up", "k"}:
            self.mutation_cursor = max(0, self.mutation_cursor - 1)
        elif key in {"down", "j"}:
            self.mutation_cursor = min(max(len(self.mutations) - 1, 0), self.mutation_cursor + 1)
        elif key == "enter" and 0 <= self.mutation_cursor < len(self.mutations):
            if self.mutation_cursor in self.diff_open:
                self.diff_open.remove(self.mutation_cursor)
            else:
                self.diff_open.add(self.mutation_cursor)

    def load_mutations(self) -> None:
        rows = load_v8_event_history(self.store, limit=500)
        self.apply_v8_history(rows)

    def apply_v8_history(self, rows: tuple[V8EventHistoryRow, ...]) -> None:
        """Apply mutations projected from a shared canonical snapshot."""

        self.apply_mutations(activity_mutations_from_v8_history(rows))

    def apply_mutations(self, mutations: tuple[ActivityMutation, ...]) -> None:
        """Apply pre-projected mutations without database or JSON work."""

        self.mutations = list(mutations)
        if self.mutation_cursor >= len(self.mutations):
            self.mutation_cursor = max(len(self.mutations) - 1, 0)

    def render_text(self, *, height: int = 24) -> str:
        tab_bar = "  [1] Commands   [2] Mutations (gateway activity)\n\n"
        if self.tab == "mutations":
            return tab_bar + self._render_mutations(height=height)
        if not self.entries:
            return tab_bar + "  No commands run yet.\n  Next: press : and run doctor, readiness, or keys check."
        if self.term_mode:
            return tab_bar + self._render_terminal(height=height)
        return tab_bar + self._render_history(height=height)

    def _render_terminal(self, *, height: int) -> str:
        if self.cursor < 0 or self.cursor >= len(self.entries):
            self.cursor = len(self.entries) - 1
        entry = self.entries[self.cursor]
        lines = [f"$ {entry.command}  {entry.status_label}", "-" * 40]
        visible = max(height - 6, 5)
        end = len(entry.output) - self.term_scroll
        end = max(0, min(end, len(entry.output)))
        start = max(0, end - visible)
        lines.extend(entry.output[start:end])
        lines.append("  [Esc] history  [Up/Down] scroll  [Ctrl+C] cancel")
        return "\n".join(lines)

    def _render_history(self, *, height: int) -> str:
        # Escape the ``[t]`` hotkey: Rich parses single lowercase
        # letters as opening style tags and silently drops the
        # bracketed text. ``[Enter]`` is uppercase-led so Rich already
        # treats it as literal — escaping it is harmless either way.
        lines = ["  Command History  \\[Enter] view output  \\[t] terminal mode", ""]
        for index, entry in enumerate(self.entries):
            prefix = "->" if index == self.cursor else "  "
            lines.append(f"{prefix} {entry.command}  {entry.status_label} ({len(entry.output)} lines)")
            if entry.expanded:
                lines.extend(f"    {line}" for line in entry.output[:5])
                if len(entry.output) > 5:
                    lines.append(f"    ... {len(entry.output) - 5} more lines (Enter to view)")
            lines.append("")
        return "\n".join(lines[: max(height, 5)])

    def _render_mutations(self, *, height: int) -> str:
        if not self.mutations:
            return "  No activity events in canonical SQLite event history yet."
        lines: list[str] = []
        max_rows = max(height - 6, 5)
        start = max(0, self.mutation_cursor - max_rows + 1)
        for index, mutation in enumerate(self.mutations[start : start + max_rows], start=start):
            prefix = "▸ " if index == self.mutation_cursor else "  "
            from_version = mutation.version_from or "∅"
            to_version = mutation.version_to or "∅"
            reason = f" -- {mutation.reason[:40]}" if mutation.reason else ""
            lines.append(
                f"{prefix}{timestamp_label(mutation.timestamp)}  {mutation.actor}  {mutation.action}  "
                f"{mutation.target_label}  {from_version} -> {to_version}{reason}"
            )
            if index in self.diff_open:
                if mutation.diff:
                    lines.extend(f"      {item.get('op', '')} {item.get('path', '')}" for item in mutation.diff)
                else:
                    lines.append("      (no structured diff)")
        lines.append("\n  [Enter] expand diff")
        return "\n".join(lines)
