# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Pure parsing of ``defenseclaw substrate list --json`` for the Sandboxes panel.

The panel lists the coding agents the launcher started in an Agent Substrate
cluster next to the OpenShell sandboxes. The app runs the command in the
background and hands its exit status and output to :func:`parse_substrate_list`,
which never raises: a signed-out launcher, an unreachable cluster or an answer
it cannot read becomes one dim line (``SubstrateList.note``), not an error.
No I/O happens here.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from defenseclaw.tui.services.sandbox_state import RUNTIME_OPENSHELL, RUNTIME_SUBSTRATE, _safe, format_duration

# The command the app runs (through the TUI's captured-command service).
SUBSTRATE_LIST_ARGS: tuple[str, ...] = ("substrate", "list", "--json")
# The longest the panel waits between two runs of it.
SUBSTRATE_REFRESH_SECONDS = 15.0
# The most agents the table shows; the rest read as "+N more".
SUBSTRATE_MAX_ROWS = 50
# Palette commands that ask questions or take the whole screen (sign-in, a new
# agent, connect, pull): they run on the user's terminal, not in the Activity log.
SUBSTRATE_TERMINAL_VERBS = frozenset({"login", "run", "connect", "pull"})
# The launcher's exit status for "not signed in" (also: no cluster configured).
SUBSTRATE_EXIT_SIGNED_OUT = 4

__all__ = [
    "RUNTIME_OPENSHELL",
    "RUNTIME_SUBSTRATE",
    "SIGNED_OUT_NOTE",
    "SUBSTRATE_EXIT_SIGNED_OUT",
    "SUBSTRATE_LIST_ARGS",
    "SUBSTRATE_MAX_ROWS",
    "SUBSTRATE_REFRESH_SECONDS",
    "SubstrateList",
    "SubstrateRow",
    "parse_substrate_list",
    "substrate_needs_terminal",
]

SIGNED_OUT_NOTE = "Agent Substrate: not signed in. Run: defenseclaw substrate login"
_NOTE_PREFIX = "Agent Substrate: "
_NOTE_LIMIT = 100
# A cluster name the launcher accepts as an argument: DNS-label shaped, never
# something a command line could read as a flag.
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def substrate_needs_terminal(args: tuple[str, ...]) -> bool:
    """Whether ``defenseclaw <args>`` is an interactive substrate command."""
    return len(args) >= 2 and args[0] == "substrate" and args[1] in SUBSTRATE_TERMINAL_VERBS


@dataclass(frozen=True)
class SubstrateRow:
    """One agent as ``substrate list --json`` describes it."""

    atespace: str
    name: str
    # What the launcher is given to name the agent: the plain name unless
    # another agent shares it (then ``atespace/name``).
    ref: str
    state: str = ""
    profile: str = ""
    connector: str = ""
    template: str = ""
    batch_id: str = ""
    unattended: bool = False
    created_at: datetime | None = None

    def age_text(self, now: datetime | None = None) -> str:
        if self.created_at is None:
            return "-"
        seconds = int(((now or datetime.now(timezone.utc)) - self.created_at).total_seconds())
        return format_duration(seconds)

    def detail_line(self, now: datetime | None = None) -> str:
        """One line for Enter on the row: what the agent is and how to reach it."""
        parts = [
            self.ref,
            self.connector or "agent",
            self.state or "unknown state",
            f"profile {self.profile}" if self.profile else "",
            f"up {self.age_text(now)}" if self.created_at else "",
            "unattended" if self.unattended else "",
        ]
        return " · ".join(part for part in parts if part)


@dataclass(frozen=True)
class SubstrateList:
    """The result of one run: the rows shown, how many more there are, or why none."""

    rows: tuple[SubstrateRow, ...] = ()
    more: int = 0
    # The dim line that stands in for the rows ("" when the list was read).
    note: str = ""

    @property
    def line(self) -> str:
        """The panel's dim line: the reason there are no rows, or the "+N more" tail."""
        if self.note:
            return self.note
        if self.more:
            return f"{_NOTE_PREFIX}+{self.more} more (all of them: defenseclaw substrate list)"
        return ""


def _note(reason: str) -> SubstrateList:
    text = " ".join(_safe(reason).split())
    if len(text) > _NOTE_LIMIT:
        text = text[: _NOTE_LIMIT - 1].rstrip() + "…"
    return SubstrateList(note=_NOTE_PREFIX + text)


def _created(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text or text.startswith("0001-01-01"):
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _failure_reason(returncode: int, stderr: str) -> str:
    lines = [line.strip() for line in _safe(stderr).splitlines() if line.strip()]
    if lines:
        return lines[-1]
    return f"the launcher exited {returncode}"


def parse_substrate_list(
    returncode: int, stdout: str | bytes, stderr: str | bytes = "", *, limit: int = SUBSTRATE_MAX_ROWS
) -> SubstrateList:
    """Turn one run of ``substrate list --json`` into rows or one dim line.

    * exit 4 (not signed in, or no cluster configured): the sign-in line;
    * another non-zero exit: its last line of stderr as the reason;
    * exit 0 with output that is not ``{"actors": [...]}``: an "unreadable" line;
    * exit 0 with no agents: no rows and no note;
    * more than ``limit`` agents: the first ``limit`` and ``more`` for the rest.
    """
    out = stdout.decode("utf-8", "replace") if isinstance(stdout, bytes) else stdout
    err = stderr.decode("utf-8", "replace") if isinstance(stderr, bytes) else stderr
    if returncode == SUBSTRATE_EXIT_SIGNED_OUT:
        return SubstrateList(note=SIGNED_OUT_NOTE)
    if returncode != 0:
        return _note(_failure_reason(returncode, err))
    try:
        payload = json.loads(out)
    except ValueError:
        return _note("the list could not be read; update DefenseClaw and try again")
    actors = payload.get("actors") if isinstance(payload, dict) else None
    if actors is None and isinstance(payload, dict):
        actors = []
    if not isinstance(actors, list):
        return _note("the list could not be read; update DefenseClaw and try again")
    seen: dict[str, int] = {}
    decoded: list[dict[str, Any]] = []
    for raw in actors:
        if not isinstance(raw, dict) or raw.get("deleted"):
            continue
        name = str(raw.get("name") or "")
        atespace = str(raw.get("atespace") or "")
        if not _NAME.match(name) or (atespace and not _NAME.match(atespace)):
            continue
        decoded.append(raw)
        seen[name] = seen.get(name, 0) + 1
    decoded.sort(key=lambda raw: (str(raw.get("name") or ""), str(raw.get("atespace") or "")))
    rows = tuple(
        SubstrateRow(
            atespace=str(raw.get("atespace") or ""),
            name=str(raw["name"]),
            ref=(
                f"{raw['atespace']}/{raw['name']}"
                if raw.get("atespace") and seen[str(raw["name"])] > 1
                else str(raw["name"])
            ),
            state=_safe(raw.get("state"), 24),
            profile=_safe(raw.get("profile"), 40),
            connector=_safe(raw.get("connector"), 24),
            template=_safe(raw.get("template"), 60),
            batch_id=_safe(raw.get("batch_id"), 40),
            unattended=raw.get("unattended") is True,
            created_at=_created(raw.get("created_at")),
        )
        for raw in decoded
    )
    if limit > 0 and len(rows) > limit:
        return SubstrateList(rows=rows[:limit], more=len(rows) - limit)
    return SubstrateList(rows=rows)
