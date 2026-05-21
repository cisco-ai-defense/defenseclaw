# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""SQLite judge response history modal for the Logs panel."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime

from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Static

from defenseclaw.tui.theme import DEFAULT_TOKENS

TOKENS = DEFAULT_TOKENS


class JudgeHistoryScreen(ModalScreen[None]):
    """Rounded detail modal containing recent retained LLM judge rows."""

    CSS = f"""
    JudgeHistoryScreen {{
        align: center middle;
    }}

    #judge-history-dialog {{
        width: 120;
        height: 32;
        padding: 1 2;
        border: round {TOKENS.border_active};
        background: {TOKENS.surface_panel};
        color: {TOKENS.text_primary};
    }}

    #judge-history-title {{
        height: 1;
        margin-bottom: 1;
        color: {TOKENS.accent_cyan};
        text-style: bold;
    }}

    #judge-history-body {{
        height: 26;
        overflow-y: auto;
        color: {TOKENS.text_secondary};
    }}

    #judge-history-footer {{
        height: 1;
        color: {TOKENS.text_muted};
    }}
    """

    BINDINGS = [
        Binding("escape,q,enter", "close", "Close", show=False),
    ]

    def __init__(self, rows: Sequence[object] = (), *, error: str = "") -> None:
        super().__init__()
        self.rows = tuple(rows)
        self.error = error

    def compose(self) -> ComposeResult:
        title = "Judge Responses"
        if self.rows:
            title = f"Judge Responses - last {len(self.rows)}"
        elif self.error:
            title = "Judge Responses - error"
        with Vertical(id="judge-history-dialog"):
            yield Static(title, id="judge-history-title")
            yield Static(self._body(), id="judge-history-body", markup=True)
            yield Static("[Enter] close  [Esc] close", id="judge-history-footer")

    def action_close(self) -> None:
        self.dismiss(None)

    def on_click(self, event: events.Click) -> None:
        if event.widget is self:
            event.stop()
            self.dismiss(None)

    def _body(self) -> str:
        if self.error:
            return f"[{TOKENS.accent_red}]Error[/]\n{self.error}"
        if not self.rows:
            return (
                "No judge responses persisted yet.\n"
                "Ensure guardrail.retain_judge_bodies is on and traffic has been inspected."
            )
        return "\n".join(_format_pair(key, value) for key, value in judge_response_detail_pairs(self.rows))


def judge_response_detail_pairs(rows: Sequence[object]) -> tuple[tuple[str, str], ...]:
    """Return Go-compatible label/value pairs for retained judge responses."""

    pairs: list[tuple[str, str]] = []
    for index, row in enumerate(rows, start=1):
        if index > 1:
            pairs.append(("", ""))
        prefix = f"[{index}] "
        pairs.extend(
            (
                (prefix + "Timestamp", _timestamp(_value(row, "timestamp"))),
                (prefix + "Kind", _string_value(row, "kind")),
                (prefix + "Direction", _string_value(row, "direction")),
                (prefix + "Action", _string_value(row, "action")),
                (prefix + "Severity", _string_value(row, "severity")),
                (prefix + "Latency (ms)", _string_value(row, "latency_ms")),
            )
        )
        _append_optional(pairs, prefix + "Inspected model", _string_value(row, "inspected_model"))
        _append_optional(pairs, prefix + "Judge model", _string_value(row, "model"))
        _append_optional(pairs, prefix + "Request ID", _string_value(row, "request_id"))
        _append_optional(pairs, prefix + "Trace ID", _string_value(row, "trace_id"))
        _append_optional(pairs, prefix + "Run ID", _string_value(row, "run_id"))
        _append_optional(pairs, prefix + "Input hash", _string_value(row, "input_hash"))
        confidence = _value(row, "confidence")
        if confidence not in {"", None, 0, 0.0}:
            try:
                pairs.append((prefix + "Confidence", f"{float(confidence):.3f}"))
            except (TypeError, ValueError):
                pairs.append((prefix + "Confidence", str(confidence)))
        fail_closed = bool(_value(row, "fail_closed_applied", False))
        if fail_closed:
            pairs.append((prefix + "Fail-closed", "yes"))
        _append_optional(pairs, prefix + "Prompt template", _string_value(row, "prompt_template_id"))
        _append_optional(pairs, prefix + "Parse error", _string_value(row, "parse_error"))
        pairs.append((prefix + "Raw (redacted)", _string_value(row, "raw")))
    return tuple(pairs)


def _append_optional(pairs: list[tuple[str, str]], key: str, value: str) -> None:
    if value:
        pairs.append((key, value))


def _format_pair(key: str, value: str) -> str:
    if not key and not value:
        return ""
    return f"[{TOKENS.accent_violet}]{key}[/]: {value}"


def _value(row: object, key: str, default: object = "") -> object:
    if isinstance(row, Mapping):
        return row.get(key, default)
    return getattr(row, key, default)


def _string_value(row: object, key: str) -> str:
    value = _value(row, key, "")
    return "" if value is None else str(value)


def _timestamp(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return "" if value is None else str(value)
