# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Toast notifications for the Textual TUI.

Mirrors :mod:`internal/tui/toast.go` so success/warn/error feedback
matches the Go TUI exactly. Toasts are auto-dismissing, capped at
``MAX_TOASTS=3`` to keep the chrome quiet, and use ASCII glyphs
(``OK``/``!!``/``ERR``/``--``) so they remain readable on monochrome
terminals (codeguard-0: do not rely on colour for safety signals).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from time import monotonic
from typing import Literal

from textual.containers import Vertical
from textual.widgets import Static

ToastLevel = Literal["info", "success", "warn", "error"]

MAX_TOASTS = 3

TTL_INFO = 4.0
TTL_SUCCESS = 4.0
TTL_WARN = 6.0
TTL_ERROR = 8.0

_GLYPHS: dict[str, str] = {
    "info": "--",
    "success": "OK",
    "warn": "!!",
    "error": "ERR",
}

_TTLS: dict[str, float] = {
    "info": TTL_INFO,
    "success": TTL_SUCCESS,
    "warn": TTL_WARN,
    "error": TTL_ERROR,
}


@dataclass(frozen=True)
class Toast:
    """Single auto-dismissing notification."""

    level: ToastLevel
    message: str
    expires_at: float

    @property
    def glyph(self) -> str:
        return _GLYPHS.get(self.level, "--")


@dataclass
class ToastManager:
    """Pure logic for queueing and pruning toasts.

    Kept separate from the Textual widget so the same code can be
    unit-tested without spinning up a TUI app.
    """

    items: list[Toast] = field(default_factory=list)

    def push(self, level: ToastLevel, message: str, *, now: float | None = None) -> Toast:
        """Add a new toast. Returns the newly created entry."""

        ttl = _TTLS.get(level, TTL_INFO)
        when = monotonic() if now is None else now
        toast = Toast(level=level, message=message, expires_at=when + ttl)
        self.items.append(toast)
        if len(self.items) > MAX_TOASTS:
            self.items = self.items[-MAX_TOASTS:]
        return toast

    def tick(self, now: float | None = None) -> bool:
        """Prune expired toasts. Returns True when anything changed."""

        when = monotonic() if now is None else now
        before = len(self.items)
        self.items = [t for t in self.items if t.expires_at > when]
        return len(self.items) != before

    def clear(self) -> None:
        self.items = []

    def has_items(self) -> bool:
        return bool(self.items)


def _toast_class(level: ToastLevel) -> str:
    return f"toast toast-{level}"


class ToastStack(Vertical):
    """Vertical stack of 1-line toast bars rendered above the hint bar."""

    DEFAULT_CSS = """
    ToastStack {
        height: auto;
        max-height: 4;
        layout: vertical;
        padding: 0 1;
        background: transparent;
    }

    ToastStack.hidden {
        display: none;
    }

    ToastStack Static.toast {
        height: 1;
        padding: 0 1;
        margin: 0 0 1 0;
        background: #1F2937;
        color: #E5E7EB;
        text-style: bold;
    }

    ToastStack Static.toast-info {
        background: #1E3A8A;
        color: #BFDBFE;
    }

    ToastStack Static.toast-success {
        background: #065F46;
        color: #BBF7D0;
    }

    ToastStack Static.toast-warn {
        background: #78350F;
        color: #FDE68A;
    }

    ToastStack Static.toast-error {
        background: #7F1D1D;
        color: #FECACA;
    }
    """

    def __init__(self, *, id: str | None = None) -> None:  # noqa: A002 - Textual API
        super().__init__(id=id)
        self.add_class("hidden")

    def render_items(self, items: list[Toast]) -> None:
        """Re-mount the stack with the given toasts.

        The toast count is small (cap 3) so rebuilding the children is
        cheap and avoids the bookkeeping cost of diffing.
        """

        self.remove_children()
        if not items:
            self.add_class("hidden")
            return
        self.remove_class("hidden")
        for toast in items:
            label = f"{toast.glyph}  {toast.message}"
            widget = Static(label, classes=_toast_class(toast.level), markup=False)
            self.mount(widget)


__all__ = [
    "MAX_TOASTS",
    "TTL_ERROR",
    "TTL_INFO",
    "TTL_SUCCESS",
    "TTL_WARN",
    "Toast",
    "ToastLevel",
    "ToastManager",
    "ToastStack",
]
