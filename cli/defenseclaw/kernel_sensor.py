# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Words for the kernel sensor (Tetragon) that every Python surface shares.

The doctor row, ``agent discovery runtime status`` and the TUI Runtime panel
all describe the same facts: which kernel sensor runs, what the kernel controls
do and what the customer's own Tetragon policies reported. They take the
``backend`` object the gateway puts on plane C (``/api/v1/ai-usage/runtime``)
and return plain text, so the three surfaces cannot drift apart. No I/O.

Glossary (SPEC-TETRAGON-UX 5.1): "kernel sensor" is Tetragon as plane C's
source, "kernel controls" are DefenseClaw's two controls, "your policies" are
the customer's own Tetragon policies. JSON keys such as ``kernel_floor`` keep
their spelling; only the human text changes.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

#: Where the managed Linux packages put the gateway binary. It is not on PATH
#: and ``sudo`` resets PATH, so every command printed for a root user carries
#: the full path.
ADMIN_BIN_DIR = "/opt/defenseclaw/bin"

_FALLBACK_TEXT = {
    "tetragon_unavailable": "Tetragon is not running or its info file is missing",
    "tetragon_tcp_api": "its API listens on TCP instead of a local socket",
    "tetragon_untrusted_endpoint": "its socket or info file is not owned by root",
    "tetragon_unsupported_version": "this Tetragon version is not supported",
}

_MAX_FALLBACK = 80


def admin_command(*args: str, binary: str = "defenseclaw-gateway") -> str:
    """A command line for a root user, e.g. ``sudo /opt/defenseclaw/bin/defenseclaw-gateway ...``."""

    return " ".join(("sudo", f"{ADMIN_BIN_DIR}/{binary}", *args))


def _int(value: object) -> int:
    try:
        return int(value or 0)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return 0


def _users(count: int) -> str:
    return f"{count} user" if count == 1 else f"{count} users"


def _clip(text: str, limit: int = _MAX_FALLBACK) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def fallback_text(reason: str) -> str:
    """Why the native backend runs although Tetragon is wanted, without the raw reason code."""

    code, _, detail = str(reason or "").partition(":")
    code = code.strip()
    known = _FALLBACK_TEXT.get(code)
    if known:
        return known
    return _clip(detail.strip() or code.replace("_", " ") or "no reason reported")


def _eta(hours: object) -> str:
    """``~9 days`` or ``~5 hours`` for a number of hours; empty when unknown."""

    try:
        value = float(hours)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return ""
    if value <= 0:
        return ""
    if value < 1:
        return "~1 hour"
    if value < 48:
        count = round(value)
        return f"~{count} hour" if count == 1 else f"~{count} hours"
    days = round(value / 24)
    return f"~{days} days"


def kernel_sensor_summary(backend: Mapping[str, Any] | None) -> str:
    """``Tetragon v1.7.1, enforce, 0 events lost``; the fallback sentence when Tetragon is not used.

    Empty without a backend, so a gateway that reports none renders nothing.
    """

    if not isinstance(backend, Mapping) or not backend:
        return ""
    kind = str(backend.get("kind") or "").strip().lower()
    if kind == "tetragon":
        version = str(backend.get("version") or "").strip()
        if version[:1].isdigit():
            version = "v" + version
        mode = str(backend.get("mode") or "").strip().lower()
        if backend.get("loss_known") is not False and "events_lost" in backend:
            loss = f"{_int(backend.get('events_lost'))} events lost"
        else:
            # A count the helper cannot vouch for would read as a clean stream.
            loss = "events lost unknown"
        return ", ".join(part for part in (f"Tetragon {version}".strip(), mode, loss) if part)
    reason = str(backend.get("fallback_reason") or "").strip()
    if reason:
        return f"cn_proc and fanotify (Tetragon not used: {fallback_text(reason)})"
    return ""


def kernel_controls_line(floor: Mapping[str, Any] | None) -> str:
    """``enforcing 2 of 3 users; 1 in burn-in, next ready ~9 days`` for the kernel controls.

    ``floor`` is ``backend.kernel_floor``. Empty when the helper reports none.
    """

    if not isinstance(floor, Mapping) or not floor:
        return ""
    mode = str(floor.get("mode") or "").strip().lower() or "monitor"
    enrolled = _int(floor.get("enrolled_users"))
    if mode != "enforce":
        return f"monitoring {_users(enrolled)}, not enforcing"
    approval = str(floor.get("approval") or "").strip().lower()
    if approval == "missing":
        return f"monitoring {_users(enrolled)}; enforce is not approved yet"
    if approval == "stale":
        return f"monitoring {_users(enrolled)}; the approval is for another build"
    text = f"enforcing {_int(floor.get('enforced_users'))} of {_users(enrolled)}"
    burning = _int(floor.get("burn_in_users"))
    if burning:
        text += f"; {burning} in burn-in"
        eta = _eta(floor.get("next_ready_hours"))
        if eta:
            text += f", next ready {eta}"
    return text


def your_policies_line(backend: Mapping[str, Any] | None) -> str:
    """``your policies: 12 agent events``; empty when no policy of the customer's is reported."""

    if not isinstance(backend, Mapping):
        return ""
    events = backend.get("customer_events")
    policies = backend.get("customer_policies")
    loaded = len(policies) if isinstance(policies, list) else 0
    if not isinstance(events, Mapping):
        return "your policies: no agent events" if loaded else ""
    forwarded = _int(events.get("forwarded"))
    if forwarded:
        noun = "agent event" if forwarded == 1 else "agent events"
        return f"your policies: {forwarded} {noun}"
    return "your policies: no agent events" if loaded or events else ""


def helper_command(*args: str) -> str:
    """A sensor helper command for a root user: ``sudo /opt/defenseclaw/bin/defenseclaw-sensor-helper ...``."""

    return admin_command(*args, binary="defenseclaw-sensor-helper")


#: The restart every Tetragon change needs, with what it costs: a restart
#: drops the policies added with ``tetra`` (``tetragon.tp.d`` policies reload).
TETRAGON_RESTART = (
    "`sudo systemctl restart tetragon` (this drops policies added with tetra; tetragon.tp.d policies reload)"
)


def tetragon_setting(flag: str, value: str) -> str:
    """The command that sets one Tetragon flag: one file per flag, named for it."""

    return f"echo {value} | sudo tee /etc/tetragon/tetragon.conf.d/{flag}"


def paused_suffix(floor: Mapping[str, Any] | None) -> str:
    """``; paused until 2026-10-07T14:05:00Z`` when the kernel controls are paused."""

    if not isinstance(floor, Mapping):
        return ""
    paused = str(floor.get("paused_until") or "").strip()
    return f"; paused until {paused}" if paused else ""


def your_policies_summary(backend: Mapping[str, Any] | None) -> str:
    """``2 loaded (1 enforcing); 12 agent events forwarded``: the CLI and doctor form of
    :func:`your_policies_line`, in the words of ``enterprise linux discovery``.

    Empty when the helper reports none of the customer's own policies.
    """

    if not isinstance(backend, Mapping):
        return ""
    policies = backend.get("customer_policies")
    events = backend.get("customer_events")
    rows = [item for item in policies if isinstance(item, Mapping)] if isinstance(policies, list) else []
    if not rows and not isinstance(events, Mapping):
        return ""
    enforcing = sum(1 for item in rows if str(item.get("mode") or "").strip().lower() == "enforce")
    text = f"{len(rows)} loaded ({enforcing} enforcing)"
    if isinstance(events, Mapping):
        forwarded = _int(events.get("forwarded"))
        text += f"; {forwarded} agent {'event' if forwarded == 1 else 'events'} forwarded"
        dropped = _int(events.get("dropped"))
        if dropped:
            text += f", {dropped} over the budget"
    return text
