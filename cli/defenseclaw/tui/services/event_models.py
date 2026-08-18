# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Canonical event-history view models shared by the Python TUI.

The TUI populates these models from the v8 SQLite event history.  Keeping the
models independent of any storage format prevents a retired JSONL side channel
from becoming an accidental second runtime event source.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class ActivityMutation:
    """Operator/configuration mutation projected from canonical event history."""

    actor: str = ""
    action: str = ""
    target_type: str = ""
    target_id: str = ""
    version_from: str = ""
    version_to: str = ""
    reason: str = ""
    diff: tuple[dict[str, Any], ...] = ()
    timestamp: datetime | None = None

    @property
    def target_label(self) -> str:
        if self.target_type:
            return f"{self.target_type}:{self.target_id}"
        return self.target_id


@dataclass(frozen=True)
class ScanBlock:
    """Canonical asset-scan roll-up with child findings."""

    scan_id: str
    scanner: str = ""
    target: str = ""
    severity: str = "INFO"
    verdict: str = ""
    duration_ms: int = 0
    total_count: int = 0
    counts: dict[str, int] = field(default_factory=dict)
    timestamp: datetime | None = None
    findings: tuple[dict[str, Any], ...] = ()


@dataclass(frozen=True)
class EgressEvent:
    """Canonical network-egress event used by alert and posture views."""

    timestamp: datetime | None = None
    target_host: str = ""
    target_path: str = ""
    body_shape: str = ""
    looks_like_llm: bool = False
    branch: str = ""
    decision: str = ""
    reason: str = ""
    source: str = ""


def count_recent_silent_bypass(
    events: tuple[EgressEvent, ...] | list[EgressEvent],
    window_seconds: int = 300,
) -> int:
    """Count recently allowed LLM-shaped egress that bypassed inspection."""

    if not events or window_seconds <= 0:
        return 0
    cutoff = datetime.now(timezone.utc).timestamp() - window_seconds
    count = 0
    for event in events:
        if event.timestamp is None:
            continue
        timestamp = event.timestamp
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        if timestamp.timestamp() < cutoff or event.decision != "allow":
            continue
        if (event.branch == "passthrough" and event.looks_like_llm) or event.branch == "shape":
            count += 1
    return count


def parse_timestamp(raw: object) -> datetime | None:
    """Parse an RFC3339 timestamp from the canonical event projection."""

    if not isinstance(raw, str) or not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def timestamp_label(timestamp: datetime | None) -> str:
    """Return compact local-time labels for event-history rows."""

    if timestamp is None:
        return "--:--:--"
    return timestamp.astimezone().strftime("%H:%M:%S")
