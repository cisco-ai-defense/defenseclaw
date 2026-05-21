# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Lightweight state models for the initial Python Textual shell."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Literal

ServiceState = Literal[
    "active",
    "allowed",
    "blocked",
    "clean",
    "disabled",
    "enabled",
    "error",
    "offline",
    "reconnecting",
    "rejected",
    "running",
    "starting",
    "stopped",
    "unknown",
    "warning",
]

CommandState = Literal["pending", "running", "succeeded", "failed", "cancelled"]


def utc_now() -> datetime:
    """Return an aware timestamp for shell state snapshots."""

    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class ServiceStatus:
    """Status for one status-strip service segment."""

    label: str
    state: ServiceState | str = "unknown"
    detail: str = ""

    @property
    def is_healthy(self) -> bool:
        return self.state in {"active", "allowed", "clean", "enabled", "running"}

    @property
    def display_label(self) -> str:
        if not self.detail:
            return self.label
        return f"{self.label} ({self.detail})"


@dataclass(frozen=True)
class StatusModel:
    """Top-level shell state used by hint bars and status strips."""

    gateway: ServiceStatus = field(default_factory=lambda: ServiceStatus("Gateway", "offline"))
    watchdog: ServiceStatus = field(default_factory=lambda: ServiceStatus("Watchdog", "unknown"))
    guardrail: ServiceStatus = field(default_factory=lambda: ServiceStatus("Guardrail", "disabled"))
    active_alerts: int = 0
    version: str = ""
    command_running: bool = False
    focused: bool = True
    last_refresh: datetime | None = None
    stale_after: timedelta = timedelta(seconds=15)

    @property
    def is_stale(self) -> bool:
        if self.last_refresh is None:
            return False
        return utc_now() - self.last_refresh > self.stale_after


@dataclass(frozen=True)
class CommandResult:
    """A completed or running command entry for Activity-style widgets."""

    label: str
    argv: tuple[str, ...]
    state: CommandState = "pending"
    started_at: datetime = field(default_factory=utc_now)
    finished_at: datetime | None = None
    exit_code: int | None = None
    stdout: tuple[str, ...] = ()
    stderr: tuple[str, ...] = ()
    masked: bool = False

    @classmethod
    def from_argv(
        cls,
        argv: Sequence[str],
        *,
        label: str | None = None,
        state: CommandState = "pending",
    ) -> CommandResult:
        command = tuple(argv)
        return cls(label=label or " ".join(command), argv=command, state=state)

    @property
    def duration(self) -> timedelta | None:
        if self.finished_at is None:
            return None
        return self.finished_at - self.started_at

    @property
    def output_lines(self) -> tuple[str, ...]:
        return (*self.stdout, *self.stderr)

    @property
    def succeeded(self) -> bool:
        return self.state == "succeeded" and self.exit_code == 0

    def complete(
        self,
        *,
        exit_code: int,
        stdout: Sequence[str] = (),
        stderr: Sequence[str] = (),
        finished_at: datetime | None = None,
    ) -> CommandResult:
        return CommandResult(
            label=self.label,
            argv=self.argv,
            state="succeeded" if exit_code == 0 else "failed",
            started_at=self.started_at,
            finished_at=finished_at or utc_now(),
            exit_code=exit_code,
            stdout=tuple(stdout),
            stderr=tuple(stderr),
            masked=self.masked,
        )

    def cancel(self, *, finished_at: datetime | None = None) -> CommandResult:
        return CommandResult(
            label=self.label,
            argv=self.argv,
            state="cancelled",
            started_at=self.started_at,
            finished_at=finished_at or utc_now(),
            exit_code=self.exit_code,
            stdout=self.stdout,
            stderr=self.stderr,
            masked=self.masked,
        )


@dataclass(frozen=True)
class HintState:
    """Minimal inputs for contextual shell hints."""

    active_panel: str = "overview"
    filter_active: str = ""
    critical_alerts: int = 0
    total_alerts: int = 0
    unscanned_skills: int = 0
    commands_run: int = 0
    command_running: bool = False
    command_label: str = ""
    command_elapsed_secs: int = 0
    logs_paused: bool = False
    new_lines_since_pause: int = 0
