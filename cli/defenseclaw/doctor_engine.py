# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Typed planning primitives for :mod:`defenseclaw.commands.cmd_doctor`.

Doctor historically represented both health checks and repair attempts as
human-facing ``(status, label, detail)`` rows.  That made the plain output
pleasant, but left automation unable to distinguish:

* a failed health check from a failed repair;
* a no-op from a declined or policy-blocked repair;
* a safe file edit from a restart or an explicit policy change; and
* an applicable dry-run action from a fixer that merely exists.

This module deliberately contains no command imports.  Keeping the engine
types independent lets checks, the TUI, and native-platform tests use the same
schema without importing Click or creating runtime state.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal, Protocol

RepairState = Literal[
    "applicable",
    "noop",
    "blocked",
    "manual",
    "requires_confirmation",
    "declined",
    "applied",
    "failed",
]
RepairRisk = Literal["safe", "disruptive", "policy", "experimental"]

_IDENTIFIER_COMPONENT_RE = re.compile(r"[^a-z0-9]+")


def stable_doctor_id(kind: str, section: str, label: str) -> str:
    """Return a bounded machine identifier for a legacy Doctor row.

    New checks should pass an explicit identifier.  Existing checks are
    numerous and historically exposed only labels, so the compatibility path
    derives an ID from section + label and adds a short digest.  The readable
    prefix helps operators while the digest prevents two punctuation variants
    from collapsing to the same identifier.
    """

    raw = f"{kind}\0{section}\0{label}".strip()
    readable = _IDENTIFIER_COMPONENT_RE.sub(
        ".",
        f"{section}.{label}".strip().casefold(),
    ).strip(".")
    readable = readable[:96].rstrip(".") or "unnamed"
    digest = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:10]
    return f"doctor.{kind}.{readable}.{digest}"


@dataclass(frozen=True)
class RepairDecision:
    """One secret-free plan/apply/verify result."""

    state: RepairState
    detail: str
    effects: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()
    state_key: str = ""

    @property
    def applicable(self) -> bool:
        return self.state in {"applicable", "requires_confirmation"}


class RepairPlanner(Protocol):
    def __call__(self, cfg: object) -> RepairDecision: ...


class RepairApplier(Protocol):
    def __call__(self, cfg: object, *, assume_yes: bool) -> tuple[str, str]: ...


class RepairVerifier(Protocol):
    def __call__(self, cfg: object) -> RepairDecision: ...


@dataclass(frozen=True)
class RepairSpec:
    """Declarative contract for one Doctor repair."""

    repair_id: str
    label: str
    risk: RepairRisk
    plan: RepairPlanner
    apply: RepairApplier
    verify: RepairVerifier | None = None
    dependencies: tuple[str, ...] = ()
    effects: tuple[str, ...] = ()
    may_restart: bool = False
    explicit_selection_required: bool = False
    platforms: tuple[str, ...] = ("linux", "darwin", "win32")


@dataclass
class RepairRunSummary:
    """Aggregate repair states without contaminating health counts."""

    planned: int = 0
    applied: int = 0
    failed: int = 0
    blocked: int = 0
    manual: int = 0
    noop: int = 0
    declined: int = 0
    requires_confirmation: int = 0

    def record(self, state: RepairState) -> None:
        attribute = {
            "applicable": "planned",
            "requires_confirmation": "requires_confirmation",
            "applied": "applied",
            "failed": "failed",
            "blocked": "blocked",
            "manual": "manual",
            "noop": "noop",
            "declined": "declined",
        }[state]
        setattr(self, attribute, getattr(self, attribute) + 1)

    def to_dict(self) -> dict[str, int]:
        return {
            "planned": self.planned,
            "applied": self.applied,
            "failed": self.failed,
            "blocked": self.blocked,
            "manual": self.manual,
            "noop": self.noop,
            "declined": self.declined,
            "requires_confirmation": self.requires_confirmation,
        }


@dataclass(frozen=True)
class RepairRecord:
    """Serializable repair record emitted by Doctor schema v2."""

    repair_id: str
    label: str
    state: RepairState
    risk: RepairRisk
    detail: str
    dependencies: tuple[str, ...] = ()
    effects: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()
    may_restart: bool = False
    explicit_selection_required: bool = False
    platform: str = ""
    duration_ms: int = 0
    metadata: dict[str, str | int | bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "repair_id": self.repair_id,
            "label": self.label,
            "state": self.state,
            "risk": self.risk,
            "detail": self.detail,
            "dependencies": list(self.dependencies),
            "effects": list(self.effects),
            "blockers": list(self.blockers),
            "may_restart": self.may_restart,
            "explicit_selection_required": self.explicit_selection_required,
            "platform": self.platform,
            "duration_ms": self.duration_ms,
            "metadata": dict(self.metadata),
        }


def legacy_outcome_state(tag: str, detail: str) -> RepairState:
    """Map an existing fixer outcome into the v2 repair state vocabulary."""

    normalized_tag = tag.strip().casefold()
    lowered = detail.casefold()
    if normalized_tag == "pass":
        return "applied"
    if normalized_tag == "fail":
        return "failed"
    if normalized_tag not in {"skip", "warn"}:
        # The compatibility boundary is intentionally fail closed. A typo or
        # future legacy status must not be serialized as a successful no-op,
        # because repair failures participate in Doctor's process exit code.
        return "failed"
    if "declined" in lowered:
        return "declined"
    if "manual" in lowered or "run `" in lowered or "run '" in lowered:
        return "manual"
    if "blocked" in lowered or "refus" in lowered:
        return "blocked"
    return "noop"


def default_repair_verifier(plan: Callable[[object], RepairDecision], cfg: object) -> RepairDecision:
    """Treat a post-apply no-op plan as convergence."""

    decision = plan(cfg)
    if decision.state == "noop":
        return RepairDecision(
            "applied",
            "postcondition verified",
            effects=decision.effects,
            state_key=decision.state_key,
        )
    return RepairDecision(
        "failed",
        f"postcondition did not converge: {decision.detail}",
        effects=decision.effects,
        blockers=decision.blockers,
        state_key=decision.state_key,
    )
