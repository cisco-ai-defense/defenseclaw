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

"""Data models — mirrors internal/scanner/result.go and internal/audit/store.go types."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

SEVERITY_RANK = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    description: str = ""
    location: str = ""
    remediation: str = ""
    scanner: str = ""
    tags: list[str] = field(default_factory=list)
    rule_id: str = ""
    line_number: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "location": self.location,
            "remediation": self.remediation,
            "scanner": self.scanner,
            "tags": self.tags,
        }
        if self.rule_id:
            d["rule_id"] = self.rule_id
        if self.line_number is not None:
            d["line_number"] = self.line_number
        return d


@dataclass
class ScanResult:
    scanner: str
    target: str
    timestamp: datetime
    findings: list[Finding] = field(default_factory=list)
    duration: timedelta = field(default_factory=timedelta)

    def has_severity(self, severity: str) -> bool:
        return any(f.severity == severity for f in self.findings)

    def max_severity(self) -> str:
        if not self.findings:
            return "INFO"
        return max(self.findings, key=lambda f: SEVERITY_RANK.get(f.severity, 0)).severity

    def count_by_severity(self, severity: str) -> int:
        return sum(1 for f in self.findings if f.severity == severity)

    def is_clean(self) -> bool:
        return len(self.findings) == 0

    def to_json(self) -> str:
        return json.dumps({
            "scanner": self.scanner,
            "target": self.target,
            "timestamp": self.timestamp.isoformat(),
            "findings": [f.to_dict() for f in self.findings],
            "duration_ms": int(self.duration.total_seconds() * 1000),
        }, indent=2)


def compare_severity(a: str, b: str) -> int:
    return SEVERITY_RANK.get(a, 0) - SEVERITY_RANK.get(b, 0)


# --- Audit / enforcement models ---

@dataclass
class ActionState:
    file: str = ""
    runtime: str = ""
    install: str = ""

    def is_empty(self) -> bool:
        return not self.file and not self.runtime and not self.install

    def summary(self) -> str:
        parts: list[str] = []
        if self.install == "block":
            parts.append("blocked")
        if self.install == "allow":
            parts.append("allowed")
        if self.file == "quarantine":
            parts.append("quarantined")
        if self.runtime == "disable":
            parts.append("disabled")
        return ", ".join(parts) if parts else "-"

    def to_dict(self) -> dict[str, str]:
        d: dict[str, str] = {}
        if self.file:
            d["file"] = self.file
        if self.runtime:
            d["runtime"] = self.runtime
        if self.install:
            d["install"] = self.install
        return d

    @classmethod
    def from_dict(cls, d: dict[str, str] | None) -> ActionState:
        if not d:
            return cls()
        return cls(
            file=d.get("file", ""),
            runtime=d.get("runtime", ""),
            install=d.get("install", ""),
        )


@dataclass
class ActionEntry:
    id: str
    target_type: str
    target_name: str
    source_path: str = ""
    actions: ActionState = field(default_factory=ActionState)
    reason: str = ""
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Event:
    id: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    action: str = ""
    target: str = ""
    actor: str = "defenseclaw"
    details: str = ""
    severity: str = ""
    run_id: str = ""


@dataclass
class TargetSnapshot:
    id: str = ""
    target_type: str = ""
    target_path: str = ""
    content_hash: str = ""
    dependency_hashes: dict[str, str] = field(default_factory=dict)
    config_hashes: dict[str, str] = field(default_factory=dict)
    network_endpoints: list[str] = field(default_factory=list)
    scan_id: str = ""
    captured_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Counts:
    blocked_skills: int = 0
    allowed_skills: int = 0
    blocked_mcps: int = 0
    allowed_mcps: int = 0
    alerts: int = 0
    total_scans: int = 0
    blocked_egress_calls: int = 0
