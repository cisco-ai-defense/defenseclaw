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

"""Data types for the plugin scanner.

These are the *rich* internal types used during scanning. They carry fields
like rule_id, confidence, evidence, taxonomy, etc. that the simpler
defenseclaw.models.Finding does not have.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

ScanProfile = Literal["default", "strict"]
CategoryStatus = Literal["pass", "info", "warn", "fail"]
ScanVerdict = Literal["benign", "suspicious", "malicious", "unknown"]


def compare_severity(a: str, b: str) -> int:
    return SEVERITY_RANK.get(a, 0) - SEVERITY_RANK.get(b, 0)


def max_severity(items: list[str]) -> str:
    best = "INFO"
    for s in items:
        if compare_severity(s, best) > 0:
            best = s
    return best


@dataclass
class TaxonomyRef:
    objective: str
    technique: str
    sub_technique: str | None = None


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    description: str = ""
    rule_id: str | None = None
    confidence: float | None = None
    evidence: str | None = None
    location: str | None = None
    remediation: str | None = None
    scanner: str = ""
    tags: list[str] = field(default_factory=list)
    taxonomy: TaxonomyRef | None = None
    occurrence_count: int | None = None
    suppressed: bool | None = None
    suppression_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "scanner": self.scanner,
        }
        if self.rule_id is not None:
            d["rule_id"] = self.rule_id
        if self.confidence is not None:
            d["confidence"] = self.confidence
        if self.evidence is not None:
            d["evidence"] = self.evidence
        if self.location is not None:
            d["location"] = self.location
        if self.remediation is not None:
            d["remediation"] = self.remediation
        if self.tags:
            d["tags"] = self.tags
        if self.taxonomy is not None:
            td: dict[str, str] = {
                "objective": self.taxonomy.objective,
                "technique": self.taxonomy.technique,
            }
            if self.taxonomy.sub_technique is not None:
                td["sub_technique"] = self.taxonomy.sub_technique
            d["taxonomy"] = td
        if self.occurrence_count is not None:
            d["occurrence_count"] = self.occurrence_count
        if self.suppressed:
            d["suppressed"] = self.suppressed
        if self.suppression_reason:
            d["suppression_reason"] = self.suppression_reason
        return d


@dataclass
class ScanMetadata:
    manifest_name: str | None = None
    manifest_version: str | None = None
    file_count: int = 0
    total_size_bytes: int = 0
    has_lockfile: bool = False
    has_install_scripts: bool = False
    detected_capabilities: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_name": self.manifest_name,
            "manifest_version": self.manifest_version,
            "file_count": self.file_count,
            "total_size_bytes": self.total_size_bytes,
            "has_lockfile": self.has_lockfile,
            "has_install_scripts": self.has_install_scripts,
            "detected_capabilities": self.detected_capabilities,
        }


@dataclass
class AssessmentCategory:
    name: str
    status: str  # CategoryStatus
    summary: str


@dataclass
class Assessment:
    verdict: str  # ScanVerdict
    confidence: float
    summary: str
    categories: list[AssessmentCategory] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "confidence": self.confidence,
            "summary": self.summary,
            "categories": [{"name": c.name, "status": c.status, "summary": c.summary} for c in self.categories],
        }


@dataclass
class ScanResult:
    scanner: str
    target: str
    timestamp: str
    findings: list[Finding] = field(default_factory=list)
    duration_ns: int | None = None
    metadata: ScanMetadata | None = None
    assessment: Assessment | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "scanner": self.scanner,
            "target": self.target,
            "timestamp": self.timestamp,
            "findings": [f.to_dict() for f in self.findings],
        }
        if self.duration_ns is not None:
            d["duration_ns"] = self.duration_ns
        if self.metadata is not None:
            d["metadata"] = self.metadata.to_dict()
        if self.assessment is not None:
            d["assessment"] = self.assessment.to_dict()
        return d


@dataclass
class PluginManifest:
    name: str
    version: str | None = None
    description: str | None = None
    permissions: list[str] | None = None
    tools: list[dict[str, Any]] | None = None
    commands: list[dict[str, Any]] | None = None
    dependencies: dict[str, str] | None = None
    scripts: dict[str, str] | None = None
    source: str | None = None


@dataclass
class PluginScanOptions:
    profile: str | None = None  # ScanProfile
    policy: str | None = None
    # Optional LLM override that wins over ``PluginScanPolicy.llm``
    # after the YAML policy is loaded. This is how the unified
    # top-level ``llm:`` config (resolved for ``scanners.plugin``)
    # reaches the plugin scanner without every caller needing to
    # write a one-off YAML policy file. Shape is a dict so the types
    # module can stay decoupled from ``policy.LLMPolicy``; the scanner
    # applies it field-by-field to avoid clobbering unset fields.
    llm_override: dict[str, Any] | None = None
