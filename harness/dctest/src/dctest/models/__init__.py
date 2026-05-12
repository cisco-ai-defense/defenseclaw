"""Pydantic domain models for dctest."""

from __future__ import annotations

from dctest.models.case import (
    CaseResult,
    CaseStatus,
    TestCase,
    Verdict,
)
from dctest.models.evidence import (
    AgentTranscript,
    CommandTranscript,
    Evidence,
)
from dctest.models.matrix import (
    MatrixCell,
    MatrixDimension,
    ProviderSpec,
    Role,
)
from dctest.models.report import ReportSection, RunSummary
from dctest.models.run import (
    HostInfo,
    Run,
    RunStatus,
)

__all__ = [
    "AgentTranscript",
    "CaseResult",
    "CaseStatus",
    "CommandTranscript",
    "Evidence",
    "HostInfo",
    "MatrixCell",
    "MatrixDimension",
    "ProviderSpec",
    "ReportSection",
    "Role",
    "Run",
    "RunStatus",
    "RunSummary",
    "TestCase",
    "Verdict",
]
