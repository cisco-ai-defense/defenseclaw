"""Report-assembly models."""

from __future__ import annotations

from pydantic import BaseModel, Field

from dctest.models.case import Verdict


class ReportSection(BaseModel):
    """A logical section of the final markdown report."""

    title: str
    body_md: str
    anchor: str | None = None


class RunSummary(BaseModel):
    """Aggregated counts and lists for a finished (or in-progress) run."""

    run_id: str
    total_cells: int
    total_cases: int
    by_verdict: dict[Verdict, int] = Field(default_factory=dict)
    by_cell_id: dict[str, dict[Verdict, int]] = Field(default_factory=dict)
    failing_required_cells: list[str] = Field(default_factory=list)
    skipped_optional_cells: list[str] = Field(default_factory=list)
    needs_human_cases: list[str] = Field(default_factory=list)
    duration_seconds: float = 0.0
