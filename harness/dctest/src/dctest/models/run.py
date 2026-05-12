"""Run-level models: a single ``dctest run`` invocation."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field


class RunStatus(str, Enum):
    """Lifecycle states for a run."""

    CREATED = "created"
    PLANNED = "planned"
    EXECUTING = "executing"
    COMPLETED = "completed"
    ABORTED = "aborted"
    FAILED = "failed"


class HostInfo(BaseModel):
    """Snapshot of host-level metadata recorded at intake."""

    os: str
    os_version: str
    arch: str
    python_version: str
    go_version: str | None = None
    claude_version: str | None = None
    codex_version: str | None = None
    defenseclaw_version: str | None = None
    defenseclaw_gateway_version: str | None = None
    docker_version: str | None = None
    hostname: str
    user: str


class Run(BaseModel):
    """A single dctest run instance.

    Persisted as ``runs/<run-id>/run.json``. The run id is the slug; the
    target_head_sha is pinned at intake.
    """

    slug: str = Field(description="Unique run identifier (also the folder name).")
    target_head_sha: str = Field(description="Commit SHA being tested.")
    target_branch: str | None = None
    target_worktree: Path
    created_at: datetime
    updated_at: datetime
    status: RunStatus = RunStatus.CREATED
    backend: str = "claude"
    selection_path: Path | None = Field(
        default=None,
        description="Path to the matrix selection YAML used for this run, if any.",
    )
    host_info: HostInfo
    notes: str = ""
