"""Evidence and transcript models."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, Field


class CommandTranscript(BaseModel):
    """Captured I/O of a single defenseclaw command under test."""

    command: str
    cwd: Path
    env_overrides: dict[str, str]
    started_at: datetime
    ended_at: datetime
    exit_code: int
    timed_out: bool
    stdout_path: Path
    stderr_path: Path


class AgentTranscript(BaseModel):
    """Captured I/O of a single agent (claude/codex) invocation."""

    backend: str
    argv: list[str]
    cwd: Path
    started_at: datetime
    ended_at: datetime
    exit_code: int
    timed_out: bool
    prompt_path: Path
    stdout_path: Path
    stderr_path: Path
    last_message_path: Path | None = None


class Evidence(BaseModel):
    """A piece of supporting evidence attached to a case result."""

    kind: str = Field(description="e.g. 'stdout', 'config-diff', 'audit-export', 'screenshot'.")
    path: Path
    description: str = ""
