"""Run intake: capture target state, host metadata, and write run.json."""

from __future__ import annotations

import getpass
import platform
import socket
import subprocess
import sys
from pathlib import Path

from dctest import utc_now
from dctest.config import get_settings
from dctest.models import HostInfo, Run, RunStatus
from dctest.services import run_store


def _safe_capture(argv: list[str]) -> str | None:
    try:
        out = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if out.returncode != 0:
            return None
        return out.stdout.strip().splitlines()[0] if out.stdout.strip() else None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def collect_host_info() -> HostInfo:
    return HostInfo(
        os=platform.system(),
        os_version=platform.version(),
        arch=platform.machine(),
        python_version=sys.version.split()[0],
        go_version=_safe_capture(["go", "version"]),
        claude_version=_safe_capture(["claude", "--version"]),
        codex_version=_safe_capture(["codex", "--version"]),
        defenseclaw_version=_safe_capture(["defenseclaw", "version"]),
        defenseclaw_gateway_version=_safe_capture(["defenseclaw-gateway", "--version"]),
        docker_version=_safe_capture(["docker", "--version"]),
        hostname=socket.gethostname(),
        user=getpass.getuser(),
    )


def _git_head_sha(worktree: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(worktree), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return out.stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return "unknown"


def _git_branch(worktree: Path) -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(worktree), "rev-parse", "--abbrev-ref", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        ref = out.stdout.strip()
        return None if ref == "HEAD" else ref
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None


def create_run(
    *,
    slug: str,
    worktree: Path,
    backend: str | None = None,
    notes: str = "",
) -> Run:
    """Create a new run rooted at the configured runs_root and write run.json."""
    settings = get_settings()
    worktree = worktree.resolve()
    if not worktree.exists():
        raise FileNotFoundError(f"Target worktree does not exist: {worktree}")
    head_sha = _git_head_sha(worktree)
    branch = _git_branch(worktree)
    host = collect_host_info()
    now = utc_now()
    run = Run(
        slug=slug,
        target_head_sha=head_sha,
        target_branch=branch,
        target_worktree=worktree,
        created_at=now,
        updated_at=now,
        status=RunStatus.CREATED,
        backend=backend or settings.default_backend,
        host_info=host,
        notes=notes,
    )
    run_store.ensure_run_layout(settings.runs_root, slug)
    run_store.save_run(settings.runs_root, run)
    run_store.write_host_info(settings.runs_root, slug, host)
    run_store.write_target_head_sha(settings.runs_root, slug, head_sha)
    return run
