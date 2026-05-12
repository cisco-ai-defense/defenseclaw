"""Pydantic round-trips for core models."""

from __future__ import annotations

from pathlib import Path

from dctest import utc_now
from dctest.models import (
    CaseResult,
    CaseStatus,
    HostInfo,
    MatrixCell,
    ProviderSpec,
    Run,
    RunStatus,
    Verdict,
)
from dctest.models.matrix import Tier


def _provider() -> ProviderSpec:
    return ProviderSpec(
        id="anthropic-claude-sonnet",
        vendor="anthropic",
        model="claude-sonnet-4-5",
        auth_env="ANTHROPIC_API_KEY",
    )


def test_run_round_trip(tmp_path):
    info = HostInfo(
        os="Darwin",
        os_version="25.2.0",
        arch="arm64",
        python_version="3.13.0",
        hostname="test",
        user="dctest",
    )
    run = Run(
        slug="dctest-run-1",
        target_head_sha="deadbeef",
        target_worktree=tmp_path,
        created_at=utc_now(),
        updated_at=utc_now(),
        status=RunStatus.CREATED,
        backend="claude",
        host_info=info,
    )
    blob = run.model_dump_json()
    again = Run.model_validate_json(blob)
    assert again == run


def test_cell_round_trip():
    provider = _provider()
    cell = MatrixCell(
        id="codex--anthropic-claude-sonnet--guardrail-only--opa.default--pack.default--fail-open--skill",
        connector="codex",
        provider=provider,
        role="guardrail-only",
        opa_profile="default",
        pack_profile="default",
        fail_mode="fail-open",
        scan_type="skill",
        tier=Tier.REQUIRED,
    )
    again = MatrixCell.model_validate_json(cell.model_dump_json())
    assert again.id == cell.id
    assert again.provider.id == provider.id


def test_case_result_round_trip(tmp_path):
    res = CaseResult(
        case_id="cli-py.version.basic",
        cell_id="cell-1",
        run_id="run-1",
        started_at=utc_now(),
        ended_at=utc_now(),
        exit_code=0,
        stdout_path=tmp_path / "stdout.txt",
        stderr_path=tmp_path / "stderr.txt",
        verdict=Verdict.PASS,
        status=CaseStatus.CLASSIFIED,
    )
    again = CaseResult.model_validate_json(res.model_dump_json())
    assert again.verdict == Verdict.PASS
    assert isinstance(again.stdout_path, Path)
