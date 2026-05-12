"""Programmatic report assembly handles empty + populated runs."""

from __future__ import annotations

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
from dctest.services import run_store
from dctest.services.report import build_report
from dctest.services.score import build_summary


def _provider() -> ProviderSpec:
    return ProviderSpec(
        id="anthropic-claude-sonnet",
        vendor="anthropic",
        model="claude-sonnet-4-5",
        auth_env="ANTHROPIC_API_KEY",
    )


def _seed(runs_root, *, verdict: Verdict, tier: Tier = Tier.REQUIRED):
    info = HostInfo(
        os="Linux",
        os_version="6",
        arch="x86_64",
        python_version="3.13",
        hostname="ci",
        user="dctest",
    )
    run = Run(
        slug="report-it",
        target_head_sha="abc",
        target_worktree=runs_root,
        created_at=utc_now(),
        updated_at=utc_now(),
        status=RunStatus.COMPLETED,
        backend="manual",
        host_info=info,
    )
    run_store.ensure_run_layout(runs_root, run.slug)
    run_store.save_run(runs_root, run)
    cell = MatrixCell(
        id="cell-1",
        connector="codex",
        provider=_provider(),
        role="guardrail-only",
        opa_profile="default",
        pack_profile="default",
        fail_mode="fail-open",
        scan_type="skill",
        tier=tier,
    )
    run_store.save_cell(runs_root, run.slug, cell)
    res = CaseResult(
        case_id="case-1",
        cell_id=cell.id,
        run_id=run.slug,
        started_at=utc_now(),
        ended_at=utc_now(),
        exit_code=0,
        stdout_path=runs_root / run.slug / "out.txt",
        stderr_path=runs_root / run.slug / "err.txt",
        verdict=verdict,
        agent_reasoning="seeded for test",
        status=CaseStatus.CLASSIFIED,
    )
    run_store.save_case_result(runs_root, res)
    return run.slug


def test_summary_and_report_for_pass(isolated_runs_root):
    slug = _seed(isolated_runs_root, verdict=Verdict.PASS)
    summary = build_summary(slug)
    assert summary.by_verdict[Verdict.PASS] == 1
    report = build_report(slug)
    body = report.read_text(encoding="utf-8")
    assert slug in body
    assert "case-1" in body


def test_summary_marks_required_failure(isolated_runs_root):
    slug = _seed(isolated_runs_root, verdict=Verdict.FAIL)
    summary = build_summary(slug)
    assert summary.failing_required_cells == ["cell-1"]
