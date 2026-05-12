"""Aggregate per-case verdicts into a run-level summary."""

from __future__ import annotations

import json
from pathlib import Path

from dctest.config import get_settings
from dctest.models import CaseResult, MatrixCell, RunSummary, Verdict
from dctest.services import run_store


def _gather_results(run_id: str) -> tuple[list[MatrixCell], dict[str, list[CaseResult]]]:
    settings = get_settings()
    cells = run_store.list_cells(settings.runs_root, run_id)
    out: dict[str, list[CaseResult]] = {}
    for cell in cells:
        cell_results: list[CaseResult] = []
        case_root = run_store.cell_dir(settings.runs_root, run_id, cell.id) / "cases"
        if not case_root.exists():
            out[cell.id] = []
            continue
        for case_dir in sorted(case_root.iterdir()):
            r_path = case_dir / "result.json"
            if not r_path.exists():
                continue
            try:
                cell_results.append(
                    CaseResult.model_validate_json(r_path.read_text(encoding="utf-8"))
                )
            except Exception:  # noqa: BLE001 - keep going on a partial run
                continue
        out[cell.id] = cell_results
    return cells, out


def build_summary(run_id: str) -> RunSummary:
    settings = get_settings()
    cells, results_by_cell = _gather_results(run_id)
    total_cases = sum(len(v) for v in results_by_cell.values())
    by_verdict: dict[Verdict, int] = {v: 0 for v in Verdict}
    by_cell: dict[str, dict[Verdict, int]] = {}
    failing_required: list[str] = []
    skipped_optional: list[str] = []
    needs_human: list[str] = []
    earliest: float | None = None
    latest: float | None = None
    for cell in cells:
        cell_results = results_by_cell.get(cell.id, [])
        counts: dict[Verdict, int] = {v: 0 for v in Verdict}
        for r in cell_results:
            counts[r.verdict] = counts.get(r.verdict, 0) + 1
            by_verdict[r.verdict] += 1
            if r.verdict == Verdict.NEEDS_HUMAN:
                needs_human.append(f"{cell.id}::{r.case_id}")
            started = r.started_at.timestamp()
            ended = r.ended_at.timestamp()
            earliest = started if earliest is None else min(earliest, started)
            latest = ended if latest is None else max(latest, ended)
        by_cell[cell.id] = counts
        any_fail = counts.get(Verdict.FAIL, 0) > 0
        any_blocked = counts.get(Verdict.BLOCKED, 0) > 0
        if (any_fail or any_blocked) and cell.tier.value == "required":
            failing_required.append(cell.id)
        if cell.tier.value == "optional" and not cell_results:
            skipped_optional.append(cell.id)
    duration = 0.0 if (earliest is None or latest is None) else max(0.0, latest - earliest)
    summary = RunSummary(
        run_id=run_id,
        total_cells=len(cells),
        total_cases=total_cases,
        by_verdict=by_verdict,
        by_cell_id=by_cell,
        failing_required_cells=failing_required,
        skipped_optional_cells=skipped_optional,
        needs_human_cases=needs_human,
        duration_seconds=duration,
    )
    _write_summary(settings.runs_root, run_id, summary)
    return summary


def _write_summary(runs_root: Path, run_id: str, summary: RunSummary) -> None:
    path = run_store.summary_path(runs_root, run_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = summary.model_dump(mode="json")
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def exit_code_for_summary(summary: RunSummary) -> int:
    """Return non-zero if any required cell failed or any case needs a human."""
    if summary.failing_required_cells:
        return 1
    if summary.needs_human_cases:
        return 2
    return 0
