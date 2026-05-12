"""On-disk persistence helpers for a dctest run.

Mirrors avarice's ``services/campaign_store.py``: pure path conventions plus
JSON round-trip helpers. All other services compose against these helpers.
"""

from __future__ import annotations

import json
from pathlib import Path

from dctest import utc_now
from dctest.exceptions import CaseNotFoundError, CellNotFoundError, RunNotFoundError
from dctest.models import (
    CaseResult,
    HostInfo,
    MatrixCell,
    Run,
    RunStatus,
)


def run_dir(runs_root: Path, run_id: str) -> Path:
    return runs_root / run_id


def cell_dir(runs_root: Path, run_id: str, cell_id: str) -> Path:
    return run_dir(runs_root, run_id) / "cells" / cell_id


def case_dir(runs_root: Path, run_id: str, cell_id: str, case_id: str) -> Path:
    return cell_dir(runs_root, run_id, cell_id) / "cases" / case_id


def logs_dir(runs_root: Path, run_id: str, stage: str) -> Path:
    return run_dir(runs_root, run_id) / "logs" / stage


def snapshots_dir(runs_root: Path, run_id: str) -> Path:
    return run_dir(runs_root, run_id) / "snapshots"


def staged_dir(runs_root: Path, run_id: str, stage: str) -> Path:
    return run_dir(runs_root, run_id) / "staged" / stage


def run_json_path(runs_root: Path, run_id: str) -> Path:
    return run_dir(runs_root, run_id) / "run.json"


def cell_json_path(runs_root: Path, run_id: str, cell_id: str) -> Path:
    return cell_dir(runs_root, run_id, cell_id) / "cell.json"


def verdict_path(runs_root: Path, run_id: str, cell_id: str, case_id: str) -> Path:
    return case_dir(runs_root, run_id, cell_id, case_id) / "verdict.json"


def summary_path(runs_root: Path, run_id: str) -> Path:
    return run_dir(runs_root, run_id) / "SUMMARY.json"


def report_path(runs_root: Path, run_id: str) -> Path:
    return run_dir(runs_root, run_id) / "report.md"


def ensure_run_layout(runs_root: Path, run_id: str) -> None:
    run_dir(runs_root, run_id).mkdir(parents=True, exist_ok=True)
    (run_dir(runs_root, run_id) / "cells").mkdir(exist_ok=True)
    (run_dir(runs_root, run_id) / "logs").mkdir(exist_ok=True)
    (run_dir(runs_root, run_id) / "snapshots").mkdir(exist_ok=True)
    (run_dir(runs_root, run_id) / "staged").mkdir(exist_ok=True)


def save_run(runs_root: Path, run: Run) -> None:
    ensure_run_layout(runs_root, run.slug)
    path = run_json_path(runs_root, run.slug)
    path.write_text(run.model_dump_json(indent=2, exclude_none=False), encoding="utf-8")


def load_run(runs_root: Path, run_id: str) -> Run:
    path = run_json_path(runs_root, run_id)
    if not path.exists():
        raise RunNotFoundError(f"No run found at {path}")
    return Run.model_validate_json(path.read_text(encoding="utf-8"))


def update_run_status(runs_root: Path, run_id: str, status: RunStatus) -> Run:
    run = load_run(runs_root, run_id)
    run.status = status
    run.updated_at = utc_now()
    save_run(runs_root, run)
    return run


def save_cell(runs_root: Path, run_id: str, cell: MatrixCell) -> None:
    cell_dir(runs_root, run_id, cell.id).mkdir(parents=True, exist_ok=True)
    cell_json_path(runs_root, run_id, cell.id).write_text(
        cell.model_dump_json(indent=2), encoding="utf-8"
    )


def load_cell(runs_root: Path, run_id: str, cell_id: str) -> MatrixCell:
    path = cell_json_path(runs_root, run_id, cell_id)
    if not path.exists():
        raise CellNotFoundError(f"No cell found at {path}")
    return MatrixCell.model_validate_json(path.read_text(encoding="utf-8"))


def list_cells(runs_root: Path, run_id: str) -> list[MatrixCell]:
    cells_root = run_dir(runs_root, run_id) / "cells"
    if not cells_root.exists():
        return []
    out: list[MatrixCell] = []
    for d in sorted(cells_root.iterdir()):
        if d.is_dir() and (d / "cell.json").exists():
            out.append(MatrixCell.model_validate_json((d / "cell.json").read_text(encoding="utf-8")))
    return out


def save_case_result(runs_root: Path, result: CaseResult) -> None:
    d = case_dir(runs_root, result.run_id, result.cell_id, result.case_id)
    d.mkdir(parents=True, exist_ok=True)
    (d / "result.json").write_text(result.model_dump_json(indent=2), encoding="utf-8")


def load_case_result(runs_root: Path, run_id: str, cell_id: str, case_id: str) -> CaseResult:
    d = case_dir(runs_root, run_id, cell_id, case_id)
    path = d / "result.json"
    if not path.exists():
        raise CaseNotFoundError(f"No case result at {path}")
    return CaseResult.model_validate_json(path.read_text(encoding="utf-8"))


def write_host_info(runs_root: Path, run_id: str, info: HostInfo) -> None:
    path = run_dir(runs_root, run_id) / "host_info.json"
    path.write_text(info.model_dump_json(indent=2), encoding="utf-8")


def write_target_head_sha(runs_root: Path, run_id: str, sha: str) -> None:
    path = run_dir(runs_root, run_id) / "target_head_sha.txt"
    path.write_text(sha + "\n", encoding="utf-8")


def append_jsonl(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, default=str) + "\n")
