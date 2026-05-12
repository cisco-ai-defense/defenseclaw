"""Programmatic markdown report assembly.

Mirrors avarice's ``services/report.py``: pure Python string assembly from
on-disk artifacts. Not driven by a markdown template — the structure of
the report is part of the harness contract.
"""

from __future__ import annotations

from pathlib import Path

from dctest import utc_now
from dctest.config import get_settings
from dctest.models import CaseResult, Run, RunSummary, Verdict
from dctest.services import cluster as cluster_svc
from dctest.services import run_store


def build_report(run_id: str) -> Path:
    settings = get_settings()
    run = run_store.load_run(settings.runs_root, run_id)
    cells = run_store.list_cells(settings.runs_root, run_id)
    summary = _load_summary(run_id)
    parts: list[str] = []
    parts.append(_header(run, summary))
    parts.append(_summary_table(summary))
    parts.append(_root_cause_clusters_section(run_id))
    parts.append(_per_cell_section(run_id, cells))
    parts.append(_failures_section(run_id, cells))
    parts.append(_needs_human_section(summary))
    parts.append(_footer(run))
    out_path = run_store.report_path(settings.runs_root, run_id)
    out_path.write_text("\n\n".join(p for p in parts if p), encoding="utf-8")
    return out_path


def _load_summary(run_id: str) -> RunSummary | None:
    settings = get_settings()
    path = run_store.summary_path(settings.runs_root, run_id)
    if not path.exists():
        return None
    try:
        return RunSummary.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None


def _header(run: Run, summary: RunSummary | None) -> str:
    lines = [
        f"# dctest run report — `{run.slug}`",
        "",
        f"- target_head_sha: `{run.target_head_sha}`",
        f"- branch: `{run.target_branch or '(detached)'}`",
        f"- backend: `{run.backend}`",
        f"- created_at: `{run.created_at.isoformat()}Z`",
        f"- updated_at: `{run.updated_at.isoformat()}Z`",
        f"- status: `{run.status.value}`",
    ]
    if summary:
        lines.append(f"- total_cells: `{summary.total_cells}`")
        lines.append(f"- total_cases: `{summary.total_cases}`")
        lines.append(f"- duration: `{summary.duration_seconds:.1f}s`")
    return "\n".join(lines)


def _summary_table(summary: RunSummary | None) -> str:
    if summary is None:
        return "## Summary\n\n*No SUMMARY.json yet — run `dctest score` first.*"
    rows = ["## Summary", ""]
    rows.append("| Verdict | Count |")
    rows.append("| --- | --- |")
    for v in Verdict:
        rows.append(f"| {v.value} | {summary.by_verdict.get(v, 0)} |")
    return "\n".join(rows)


def _per_cell_section(run_id: str, cells: list) -> str:
    settings = get_settings()
    parts = ["## Per-cell results", ""]
    if not cells:
        parts.append("*No cells materialized yet — run `dctest matrix select` and `dctest run`.*")
        return "\n".join(parts)
    for cell in cells:
        parts.append(f"### `{cell.id}`")
        parts.append(f"- {cell.short_label()}")
        case_root = run_store.cell_dir(settings.runs_root, run_id, cell.id) / "cases"
        if not case_root.exists():
            parts.append("- *(no cases executed)*")
            continue
        bullets: list[str] = []
        for case_dir in sorted(case_root.iterdir()):
            r_path = case_dir / "result.json"
            if not r_path.exists():
                continue
            try:
                r = CaseResult.model_validate_json(r_path.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                continue
            bullets.append(
                f"- `{r.case_id}` — **{r.verdict.value}** "
                f"(exit={r.exit_code}, timed_out={r.timed_out})"
            )
            if r.agent_reasoning:
                bullets.append(f"  > {r.agent_reasoning[:240].strip()}")
        parts.extend(bullets if bullets else ["- *(no result.json yet)*"])
    return "\n".join(parts)


def _failures_section(run_id: str, cells: list) -> str:
    settings = get_settings()
    fails: list[str] = []
    for cell in cells:
        case_root = run_store.cell_dir(settings.runs_root, run_id, cell.id) / "cases"
        if not case_root.exists():
            continue
        for case_dir in sorted(case_root.iterdir()):
            r_path = case_dir / "result.json"
            if not r_path.exists():
                continue
            try:
                r = CaseResult.model_validate_json(r_path.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                continue
            if r.verdict in (Verdict.FAIL, Verdict.BLOCKED):
                fails.append(
                    f"- `{cell.id}` :: `{r.case_id}` ({r.verdict.value}) "
                    f"— stdout `{r.stdout_path}`"
                )
    if not fails:
        return "## Failures\n\n*None recorded.*"
    return "## Failures\n\n" + "\n".join(fails)


def _root_cause_clusters_section(run_id: str) -> str:
    """Group failures by normalized stderr fingerprint.

    The full list of cluster members is persisted to ``clusters.json``; the
    report only shows the top clusters by member count to keep it
    readable. Clusters where every member is expected-to-fail get a
    distinguishing prefix so reviewers can skip over tracked bugs.
    """
    clusters = cluster_svc.cluster_run(run_id)
    if not clusters:
        return "## Root-cause clusters\n\n*No failures or blocked cases recorded.*"
    cluster_svc.save_clusters(run_id, clusters)
    lines = [
        "## Root-cause clusters",
        "",
        (
            "Failures grouped by normalized stderr fingerprint. Clusters tagged "
            "`tracked` contain only cases that declare "
            "`expected_to_fail_at` — investigate the rest first."
        ),
        "",
        "| # | tag | exit | members | sample stderr |",
        "| --- | --- | --- | --- | --- |",
    ]
    for idx, c in enumerate(clusters[:20], 1):
        tag = "tracked" if c.all_expected else "new"
        sample = (c.sample_line or "(no stderr)")[:120].replace("|", "\\|")
        lines.append(f"| {idx} | {tag} | {c.exit_code} | {len(c.members)} | `{sample}` |")
    if len(clusters) > 20:
        lines.append(
            f"\n... and {len(clusters) - 20} more (see "
            f"`runs/{run_id}/clusters.json` for the full list)."
        )
    return "\n".join(lines)


def _needs_human_section(summary: RunSummary | None) -> str:
    if not summary or not summary.needs_human_cases:
        return ""
    lines = ["## Needs human review", ""]
    for label in summary.needs_human_cases:
        lines.append(f"- {label}")
    return "\n".join(lines)


def _footer(run: Run) -> str:
    return (
        f"---\n*Generated by dctest at {utc_now().isoformat()}Z. "
        f"Run dir: `{Path(run.target_worktree)}`.*"
    )
