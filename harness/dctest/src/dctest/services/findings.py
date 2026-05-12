"""Emit one Markdown ``finding`` file per unexpected fail.

Each file is GitHub-issue-ready: title, repro command, captured outputs,
agent reasoning, and a triage hint based on the case's
``expected_to_fail_at`` annotation. Cases whose entire cluster is marked
``all_expected`` are skipped — those are tracked bugs, not new findings.
"""

from __future__ import annotations

from pathlib import Path

from dctest.config import get_settings
from dctest.models import CaseResult, Verdict
from dctest.services import case_loader, cluster, run_store


def emit_findings(run_id: str) -> list[Path]:
    """Write one Markdown file per unexpected fail; return their paths."""
    settings = get_settings()
    out_dir = settings.runs_root / run_id / "findings"
    out_dir.mkdir(parents=True, exist_ok=True)

    clusters = cluster.cluster_run(run_id)
    expected_by_case = {c.id: list(c.expected_to_fail_at) for c in case_loader.load_all_cases()}
    case_by_id = {c.id: c for c in case_loader.load_all_cases()}

    written: list[Path] = []
    for clust in clusters:
        if clust.all_expected:
            continue
        for m in clust.members:
            # Skip individual members that ARE marked expected even if the
            # cluster as a whole isn't (mixed cluster).
            if expected_by_case.get(m.case_id):
                continue
            tc = case_by_id.get(m.case_id)
            body = _render_finding(
                run_id=run_id,
                case_id=m.case_id,
                cell_id=m.cell_id,
                verdict=m.verdict,
                cluster_fingerprint=clust.fingerprint,
                sample_line=clust.sample_line,
                stdout_path=m.stdout_path,
                stderr_path=m.stderr_path,
                command=tc.command if tc else "",
                expected_substrings=list(tc.expected_substrings) if tc else [],
                expected_exit_code=tc.expected_exit_code if tc else None,
                docs_site_refs=list(tc.docs_site_refs) if tc else [],
            )
            out_path = out_dir / f"{m.case_id.replace('/', '_')}.md"
            out_path.write_text(body, encoding="utf-8")
            written.append(out_path)
    return written


def _render_finding(
    *,
    run_id: str,
    case_id: str,
    cell_id: str,
    verdict: str,
    cluster_fingerprint: str,
    sample_line: str,
    stdout_path: str,
    stderr_path: str,
    command: str,
    expected_substrings: list[str],
    expected_exit_code: int | None,
    docs_site_refs: list[str],
) -> str:
    lines = [
        f"# `{case_id}` — verdict `{verdict}`",
        "",
        f"- **run**: `{run_id}`",
        f"- **cell**: `{cell_id}`",
        f"- **cluster**: `{cluster_fingerprint}`",
        f"- **canonical stderr**: `{sample_line}`",
        f"- **expected_exit_code**: `{expected_exit_code}`",
    ]
    if expected_substrings:
        lines.append(
            "- **expected substrings**: " + ", ".join(f"`{s}`" for s in expected_substrings)
        )
    if docs_site_refs:
        lines.append("- **docs refs**:")
        for d in docs_site_refs:
            lines.append(f"  - `{d}`")
    lines += [
        "",
        "## Repro",
        "",
        "```bash",
        command.strip() or "(no command captured)",
        "```",
        "",
        "## Captured outputs",
        "",
        f"- stdout: `{stdout_path}`",
        f"- stderr: `{stderr_path}`",
        "",
        "## Triage",
        "",
        (
            "This failure is NOT marked `expected_to_fail_at` in the case YAML. "
            "Either the underlying DefenseClaw behavior regressed or the case "
            "needs to declare a tracked failure. Read the captured stderr above "
            "before assigning."
        ),
    ]
    return "\n".join(lines) + "\n"


def _result_for(run_id: str, cell_id: str, case_id: str) -> CaseResult | None:
    settings = get_settings()
    case_d = run_store.case_dir(settings.runs_root, run_id, cell_id, case_id)
    r_path = case_d / "result.json"
    if not r_path.exists():
        return None
    try:
        return CaseResult.model_validate_json(r_path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None


_ = Verdict  # silence unused warning while keeping the import available
