"""Execute a TestCase inside a MatrixCell and capture an agent verdict.

The flow per case mirrors avarice's render → execute → collect contract,
but in-process when the backend is ``claude`` or ``codex``. For ``manual``,
the harness writes the case prompt to ``staged/<stage>/`` and returns;
the user runs the agent externally, then invokes ``dctest collect``.

Pass/fail decisions are always written by the agent to ``verdict.json``;
the harness never decides on its own from the command output.
"""

from __future__ import annotations

import json
from pathlib import Path

from dctest import utc_now
from dctest.config import get_settings
from dctest.models import (
    CaseResult,
    CaseStatus,
    MatrixCell,
    TestCase,
    Verdict,
)
from dctest.prompt_loader import load_preamble, load_stage_prompt
from dctest.services import doctor, executor, run_store, stage_runner
from dctest.services.followup_evidence import (
    CollectedEvidence,
    collect_followup_evidence,
)
from dctest.services.stage_runner import StageInvocation


def render_execute_prompt(
    *,
    run_id: str,
    cell: MatrixCell,
    case: TestCase,
    target_worktree: Path,
) -> str:
    preamble = load_preamble()
    body = load_stage_prompt("execute_case")
    case_dir = run_store.case_dir(get_settings().runs_root, run_id, cell.id, case.id)
    return _render(
        preamble + "\n\n" + body,
        run_id=run_id,
        cell_id=cell.id,
        cell_label=cell.short_label(),
        case_id=case.id,
        case_title=case.title,
        case_surface=case.surface,
        case_command=case.command,
        case_env=json.dumps(case.env_overrides, indent=2),
        case_expected=json.dumps(
            {
                "exit_code": case.expected_exit_code,
                "expected_substrings": case.expected_substrings,
                "must_not_contain": case.must_not_contain,
            },
            indent=2,
        ),
        case_dir=str(case_dir),
        target_worktree=str(target_worktree),
        provider_id=cell.provider.id,
        provider_vendor=cell.provider.vendor,
        provider_model=cell.provider.model,
        provider_endpoint=cell.provider.endpoint or "n/a",
        role=cell.role,
        opa_profile=cell.opa_profile,
        pack_profile=cell.pack_profile,
        fail_mode=cell.fail_mode,
        scan_type=cell.scan_type,
        connector=cell.connector,
    )


def render_classify_prompt(
    *,
    run_id: str,
    cell: MatrixCell,
    case: TestCase,
    stdout_path: Path,
    stderr_path: Path,
    exit_code: int,
    timed_out: bool,
    followup: list[CollectedEvidence] | None = None,
) -> str:
    preamble = load_preamble()
    body = load_stage_prompt("classify_evidence")
    verdict_path = run_store.verdict_path(get_settings().runs_root, run_id, cell.id, case.id)
    return _render(
        preamble + "\n\n" + body,
        run_id=run_id,
        cell_id=cell.id,
        cell_label=cell.short_label(),
        case_id=case.id,
        case_title=case.title,
        case_command=case.command,
        case_expected=json.dumps(
            {
                "exit_code": case.expected_exit_code,
                "expected_substrings": case.expected_substrings,
                "must_not_contain": case.must_not_contain,
            },
            indent=2,
        ),
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
        exit_code=str(exit_code),
        timed_out=str(timed_out),
        verdict_path=str(verdict_path),
        notes_for_agent=case.notes_for_agent or "",
        followup_evidence_block=_render_followup_block(followup or []),
    )


def _render_followup_block(items: list[CollectedEvidence]) -> str:
    """Format the list of collected followup evidence for inclusion in the prompt.

    Empty list -> empty string (the template uses ``{followup_evidence_block}``
    on its own line so we don't add a stray header).
    """
    if not items:
        return ""
    lines = ["", "## Followup evidence"]
    for ev in items:
        status = "OK" if ev.ok else "ATTN"
        lines.append(f"- [{status}] {ev.label} ({ev.kind}) — {ev.summary}")
        if ev.artifact_path:
            lines.append(f"  artifact: {ev.artifact_path}")
    lines.append("")
    return "\n".join(lines)


def _render(template: str, **kw: str) -> str:
    # Plain str.replace, mirroring avarice's policy (so literal `{}` in
    # prose are safe).
    out = template
    for key, val in kw.items():
        out = out.replace("{" + key + "}", val)
    return out


def execute_case(
    *,
    run_id: str,
    cell: MatrixCell,
    case: TestCase,
    target_worktree: Path,
    backend: str = "claude",
) -> CaseResult:
    """Execute a single case end-to-end.

    Steps:
      1. Run the command under test via :mod:`executor`.
      2. Invoke the agent backend with ``classify_evidence.md`` and have it
         write ``verdict.json`` next to the captured stdout/stderr.
      3. Read ``verdict.json`` and assemble a ``CaseResult``.

    The result is also persisted to disk.
    """
    settings = get_settings()
    case_d = run_store.case_dir(settings.runs_root, run_id, cell.id, case.id)
    case_d.mkdir(parents=True, exist_ok=True)

    if case.requires_services:
        statuses = doctor.probe_services(case.requires_services)
        missing = [name for name, ok in statuses.items() if not ok]
        if missing:
            return _short_circuit_skip(
                run_id=run_id,
                cell=cell,
                case=case,
                case_dir=case_d,
                reason=f"service-down:{','.join(missing)}",
            )

    timeout = case.timeout_s or settings.command_timeout_s
    transcript = executor.run_command(
        command=case.command,
        cwd=Path(case.cwd) if case.cwd else target_worktree,
        env_overrides=case.env_overrides,
        out_dir=case_d,
        timeout_s=timeout,
    )

    fixtures_root = settings.harness_root() / "src" / "dctest" / "fixtures"
    followup = collect_followup_evidence(
        case,
        stdout_path=transcript.stdout_path,
        case_dir=case_d,
        fixtures_root=fixtures_root,
    )

    classify_prompt = render_classify_prompt(
        run_id=run_id,
        cell=cell,
        case=case,
        stdout_path=transcript.stdout_path,
        stderr_path=transcript.stderr_path,
        exit_code=transcript.exit_code,
        timed_out=transcript.timed_out,
        followup=followup,
    )
    outcome = stage_runner.run_stage(
        StageInvocation(
            run_id=run_id,
            stage=f"classify/{cell.id}/{case.id}",
            prompt=classify_prompt,
            add_dirs=[case_d],
            backend=backend,  # type: ignore[arg-type]
            capture_output_path=run_store.verdict_path(
                settings.runs_root, run_id, cell.id, case.id
            ),
        )
    )

    verdict_path = run_store.verdict_path(settings.runs_root, run_id, cell.id, case.id)
    verdict_data: dict = {}
    if verdict_path.exists():
        try:
            verdict_data = json.loads(verdict_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            verdict_data = {}
    verdict = Verdict(verdict_data.get("verdict", Verdict.NEEDS_HUMAN.value))
    reasoning = verdict_data.get("reasoning", "")

    result = CaseResult(
        case_id=case.id,
        cell_id=cell.id,
        run_id=run_id,
        started_at=transcript.started_at,
        ended_at=transcript.ended_at,
        exit_code=transcript.exit_code,
        timed_out=transcript.timed_out,
        stdout_path=transcript.stdout_path,
        stderr_path=transcript.stderr_path,
        transcript_path=outcome.transcript.stdout_path,
        verdict=verdict,
        agent_reasoning=reasoning,
        evidence_paths=[verdict_path] if verdict_path.exists() else [],
        status=CaseStatus.CLASSIFIED if verdict_path.exists() else CaseStatus.EXECUTED,
    )
    run_store.save_case_result(settings.runs_root, result)
    return result


def _short_circuit_skip(
    *,
    run_id: str,
    cell: MatrixCell,
    case: TestCase,
    case_dir: Path,
    reason: str,
) -> CaseResult:
    """Emit a honest ``verdict: skip`` without running the command or agent.

    Used when ``requires_services`` declares a dependency the harness can't
    reach. We still write the same artifact triple (stdout/stderr/verdict)
    so downstream report/cluster code treats it uniformly, but the agent is
    never invoked, saving 30-60s per skip and reducing the "blocked from
    harness bug" noise.
    """
    now = utc_now()
    stdout_path = case_dir / "stdout.txt"
    stderr_path = case_dir / "stderr.txt"
    case_dir.mkdir(parents=True, exist_ok=True)
    stdout_path.write_text("", encoding="utf-8")
    stderr_path.write_text(
        f"[dctest] short-circuit skip: prereq not met ({reason})\n",
        encoding="utf-8",
    )

    settings = get_settings()
    verdict_path = run_store.verdict_path(settings.runs_root, run_id, cell.id, case.id)
    verdict_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "verdict": Verdict.SKIP.value,
        "reasoning": f"Required service unavailable: {reason}. Agent skipped.",
        "evidence_refs": [],
        "short_circuit": True,
    }
    verdict_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    result = CaseResult(
        case_id=case.id,
        cell_id=cell.id,
        run_id=run_id,
        started_at=now,
        ended_at=now,
        exit_code=0,
        timed_out=False,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        transcript_path=None,
        verdict=Verdict.SKIP,
        agent_reasoning=payload["reasoning"],
        evidence_paths=[verdict_path],
        status=CaseStatus.SKIPPED,
    )
    run_store.save_case_result(settings.runs_root, result)
    return result


def stage_case_for_manual(
    *,
    run_id: str,
    cell: MatrixCell,
    case: TestCase,
    target_worktree: Path,
) -> Path:
    """Write the per-case prompt to ``staged/<stage>/`` for manual execution.

    Returns the directory containing prompt.txt + manifest.json. The user
    is expected to point an external AI agent at this directory and then
    invoke ``dctest collect``.
    """
    settings = get_settings()
    staged = run_store.staged_dir(settings.runs_root, run_id, f"{cell.id}__{case.id}")
    staged.mkdir(parents=True, exist_ok=True)
    prompt = render_execute_prompt(
        run_id=run_id, cell=cell, case=case, target_worktree=target_worktree
    )
    (staged / "prompt.txt").write_text(prompt, encoding="utf-8")
    manifest = {
        "run_id": run_id,
        "cell_id": cell.id,
        "case_id": case.id,
        "created_at": utc_now().isoformat() + "Z",
        "instructions": (
            "Open prompt.txt in your AI agent. Execute the case it describes. "
            "Write verdict.json to the path printed inside the prompt."
        ),
    }
    (staged / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return staged
