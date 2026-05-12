"""dctest CLI entry point.

Subcommands mirror avarice (intake, run, render, collect, status, report,
score) plus matrix planning, doctor, snapshot, provider, connector. See
``dctest --help`` for the full surface.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from dctest import __version__, utc_now
from dctest.config import get_settings
from dctest.exceptions import DctestError
from dctest.models import RunStatus, Verdict
from dctest.services import (
    case_loader,
    case_runner,
    connector_setup,
    intake,
    provider_setup,
    run_store,
    snapshot,
)
from dctest.services import (
    doctor as doctor_svc,
)
from dctest.services import (
    matrix as matrix_svc,
)
from dctest.services import (
    report as report_svc,
)
from dctest.services import (
    score as score_svc,
)

console = Console()


def _ts_slug() -> str:
    return utc_now().strftime("%Y%m%dT%H%M%SZ")


def _slug_from_path(path: Path) -> str:
    return path.resolve().name.replace(" ", "_") + "-" + _ts_slug()


def cmd_intake(args: argparse.Namespace) -> int:
    worktree = Path(args.worktree_path or ".").resolve()
    slug = args.slug or _slug_from_path(worktree)
    run = intake.create_run(
        slug=slug,
        worktree=worktree,
        backend=args.backend,
        notes=args.notes or "",
    )
    console.print(f"[green]Created run[/green] [bold]{run.slug}[/bold]")
    console.print(f"  target_head_sha = {run.target_head_sha}")
    console.print(f"  worktree        = {run.target_worktree}")
    console.print(f"  backend         = {run.backend}")
    console.print(f"  runs_root       = {get_settings().runs_root}")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    sel = Path(args.selection) if args.selection else None
    report = doctor_svc.run_doctor(sel)
    table = Table(title="dctest doctor", show_lines=False)
    table.add_column("Check")
    table.add_column("OK")
    table.add_column("Detail", overflow="fold")
    for c in report.checks:
        table.add_row(c.name, "yes" if c.ok else "no", c.detail)
    console.print(table)
    return 0 if report.ok else 3


def cmd_matrix_list(args: argparse.Namespace) -> int:
    cells = matrix_svc.expand_matrix(
        filters=args.filter or [],
        required_only=not args.include_optional,
        full_profiles=args.full_profiles,
    )
    if args.json:
        out = [c.model_dump(mode="json") for c in cells]
        print(json.dumps(out, indent=2, default=str))
        return 0
    table = Table(title=f"matrix ({len(cells)} cells)", show_lines=False)
    table.add_column("cell id", overflow="fold")
    table.add_column("connector")
    table.add_column("provider")
    table.add_column("role")
    table.add_column("opa")
    table.add_column("pack")
    table.add_column("fail")
    table.add_column("scan")
    table.add_column("tier")
    for c in cells:
        table.add_row(
            c.id,
            c.connector,
            c.provider.id,
            c.role,
            c.opa_profile,
            c.pack_profile,
            c.fail_mode,
            c.scan_type,
            c.tier.value,
        )
    console.print(table)
    return 0


def cmd_matrix_select(args: argparse.Namespace) -> int:
    cells = matrix_svc.expand_matrix(
        filters=args.filter or [],
        required_only=not args.include_optional,
        full_profiles=args.full_profiles,
    )
    out_path = Path(args.output)
    matrix_svc.serialize_selection(cells, out_path)
    console.print(f"[green]Wrote {len(cells)} cells to[/green] {out_path}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    settings = get_settings()
    run = run_store.load_run(settings.runs_root, args.run_id)
    if args.selection:
        cells = matrix_svc.load_selection(Path(args.selection))
    else:
        existing = run_store.list_cells(settings.runs_root, run.slug)
        cells = existing or matrix_svc.expand_matrix(required_only=True)
    cells = matrix_svc.walk_priority(cells)
    for cell in cells:
        run_store.save_cell(settings.runs_root, run.slug, cell)
    run_store.update_run_status(settings.runs_root, run.slug, RunStatus.EXECUTING)

    all_cases = case_loader.load_all_cases()
    case_filter = args.cases
    cases = case_loader.filter_cases(all_cases, glob=case_filter)
    if args.surface:
        cases = case_loader.filter_cases(cases, surface=args.surface)
    if args.exclude_cases:
        import fnmatch as _fn

        patterns = [p.strip() for p in args.exclude_cases.split(",") if p.strip()]
        cases = [
            c for c in cases
            if not any(_fn.fnmatchcase(c.id, pat) for pat in patterns)
        ]

    backend = args.backend or run.backend
    target = Path(run.target_worktree)

    # Build the (cell, case) work list once. Filters applied here keep the
    # parallel path simple — each unit is independent and doesn't need to
    # consult the others.
    work: list[tuple[Any, Any]] = []
    for cell in cells:
        for case in cases:
            if (
                case.requires_provider_kind
                and cell.provider.vendor not in case.requires_provider_kind
            ):
                continue
            if case.requires_role and cell.role not in case.requires_role:
                continue
            verdict_path = run_store.verdict_path(
                settings.runs_root, run.slug, cell.id, case.id
            )
            if verdict_path.exists() and not args.no_skip:
                continue
            work.append((cell, case))

    if args.max_cases and len(work) > args.max_cases:
        console.print(f"[yellow]limiting to first {args.max_cases} of {len(work)} cases[/yellow]")
        work = work[: args.max_cases]

    jobs = max(1, int(getattr(args, "jobs", 1) or 1))
    if backend == "manual" or jobs == 1:
        for cell, case in work:
            _run_one(run, target, cell, case, backend)
    else:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        console.print(
            f"[bold]Parallel run:[/bold] {len(work)} cases x {jobs} workers ({backend})"
        )
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            futures = {
                pool.submit(_run_one, run, target, cell, case, backend): (cell.id, case.id)
                for cell, case in work
            }
            for fut in as_completed(futures):
                cell_id, case_id = futures[fut]
                try:
                    fut.result()
                except DctestError as e:
                    console.print(f"  [red]error[/red] {cell_id} :: {case_id} :: {e}")
                except Exception as e:  # noqa: BLE001 - surface unexpected errors per-case
                    console.print(
                        f"  [red]unexpected error[/red] {cell_id} :: {case_id} :: {type(e).__name__}: {e}"
                    )
    run_store.update_run_status(settings.runs_root, run.slug, RunStatus.COMPLETED)
    return 0


def _run_one(run, target_worktree, cell, case, backend) -> None:
    """Execute a single (cell, case) pair with per-case locking.

    The lock file prevents a parallel worker from racing the
    "skip if verdict.json exists" check. A second worker landing on the
    same case will see the lock, skip silently, and let the holder finish.
    """
    settings = get_settings()
    case_d = run_store.case_dir(settings.runs_root, run.slug, cell.id, case.id)
    case_d.mkdir(parents=True, exist_ok=True)
    lock_path = case_d / ".lock"

    # Best-effort exclusive lock via O_EXCL. If we can't grab it, another
    # worker is already running this case; bail.
    try:
        fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        os.close(fd)
    except FileExistsError:
        return

    try:
        verdict_path = run_store.verdict_path(
            settings.runs_root, run.slug, cell.id, case.id
        )
        if verdict_path.exists():
            return
        console.print(f"[cyan]{cell.id}[/cyan] :: [bold]{case.id}[/bold]")
        if backend == "manual":
            staged = case_runner.stage_case_for_manual(
                run_id=run.slug,
                cell=cell,
                case=case,
                target_worktree=target_worktree,
            )
            console.print(f"  staged at [yellow]{staged}[/yellow]")
            return
        result = case_runner.execute_case(
            run_id=run.slug,
            cell=cell,
            case=case,
            target_worktree=target_worktree,
            backend=backend,
        )
        console.print(
            f"  verdict=[bold]{result.verdict.value}[/bold] "
            f"exit={result.exit_code} timed_out={result.timed_out}"
        )
    finally:
        with contextlib.suppress(FileNotFoundError):
            lock_path.unlink()


def cmd_render(args: argparse.Namespace) -> int:
    settings = get_settings()
    run = run_store.load_run(settings.runs_root, args.run_id)
    cell = run_store.load_cell(settings.runs_root, run.slug, args.cell)
    case = case_loader.get_case(args.case)
    staged = case_runner.stage_case_for_manual(
        run_id=run.slug,
        cell=cell,
        case=case,
        target_worktree=Path(run.target_worktree),
    )
    console.print(f"[green]staged[/green] {staged}")
    return 0


def cmd_collect(args: argparse.Namespace) -> int:
    settings = get_settings()
    run = run_store.load_run(settings.runs_root, args.run_id)
    cells = run_store.list_cells(settings.runs_root, run.slug)
    collected = 0
    for cell in cells:
        case_root = run_store.cell_dir(settings.runs_root, run.slug, cell.id) / "cases"
        if not case_root.exists():
            continue
        for case_dir in sorted(case_root.iterdir()):
            verdict_path = case_dir / "verdict.json"
            result_path = case_dir / "result.json"
            if verdict_path.exists() and not result_path.exists():
                # Build a minimal result from verdict.json + transcript on disk
                try:
                    data = json.loads(verdict_path.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    continue
                tx_path = case_dir / "transcript.json"
                started, ended = utc_now(), utc_now()
                exit_code = 0
                timed_out = False
                if tx_path.exists():
                    try:
                        tx_data = json.loads(tx_path.read_text(encoding="utf-8"))
                        started = datetime.fromisoformat(tx_data["started_at"])
                        ended = datetime.fromisoformat(tx_data["ended_at"])
                        exit_code = int(tx_data.get("exit_code", 0))
                        timed_out = bool(tx_data.get("timed_out", False))
                    except Exception:  # noqa: BLE001
                        pass
                from dctest.models import CaseResult, CaseStatus

                result = CaseResult(
                    case_id=case_dir.name,
                    cell_id=cell.id,
                    run_id=run.slug,
                    started_at=started,
                    ended_at=ended,
                    exit_code=exit_code,
                    timed_out=timed_out,
                    stdout_path=case_dir / "stdout.txt",
                    stderr_path=case_dir / "stderr.txt",
                    transcript_path=None,
                    verdict=Verdict(data.get("verdict", Verdict.NEEDS_HUMAN.value)),
                    agent_reasoning=data.get("reasoning", ""),
                    evidence_paths=[verdict_path],
                    status=CaseStatus.CLASSIFIED,
                )
                run_store.save_case_result(settings.runs_root, result)
                collected += 1
    console.print(f"[green]Collected {collected} new verdicts[/green]")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    settings = get_settings()
    run = run_store.load_run(settings.runs_root, args.run_id)
    cells = run_store.list_cells(settings.runs_root, run.slug)
    summary = score_svc.build_summary(run.slug)
    table = Table(title=f"run {run.slug} ({run.status.value})")
    table.add_column("Verdict")
    table.add_column("Count")
    for v in Verdict:
        table.add_row(v.value, str(summary.by_verdict.get(v, 0)))
    console.print(table)
    console.print(f"cells: {summary.total_cells}, cases: {summary.total_cases}")
    if summary.failing_required_cells:
        console.print(
            f"[red]failing_required:[/red] {', '.join(summary.failing_required_cells)}"
        )
    if summary.needs_human_cases:
        console.print(f"[yellow]needs_human:[/yellow] {len(summary.needs_human_cases)} case(s)")
    _ = cells  # currently unused; placeholder for future cell-tier filtering
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    score_svc.build_summary(args.run_id)
    path = report_svc.build_report(args.run_id)
    console.print(f"[green]Wrote[/green] {path}")
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    summary = score_svc.build_summary(args.run_id)
    code = score_svc.exit_code_for_summary(summary)
    if code == 0:
        console.print(f"[green]PASS[/green] (run={args.run_id})")
    else:
        console.print(f"[red]FAIL[/red] exit_code={code}")
        if summary.failing_required_cells:
            console.print(f"  failing required cells: {summary.failing_required_cells}")
        if summary.needs_human_cases:
            console.print(f"  cases awaiting human: {len(summary.needs_human_cases)}")
    return code


def cmd_snapshot_create(args: argparse.Namespace) -> int:
    path = snapshot.create_snapshot(args.run_id, args.label, extra_paths=args.extra)
    console.print(f"[green]Wrote[/green] {path}")
    return 0


def cmd_snapshot_restore(args: argparse.Namespace) -> int:
    written = snapshot.restore_snapshot(args.run_id, args.label, dry_run=args.dry_run)
    verb = "would restore" if args.dry_run else "restored"
    console.print(f"[green]{verb}[/green] {len(written)} paths")
    for p in written[:50]:
        console.print(f"  {p}")
    if len(written) > 50:
        console.print(f"  ... and {len(written) - 50} more")
    return 0


def cmd_snapshot_list(args: argparse.Namespace) -> int:
    for p in snapshot.list_snapshots(args.run_id):
        console.print(str(p))
    return 0


def cmd_provider_plan(args: argparse.Namespace) -> int:
    providers = matrix_svc.load_providers()
    by_id = {p.id: p for p in providers}
    if args.provider_id not in by_id:
        console.print(f"[red]unknown provider id:[/red] {args.provider_id}")
        return 2
    judge = by_id.get(args.judge_provider_id) if args.judge_provider_id else None
    plan = provider_setup.plan_provider_switch(
        role=args.role,
        provider=by_id[args.provider_id],
        judge_provider=judge,
    )
    console.print(f"[bold]Provider switch plan[/bold] (role={plan.role})")
    console.print(f"  required_env: {plan.required_env}")
    console.print(f"  notes: {plan.notes}")
    console.print("[bold]shell:[/bold]")
    for line in plan.shell_lines:
        console.print(f"  $ {line}")
    return 0


def cmd_cluster(args: argparse.Namespace) -> int:
    from dctest.services import cluster as cluster_svc

    clusters = cluster_svc.cluster_run(args.run_id)
    if not clusters:
        console.print("[green]no failures clustered[/green]")
        return 0
    cluster_svc.save_clusters(args.run_id, clusters)
    if args.json:
        out = [c.to_summary().model_dump() for c in clusters]
        print(json.dumps(out, indent=2, default=str))
        return 0
    table = Table(title=f"Root-cause clusters ({len(clusters)} total)")
    table.add_column("#")
    table.add_column("tag")
    table.add_column("exit")
    table.add_column("members")
    table.add_column("sample", overflow="fold")
    for idx, c in enumerate(clusters, 1):
        tag = "tracked" if c.all_expected else "new"
        table.add_row(
            str(idx),
            tag,
            str(c.exit_code),
            str(len(c.members)),
            c.sample_line[:160] or "(no stderr)",
        )
    console.print(table)
    return 0


def cmd_findings(args: argparse.Namespace) -> int:
    from dctest.services import findings as findings_svc

    paths = findings_svc.emit_findings(args.run_id)
    if not paths:
        console.print("[green]no NEW failures to file[/green]")
        return 0
    console.print(f"[green]wrote {len(paths)} finding(s)[/green]")
    for p in paths[:50]:
        console.print(f"  {p}")
    if len(paths) > 50:
        console.print(f"  ... and {len(paths) - 50} more")
    return 0


def cmd_registry_build(args: argparse.Namespace) -> int:
    from dctest.services import cli_registry

    binaries = args.binaries.split(",") if args.binaries else None
    registry = cli_registry.build_registry(binaries=binaries)
    out_path = Path(args.output) if args.output else get_settings().runs_root / "cli_registry.json"
    cli_registry.save_registry(registry, out_path)
    console.print(f"[green]Wrote registry for {len(registry)} binaries:[/green] {out_path}")
    for name, node in registry.items():
        console.print(
            f"  {name}: {len(node.flags)} top-level flags, "
            f"{len(node.subcommands)} subcommands"
        )
    return 0


def cmd_lint_cases(args: argparse.Namespace) -> int:
    from dctest.services import cli_registry as cli_registry_svc
    from dctest.services.case_linter import LintCode, lint_cases

    registry_path = (
        Path(args.registry)
        if args.registry
        else get_settings().runs_root / "cli_registry.json"
    )
    registry = cli_registry_svc.load_registry(registry_path)
    if not registry:
        console.print(
            f"[yellow]No registry at {registry_path}; "
            "run `dctest registry build` first.[/yellow]"
        )
        return 2

    cases = case_loader.load_all_cases()
    if args.cases:
        cases = case_loader.filter_cases(cases, glob=args.cases)
    if args.surface:
        cases = case_loader.filter_cases(cases, surface=args.surface)

    report = lint_cases(cases, registry)

    if args.json:
        out = {
            "total_cases": len(cases),
            "unexpected": [
                {"case_id": f.case_id, "code": f.code.value, "message": f.message}
                for f in report.unexpected
            ],
            "expected": [
                {"case_id": f.case_id, "code": f.code.value, "message": f.message}
                for f in report.expected
            ],
        }
        print(json.dumps(out, indent=2))
        return 0 if report.ok or not args.strict else 5

    counts: dict[str, int] = {}
    for f in report.findings:
        counts[f.code.value] = counts.get(f.code.value, 0) + 1
    console.print(f"[bold]Linted {len(cases)} cases[/bold]")
    console.print(
        f"  unexpected findings: {len(report.unexpected)}"
        f"   expected (tracked) findings: {len(report.expected)}"
    )
    for code in LintCode:
        c = counts.get(code.value, 0)
        if c:
            console.print(f"    {code.value}: {c}")

    if report.unexpected:
        table = Table(
            title="Unexpected lint findings",
            show_lines=False,
        )
        table.add_column("Case", overflow="fold")
        table.add_column("Code")
        table.add_column("Message", overflow="fold")
        for f in report.unexpected[:200]:
            table.add_row(f.case_id, f.code.value, f.message)
        console.print(table)
        if len(report.unexpected) > 200:
            console.print(
                f"... and {len(report.unexpected) - 200} more (rerun with --json for full list)"
            )

    if args.strict and report.unexpected:
        return 5
    return 0


def cmd_ci(args: argparse.Namespace) -> int:
    """One-command flow: intake -> doctor -> run -> cluster -> findings -> score.

    Each sub-step is a normal dctest command; ``ci`` chains them with sane
    defaults so a reviewer can run ``dctest ci --jobs 4`` and get a
    GitHub-issue-quality artifact at the end. Exit code is 0 only when
    every required cell passed and there are no unexpected fails.
    """
    import time

    from dctest.services import findings as findings_svc

    settings = get_settings()
    started_at = time.monotonic()
    deadline: float | None = None
    if args.max_runtime:
        try:
            deadline = started_at + _parse_duration(args.max_runtime)
        except ValueError as exc:
            console.print(f"[red]bad --max-runtime: {exc}[/red]")
            return 2

    slug = args.slug or "ci-" + _ts_slug()
    worktree = Path(args.worktree_path or ".").resolve()
    run = intake.create_run(
        slug=slug,
        worktree=worktree,
        backend=args.backend or "codex",
        notes=args.notes or "dctest ci automated run",
    )
    console.print(f"[bold]Created run[/bold] {run.slug}")

    sel_path: Path | None = None
    if args.selection:
        sel_path = Path(args.selection)
    elif args.connector:
        sel_path = settings.runs_root / run.slug / "selection.yaml"
        cells = matrix_svc.expand_matrix(
            filters=[f"connector={args.connector}"],
            required_only=True,
        )
        matrix_svc.serialize_selection(cells, sel_path)

    doctor_report = doctor_svc.run_doctor(sel_path)
    if not doctor_report.ok:
        console.print("[yellow]doctor reported failures (continuing):[/yellow]")
        for c in doctor_report.checks:
            if not c.ok:
                console.print(f"  - {c.name}")

    if deadline is not None and time.monotonic() > deadline:
        console.print("[red]ci budget exhausted before run[/red]")
        return 6

    run_argv = argparse.Namespace(
        run_id=run.slug,
        selection=str(sel_path) if sel_path else None,
        cases=None,
        exclude_cases=None,
        surface=None,
        backend=run.backend,
        no_skip=False,
        max_cases=None,
        jobs=args.jobs,
        resume=False,
    )
    rc = cmd_run(run_argv)
    if rc != 0:
        console.print(f"[red]dctest run exited {rc}[/red]")

    try:
        clusters = (
            __import__("dctest.services.cluster", fromlist=["cluster_run"]).cluster_run(run.slug)
        )
        __import__("dctest.services.cluster", fromlist=["save_clusters"]).save_clusters(
            run.slug, clusters
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]cluster failed: {exc}[/red]")

    try:
        findings_svc.emit_findings(run.slug)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]findings failed: {exc}[/red]")

    try:
        report_path = report_svc.build_report(run.slug)
        console.print(f"  report: {report_path}")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]report failed: {exc}[/red]")

    summary = score_svc.build_summary(run.slug)
    code = score_svc.exit_code_for_summary(summary)
    elapsed = time.monotonic() - started_at
    console.print(
        f"[bold]ci done[/bold] in {elapsed:.0f}s. exit={code} run_id={run.slug}"
    )
    return code


def _parse_duration(s: str) -> float:
    """Parse ``30s``, ``5m``, ``2h`` (or bare seconds) into seconds."""
    s = s.strip().lower()
    if s.endswith("s"):
        return float(s[:-1])
    if s.endswith("m"):
        return float(s[:-1]) * 60
    if s.endswith("h"):
        return float(s[:-1]) * 3600
    return float(s)


def cmd_connector_plan(args: argparse.Namespace) -> int:
    plan = connector_setup.plan_connector_setup(args.connector)
    console.print(f"[bold]Connector setup plan[/bold] ({plan.connector})")
    console.print("[bold]setup:[/bold]")
    for line in plan.setup_lines:
        console.print(f"  $ {line}")
    console.print("[bold]verify:[/bold]")
    for line in plan.verify_lines:
        console.print(f"  $ {line}")
    console.print("[bold]teardown:[/bold]")
    for line in plan.teardown_lines:
        console.print(f"  $ {line}")
    console.print(f"  notes: {plan.notes}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dctest",
        description="DefenseClaw manual testing harness.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_intake = sub.add_parser("intake", help="Create a new run from a worktree.")
    p_intake.add_argument("--worktree-path", default=".")
    p_intake.add_argument("--slug")
    p_intake.add_argument("--backend", choices=("claude", "codex", "manual"))
    p_intake.add_argument("--notes")
    p_intake.set_defaults(func=cmd_intake)

    p_doctor = sub.add_parser("doctor", help="Run prerequisite checks.")
    p_doctor.add_argument("--selection", help="Path to a selection YAML.")
    p_doctor.set_defaults(func=cmd_doctor)

    p_matrix = sub.add_parser("matrix", help="Matrix planning.")
    m_sub = p_matrix.add_subparsers(dest="matrix_cmd", required=True)
    p_ml = m_sub.add_parser("list", help="Print expanded matrix.")
    p_ml.add_argument("--filter", action="append")
    p_ml.add_argument("--include-optional", action="store_true")
    p_ml.add_argument("--full-profiles", action="store_true")
    p_ml.add_argument("--json", action="store_true")
    p_ml.set_defaults(func=cmd_matrix_list)
    p_ms = m_sub.add_parser("select", help="Serialize a selection to YAML.")
    p_ms.add_argument("--output", required=True)
    p_ms.add_argument("--filter", action="append")
    p_ms.add_argument("--include-optional", action="store_true")
    p_ms.add_argument("--full-profiles", action="store_true")
    p_ms.set_defaults(func=cmd_matrix_select)

    p_run = sub.add_parser("run", help="Execute cases against materialized cells.")
    p_run.add_argument("run_id")
    p_run.add_argument("--selection")
    p_run.add_argument("--cases", help="Glob over case ids.")
    p_run.add_argument(
        "--exclude-cases",
        help="Comma-separated globs of case ids to exclude after --cases/--surface filter.",
    )
    p_run.add_argument("--surface")
    p_run.add_argument("--backend", choices=("claude", "codex", "manual"))
    p_run.add_argument("--no-skip", action="store_true")
    p_run.add_argument("--max-cases", type=int)
    p_run.add_argument(
        "--jobs",
        type=int,
        default=1,
        help=(
            "Number of cases to execute in parallel (ThreadPoolExecutor). "
            "Each case gets its own subprocess for the command and the agent, "
            "so 4-8 is usually safe. Defaults to 1 (sequential)."
        ),
    )
    p_run.add_argument(
        "--resume",
        action="store_true",
        help=(
            "Resume an interrupted run by walking only cases that don't yet "
            "have a verdict.json. Implies --no-skip=False."
        ),
    )
    p_run.set_defaults(func=cmd_run)

    p_render = sub.add_parser("render", help="Stage a case prompt for manual execution.")
    p_render.add_argument("run_id")
    p_render.add_argument("--cell", required=True)
    p_render.add_argument("--case", required=True)
    p_render.set_defaults(func=cmd_render)

    p_collect = sub.add_parser("collect", help="Ingest verdicts written by an external agent.")
    p_collect.add_argument("run_id")
    p_collect.set_defaults(func=cmd_collect)

    p_status = sub.add_parser("status", help="Show run status counts.")
    p_status.add_argument("run_id")
    p_status.set_defaults(func=cmd_status)

    p_report = sub.add_parser("report", help="Build the markdown report for a run.")
    p_report.add_argument("run_id")
    p_report.set_defaults(func=cmd_report)

    p_score = sub.add_parser("score", help="Exit non-zero if any required cell failed.")
    p_score.add_argument("run_id")
    p_score.set_defaults(func=cmd_score)

    p_snap = sub.add_parser("snapshot", help="Snapshot host state.")
    s_sub = p_snap.add_subparsers(dest="snapshot_cmd", required=True)
    p_sc = s_sub.add_parser("create")
    p_sc.add_argument("run_id")
    p_sc.add_argument("label")
    p_sc.add_argument("--extra", nargs="*")
    p_sc.set_defaults(func=cmd_snapshot_create)
    p_sr = s_sub.add_parser("restore")
    p_sr.add_argument("run_id")
    p_sr.add_argument("label")
    p_sr.add_argument("--dry-run", action="store_true")
    p_sr.set_defaults(func=cmd_snapshot_restore)
    p_sl = s_sub.add_parser("list")
    p_sl.add_argument("run_id")
    p_sl.set_defaults(func=cmd_snapshot_list)

    p_prov = sub.add_parser("provider", help="Provider planning (prints a shell plan).")
    pr_sub = p_prov.add_subparsers(dest="provider_cmd", required=True)
    p_pp = pr_sub.add_parser("plan")
    p_pp.add_argument("provider_id")
    p_pp.add_argument("--role", default="guardrail-only")
    p_pp.add_argument("--judge-provider-id")
    p_pp.set_defaults(func=cmd_provider_plan)

    p_cluster = sub.add_parser(
        "cluster",
        help="Group failed cases by normalized stderr fingerprint.",
    )
    p_cluster.add_argument("run_id")
    p_cluster.add_argument("--json", action="store_true")
    p_cluster.set_defaults(func=cmd_cluster)

    p_find = sub.add_parser(
        "findings",
        help=(
            "Emit one Markdown finding file per unexpected fail, suitable "
            "for filing as a GitHub issue."
        ),
    )
    p_find.add_argument("run_id")
    p_find.set_defaults(func=cmd_findings)

    p_reg = sub.add_parser("registry", help="CLI surface registry (build / inspect).")
    r_sub = p_reg.add_subparsers(dest="registry_cmd", required=True)
    p_rb = r_sub.add_parser(
        "build",
        help=(
            "Run --help recursively on the configured binaries and persist a "
            "tree of subcommands/flags as JSON."
        ),
    )
    p_rb.add_argument(
        "--binaries",
        help="Comma-separated list of binaries to introspect (overrides defaults).",
    )
    p_rb.add_argument(
        "--output",
        help="Output JSON path; defaults to <runs_root>/cli_registry.json.",
    )
    p_rb.set_defaults(func=cmd_registry_build)

    p_lint = sub.add_parser(
        "lint-cases",
        help="Validate each TestCase.command against the CLI registry.",
    )
    p_lint.add_argument(
        "--registry",
        help="Path to a previously built registry JSON. Defaults to <runs_root>/cli_registry.json.",
    )
    p_lint.add_argument("--cases", help="Glob over case ids.")
    p_lint.add_argument("--surface")
    p_lint.add_argument("--json", action="store_true")
    p_lint.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero if any unexpected lint finding is reported.",
    )
    p_lint.set_defaults(func=cmd_lint_cases)

    p_ci = sub.add_parser(
        "ci",
        help=(
            "Mega-command: intake → doctor → run --jobs N → cluster → "
            "findings → report → score. Produces a single GitHub-ready "
            "artifact."
        ),
    )
    p_ci.add_argument("--slug", help="Optional slug; defaults to ci-<utc-stamp>.")
    p_ci.add_argument("--worktree-path", default=".")
    p_ci.add_argument(
        "--backend", choices=("claude", "codex", "manual"), default="codex"
    )
    p_ci.add_argument(
        "--connector",
        help="Build a single-cell selection pinned to this connector (e.g. 'claudecode').",
    )
    p_ci.add_argument(
        "--selection",
        help="Explicit selection YAML path; overrides --connector.",
    )
    p_ci.add_argument("--jobs", type=int, default=4)
    p_ci.add_argument(
        "--max-runtime",
        help="Soft budget like '60m', '2h', or bare seconds. Diagnostic only.",
    )
    p_ci.add_argument("--notes", default="")
    p_ci.set_defaults(func=cmd_ci)

    p_con = sub.add_parser("connector", help="Connector planning (prints a shell plan).")
    c_sub = p_con.add_subparsers(dest="connector_cmd", required=True)
    p_cp = c_sub.add_parser("plan")
    p_cp.add_argument("connector")
    p_cp.set_defaults(func=cmd_connector_plan)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except DctestError as e:
        console.print(f"[red]dctest error:[/red] {e}")
        return 4
    except KeyboardInterrupt:
        console.print("[yellow]interrupted[/yellow]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
