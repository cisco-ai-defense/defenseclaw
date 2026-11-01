# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Contract for the performance harness (scripts/perf/dcperf.py) and its
budget gate (scripts/perf/budgets.json)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("dcperf", ROOT / "scripts" / "perf" / "dcperf.py")
assert SPEC and SPEC.loader
dcperf = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dcperf)

BUDGETS = json.loads((ROOT / "scripts" / "perf" / "budgets.json").read_text(encoding="utf-8"))


def _budgets(entries: dict, tolerance: float = 0.20) -> dict:
    return {"tolerance": tolerance, "columns": {"c": entries}}


def _result(**metrics) -> dict:
    return {"metrics": metrics}


def test_percentile_interpolates_and_summary_reports_p50_p95_max() -> None:
    values = [float(v) for v in range(1, 101)]
    assert dcperf.percentile(values, 50) == 50.5
    assert round(dcperf.percentile(values, 95), 2) == 95.05
    summary = dcperf.summarize(values)
    assert (summary["n"], summary["p50_ms"], summary["max_ms"], summary["min_ms"]) == (100, 50.5, 100.0, 1.0)
    assert 95.0 <= summary["p95_ms"] <= 95.1


def test_a_metric_over_budget_by_more_than_the_tolerance_fails_the_gate() -> None:
    budgets = _budgets({"hook.claudecode.idle.p50_ms": {"budget": 100}})
    within = dcperf.compare(_result(hook={"claudecode": {"idle": {"p50_ms": 120.0}}}), budgets, "c")
    over = dcperf.compare(_result(hook={"claudecode": {"idle": {"p50_ms": 120.5}}}), budgets, "c")
    assert within["ok"] and within["rows"][0]["status"] == "ok"
    assert not over["ok"] and over["rows"][0]["status"] == "regression"
    assert "FAIL" in dcperf.compare_text(over)


def test_a_gated_metric_that_was_not_measured_fails_the_gate() -> None:
    report = dcperf.compare(_result(), _budgets({"cli.status.p50_ms": {"budget": 1000}}), "c")
    assert not report["ok"]
    assert report["rows"][0]["status"] == "missing"


def test_todo_and_ungated_budgets_are_reported_but_never_fail() -> None:
    budgets = _budgets(
        {
            "hook.codex.burst.p95_ms": {"budget": "TODO"},
            "hook.codex.idle.max_ms": {"budget": 10, "gate": False},
        }
    )
    report = dcperf.compare(_result(hook={"codex": {"idle": {"max_ms": 999.0}}}), budgets, "c")
    assert report["ok"]
    assert {row["status"] for row in report["rows"]} == {"todo", "info"}


def test_a_benign_call_that_is_not_allowed_fails_a_zero_budget() -> None:
    budgets = _budgets({"hook.claudecode.burst.not_allowed": {"budget": 0}})
    report = dcperf.compare(_result(hook={"claudecode": {"burst": {"not_allowed": 1}}}), budgets, "c")
    assert not report["ok"]


def test_strace_parser_joins_interrupted_calls_and_skips_threads_and_failed_execs() -> None:
    log = "\n".join(
        [
            '100 execve("/bin/sh", ["sh", "-c", "hook"], 0x0 /* 3 vars */) = 0',
            "100 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD <unfinished ...>",
            '101 execve("/usr/local/bin/jq", ["jq"], 0x0 /* 3 vars */) = -1 ENOENT (No such file or directory)',
            "100 <... clone resumed>) = 101",
            '101 execve("/usr/bin/jq", ["jq"], 0x0 /* 3 vars */ <unfinished ...>',
            "101 <... execve resumed>) = 0",
            "101 clone(child_stack=0x7f, flags=CLONE_VM|CLONE_FS|CLONE_THREAD|CLONE_SYSVSEM) = 102",
            "100 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD) = 103",
        ]
    )
    parsed = dcperf.parse_strace(log)
    assert parsed["execs"] == [("sh", ""), ("jq", "sh")]
    assert parsed["forks"] == ["sh", "sh"]


def test_the_registered_claude_code_and_codex_hook_commands_are_the_ones_measured(tmp_path: Path) -> None:
    inst = dcperf.Install(tmp_path)
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {"hooks": [{"type": "command", "command": "/opt/other-hook.sh"}]},
                        {"hooks": [{"type": "command", "command": f"{inst.dc}/hooks/claude-code-hook.sh || exit 2"}]},
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "config.toml").write_text(
        "[[hooks.PreToolUse]]\nmatcher = '*'\n\n[[hooks.PreToolUse.hooks]]\n"
        f"command = '{inst.dc}/hooks/codex-hook.sh --event PreToolUse'\ntype = 'command'\n",
        encoding="utf-8",
    )
    assert dcperf.registered_hook(inst, "claudecode") == f"{inst.dc}/hooks/claude-code-hook.sh || exit 2"
    assert dcperf.registered_hook(inst, "codex") == f"{inst.dc}/hooks/codex-hook.sh --event PreToolUse"


def test_the_gateway_port_is_read_from_the_gateway_section(tmp_path: Path) -> None:
    inst = dcperf.Install(tmp_path)
    inst.dc.mkdir()
    (inst.dc / "config.yaml").write_text(
        "judge:\n  api_port: 1\ngateway:\n  host: 127.0.0.1\n  api_port: 40123\n", encoding="utf-8"
    )
    assert inst.api_port() == 40123


def test_every_gated_linux_budget_has_a_source_and_names_a_metric_the_harness_writes() -> None:
    hook = {
        "idle": {"p50_ms": 1, "p95_ms": 1, "max_ms": 1, "min_ms": 1, "n": 1, "not_allowed": 0},
        "burst": {"p50_ms": 1, "p95_ms": 1, "max_ms": 1, "min_ms": 1, "n": 1, "not_allowed": 0, "width": 32},
    }
    cli = {"p50_ms": 1, "p95_ms": 1, "max_ms": 1, "min_ms": 1, "n": 1}
    produced = dcperf.flatten(
        _result(
            hook={"claudecode": hook, "codex": hook},
            hook_execs={
                "claudecode": {"per_call_p50": 9, "per_call_max": 9, "processes_per_call_p50": 14, "calls": 10},
                "codex": {"per_call_p50": 9, "per_call_max": 9, "processes_per_call_p50": 14, "calls": 10},
            },
            cli={name: cli for name in ("status", "doctor", "setup_claudecode", "skill_scan")},
            gateway_restart={"to_api_ready": cli, "command": cli},
            gateway_rss_kb={"after_idle": 1, "idle_s": 300, "audit_db_kb": 1, "anon_kb": 1, "file_kb": 1},
        )
    )
    column = BUDGETS["columns"]["linux-per-user"]
    assert BUDGETS["tolerance"] == 0.20
    for metric, entry in column.items():
        assert metric in produced, metric
        assert entry.get("source"), metric


def test_ci_runs_the_perf_budget_on_every_pull_request_that_builds_the_install_assets() -> None:
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    job = workflow["jobs"]["perf-budget"]
    assert job["needs"] == "install-smoke-assets"
    assert job["runs-on"] == "ubuntu-latest"
    run = "\n".join(step.get("run", "") for step in job["steps"])
    assert "scripts/perf/dcperf.py provision" in run
    assert "--budgets scripts/perf/budgets.json --column linux-per-user" in run


def test_only_takes_known_measurement_groups() -> None:
    assert dcperf._groups("hook, execs") == ("hook", "execs")
    for bad in ("hook,bogus", " , "):
        try:
            dcperf._groups(bad)
        except SystemExit as exc:
            assert "--only" in str(exc)
        else:
            raise AssertionError(f"{bad!r} was accepted")


def test_every_ungated_budget_other_than_a_max_says_why() -> None:
    for column, entries in BUDGETS["columns"].items():
        for metric, entry in entries.items():
            if entry.get("gate") is False and not metric.endswith(".max_ms"):
                assert entry.get("why"), f"{column} {metric}"
