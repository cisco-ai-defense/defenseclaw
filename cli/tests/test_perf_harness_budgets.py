# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Contract for the performance harness (scripts/perf/dcperf.py) and its
budget gate (scripts/perf/budgets.json)."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
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


def _es(kind: str, seq: int, at: str, pid: int, ppid: int, path: str = "") -> str:
    if kind == "exec":
        body = {
            "exec": {"target": {"audit_token": {"pid": pid}, "ppid": ppid, "executable": {"path": path}}, "args": []}
        }
        event_type = 9
    else:
        body = {"fork": {"child": {"audit_token": {"pid": pid}, "ppid": ppid}}}
        event_type = 11
    return json.dumps({"event_type": event_type, "seq_num": seq, "time": f"2026-11-01T08:00:{at}Z", "event": body})


def _eslogger_log(runner: int, gateway: int, call2_execs: tuple[int, int], listing_exec_seq: int = 5) -> list[str]:
    return [
        # call 1, 01.0-01.2: sh (bash), a hook script fork that runs jq; an unrelated exec
        _es("fork", 1, "01.000000001", 101, runner),
        _es("exec", 1, "01.000000002", 101, runner, "/bin/sh"),
        _es("exec", 2, "01.000000003", 101, runner, "/bin/bash"),
        _es("fork", 2, "01.050000000", 102, 101),
        _es("exec", 3, "01.050000001", 102, 101, "/usr/bin/jq"),
        _es("exec", 4, "01.060000000", 777, 1, "/usr/bin/true"),
        # between the calls: the gateway's listing, dscl and its watchdog shell
        _es("fork", 3, "01.600000000", 901, gateway),
        _es("exec", listing_exec_seq, "01.600000001", 901, gateway, "/usr/bin/dscl"),
        _es("fork", 4, "01.600000002", 902, gateway),
        _es("exec", listing_exec_seq + 1, "01.600000003", 902, gateway, "/bin/sh"),
        # call 2, 02.0-02.2
        _es("fork", 5, "02.000000001", 103, runner),
        _es("exec", call2_execs[0], "02.000000002", 103, runner, "/bin/sh"),
        _es("exec", call2_execs[1], "02.000000003", 103, runner, "/bin/bash"),
        "{not json",
    ]


def _eslogger_windows() -> list[tuple[float, float]]:
    t = dcperf.eslogger_time
    return [
        (t("2026-11-01T08:00:01.000000000Z"), t("2026-11-01T08:00:01.200000000Z")),
        (t("2026-11-01T08:00:02.000000000Z"), t("2026-11-01T08:00:02.200000000Z")),
    ]


def test_eslogger_parser_counts_each_calls_tree_and_the_gateways_execs() -> None:
    t = dcperf.eslogger_time
    assert t("2026-11-01T08:00:01.500000000Z") - t("2026-11-01T08:00:00.000000000Z") == 1.5
    parsed = dcperf.parse_eslogger(_eslogger_log(50, 900, (7, 8)), _eslogger_windows(), 50, 900)
    assert (parsed["calls"], parsed["calls_dropped"]) == (2, 0)
    assert (parsed["per_call_p50"], parsed["processes_per_call_p50"]) == (2.5, 1.5)
    assert parsed["by_program"] == {"bash": 1.0, "sh": 1.0, "jq": 0.5}
    assert parsed["gateway_events_dropped"] == 0
    assert parsed["gateway_by_program"] == {"dscl": 1, "sh": 1}
    assert parsed["gateway_execs_per_call"] == 1.0


def test_a_dropped_event_in_a_call_drops_the_call_and_the_gateway_count() -> None:
    # call 2's exec events skip seq 7 and 9
    parsed = dcperf.parse_eslogger(_eslogger_log(50, 900, (8, 10)), _eslogger_windows(), 50, 900)
    assert (parsed["calls"], parsed["calls_dropped"]) == (1, 1)
    assert (parsed["per_call_p50"], parsed["processes_per_call_p50"]) == (3, 2)
    assert parsed["gateway_events_dropped"] == 2
    assert "gateway_execs_per_call" not in parsed


def test_a_dropped_event_between_the_calls_drops_the_gateway_count_only() -> None:
    # review of 19f71f9be5: the listing between two calls lost an exec (seq 5);
    # the calls themselves are whole, the gateway count is not reported
    parsed = dcperf.parse_eslogger(_eslogger_log(50, 900, (8, 9), listing_exec_seq=6), _eslogger_windows(), 50, 900)
    assert (parsed["calls"], parsed["calls_dropped"]) == (2, 0)
    assert parsed["gateway_events_dropped"] == 1
    assert "gateway_execs_per_call" not in parsed
    budgets = {"tolerance": 0.2, "columns": {"c": {"hook_execs.claudecode.gateway_execs_per_call": {"budget": 4}}}}
    report = dcperf.compare({"metrics": {"hook_execs": {"claudecode": parsed}}}, budgets, "c")
    assert not report["ok"] and report["rows"][0]["status"] == "missing"


def _pending_trace(tmp_path: Path, lines: list[str]) -> dict:
    log = tmp_path / "es.jsonl"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    windows = _eslogger_windows()
    return {
        "metrics": {},
        "eslogger_traces": {
            "claudecode": {"log": str(log), "offset": 0, "runner_pid": 50, "gateway_pid": 900, "windows": windows}
        },
    }


def _stopped_pid() -> int:
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    return proc.pid


def _tail(seq: int) -> str:
    return _es("exec", seq, "03.000000000", 778, 1, "/usr/bin/true")  # written after the last call


def test_eslogger_parse_fills_the_exec_count_from_a_stopped_logger(tmp_path: Path) -> None:
    result = dcperf.eslogger_parse(
        _pending_trace(tmp_path, _eslogger_log(50, 900, (7, 8)) + [_tail(9)]), _stopped_pid()
    )
    assert "eslogger_traces" not in result
    assert result["metrics"]["hook_execs"]["claudecode"]["gateway_events_dropped"] == 0
    assert result["metrics"]["hook_execs"]["claudecode"]["gateway_execs_per_call"] == 1.0


def test_eslogger_parse_refuses_a_log_that_may_be_partial(tmp_path: Path) -> None:
    # no event after the last call: eslogger was not stopped (its buffer was not flushed)
    try:
        dcperf.eslogger_parse(_pending_trace(tmp_path, _eslogger_log(50, 900, (7, 8))), _stopped_pid())
    except SystemExit as exc:
        assert "ends before the last traced call" in str(exc)
    else:
        raise AssertionError("a log that ends before the last call was parsed")


def test_eslogger_parse_refuses_while_the_logger_still_runs(tmp_path: Path) -> None:
    # a complete-looking log, but the eslogger that writes it is alive (this process stands in)
    try:
        dcperf.eslogger_parse(_pending_trace(tmp_path, _eslogger_log(50, 900, (7, 8)) + [_tail(9)]), os.getpid())
    except SystemExit as exc:
        assert "still running" in str(exc)
    else:
        raise AssertionError("a log was parsed while its eslogger still ran")


def test_a_dropped_event_at_the_edge_of_the_span_drops_the_gateway_count() -> None:
    # review round 2: exec seq 9 (say, the last gateway exec in the slack after
    # the final call) is missing; the span itself is whole, the next event is 10
    parsed = dcperf.parse_eslogger(_eslogger_log(50, 900, (7, 8)) + [_tail(10)], _eslogger_windows(), 50, 900)
    assert (parsed["calls"], parsed["calls_dropped"]) == (2, 0)
    assert parsed["gateway_events_dropped"] == 1
    assert "gateway_execs_per_call" not in parsed


def test_passes_merge_into_one_result_for_the_gate() -> None:
    execs = {"groups": ["execs"], "metrics": {"hook_execs": {"claudecode": {"per_call_p50": 13}}}, "errors": {}}
    rest = {"groups": ["hook"], "metrics": {"hook": {"claudecode": {"idle": {"p95_ms": 90.0}}}}, "errors": {"x": "y"}}
    merged = dcperf.merge_results([execs, rest])
    flat = dcperf.flatten(merged)
    assert flat["hook_execs.claudecode.per_call_p50"] == 13 and flat["hook.claudecode.idle.p95_ms"] == 90.0
    assert merged["groups"] == ["execs", "hook"] and merged["errors"] == {"x": "y"}
    assert "hook" not in execs["metrics"]


def test_vmmap_summary_gives_the_footprint_and_the_resident_mapped_files() -> None:
    text = "\n".join(
        [
            "Physical footprint:         118.3M",
            "Physical footprint (peak):  141.4M",
            "REGION TYPE                        SIZE     SIZE     SIZE",
            "VM_ALLOCATE                        1.3G   128.9M   102.2M       0K",
            "mapped file                       3764K    1076K       4K       0K",
        ]
    )
    assert dcperf.parse_vmmap_summary(text) == {"anon_kb": int(118.3 * 1024), "file_kb": 1076}
    assert dcperf.parse_vmmap_summary("vmmap: no process") == {}


def test_an_old_python_runs_the_harness_again_under_the_install_venv(tmp_path: Path, monkeypatch) -> None:
    python = tmp_path / ".defenseclaw" / ".venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.write_text("#!/bin/sh\n", encoding="utf-8")
    python.chmod(0o755)
    calls = []
    monkeypatch.delenv("DCPERF_REEXEC", raising=False)
    monkeypatch.setattr(dcperf.sys, "version_info", (3, 9, 6))
    monkeypatch.setattr(dcperf.os, "execv", lambda path, argv: calls.append((path, argv)))
    try:  # the real execv does not return; the stand-in does, and the harness then stops
        dcperf.reexec_under_install_python(["run", "--home", str(tmp_path)])
    except SystemExit:
        pass
    assert calls == [
        (str(python), [str(python), "-I", str(ROOT / "scripts" / "perf" / "dcperf.py"), "run", "--home", str(tmp_path)])
    ]
    monkeypatch.setenv("DCPERF_REEXEC", "1")
    try:
        dcperf.reexec_under_install_python(["run", f"--home={tmp_path}"])
    except SystemExit as exc:
        assert "3.11" in str(exc)
    else:
        raise AssertionError("a second re-exec was not refused")


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


def test_every_macos_budget_has_a_source_and_names_a_metric_the_harness_writes_there() -> None:
    hook = {
        "idle": {"p50_ms": 1, "p95_ms": 1, "max_ms": 1, "min_ms": 1, "n": 1, "not_allowed": 0},
        "burst": {"p50_ms": 1, "p95_ms": 1, "max_ms": 1, "min_ms": 1, "n": 1, "not_allowed": 0, "width": 32},
    }
    cli = {"p50_ms": 1, "p95_ms": 1, "max_ms": 1, "min_ms": 1, "n": 1}
    execs = {"per_call_p50": 13, "per_call_max": 13, "processes_per_call_p50": 36, "calls": 10, "calls_dropped": 0}
    produced = dcperf.flatten(
        _result(
            hook={"claudecode": hook, "codex": hook},
            hook_execs={"claudecode": dict(execs, gateway_execs_per_call=1.5)},
            cli={name: cli for name in ("status", "doctor", "setup_claudecode", "skill_scan")},
            gateway_restart={"to_api_ready": cli, "command": cli},
            gateway_rss_kb={"after_idle": 1, "idle_s": 300, "audit_db_kb": 1, "anon_kb": 1, "file_kb": 1},
        )
    )
    column = BUDGETS["columns"]["macos-per-user"]
    gated = [m for m, e in column.items() if isinstance(e.get("budget"), (int, float)) and e.get("gate") is not False]
    assert "hook.claudecode.idle.p95_ms" in gated and "gateway_rss_kb.after_idle" in gated
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


def test_the_windows_column_is_report_only_until_a_windows_producer_is_in_the_repo() -> None:
    # dcperf.py writes no Windows metrics (review of 19f71f9be5, finding 5)
    column = BUDGETS["columns"]["windows-per-user"]
    assert column and all(entry.get("gate") is False for entry in column.values())
    restart = column["gateway_restart.to_api_ready.p50_ms"]["source"]
    assert "single fresh-store sample" in restart


def test_every_ungated_budget_other_than_a_max_says_why() -> None:
    for column, entries in BUDGETS["columns"].items():
        for metric, entry in entries.items():
            if entry.get("gate") is False and not metric.endswith(".max_ms"):
                assert entry.get("why"), f"{column} {metric}"
