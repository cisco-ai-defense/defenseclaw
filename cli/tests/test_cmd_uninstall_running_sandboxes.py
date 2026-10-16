# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Running OpenShell sandboxes stop ``uninstall`` and ``reset`` before any change (GAP-0368)."""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import click
import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_uninstall
from defenseclaw.commands import windows_native_uninstall as native

_LISTED = {
    "sandboxes": [
        {"name": "cdx-enforce", "workdir_mode": "copy", "phase": "ready"},
        {"name": "myapp-claude", "workdir_mode": "mount", "phase": "ready"},
        {"name": "old-copy", "workdir_mode": "copy", "phase": "stopped"},
    ]
}


def _completed(returncode=0, stdout="", stderr=""):
    return type("Completed", (), {"returncode": returncode, "stdout": stdout, "stderr": stderr})()


@pytest.fixture()
def gateway(tmp_path: Path) -> str:
    path = tmp_path / "defenseclaw-gateway"
    path.write_text("#!/bin/sh\n")
    return str(path)


def _invoke(command, args, plan, listed):
    run_patch = (
        patch("subprocess.run", side_effect=listed)
        if callable(listed)
        else patch("subprocess.run", return_value=listed)
    )
    with (
        patch.object(native, "prepare_native_windows_uninstall", return_value=None),
        patch.object(cmd_uninstall, "_build_plan", return_value=plan),
        patch.object(cmd_uninstall, "_render_plan"),
        run_patch as run,
        patch.object(cmd_uninstall, "_execute_plan") as execute,
    ):
        result = CliRunner().invoke(command, args)
    return result, execute, run


def _one_line(text: str) -> str:
    return " ".join(text.split())


def test_running_sandboxes_refuse_the_uninstall_before_any_change(gateway: str) -> None:
    plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, gateway_path=gateway)
    result, execute, run = _invoke(
        cmd_uninstall.uninstall_cmd, ["--all", "--binaries", "--yes"], plan, _completed(stdout=json.dumps(_LISTED))
    )
    assert result.exit_code == 1, result.output
    execute.assert_not_called()
    assert run.call_args.args[0] == [gateway, "sandbox", "list", "--output", "json"]
    out = _one_line(result.output)
    assert "2 OpenShell sandboxes run for this account (cdx-enforce, myapp-claude)" in out
    assert "nothing was changed" in out
    assert "`defenseclaw sandbox pull cdx-enforce --branch` keeps its work on branch dc/cdx-enforce" in out
    assert "`defenseclaw sandbox stop cdx-enforce`" in out
    assert "`defenseclaw sandbox review myapp-claude`" in out
    assert "`defenseclaw sandbox stop myapp-claude`" in out
    assert "add --stop-sandboxes" in out
    # A stopped sandbox does not refuse the run.
    assert "old-copy" not in out


def test_stop_sandboxes_lets_the_teardown_stop_them(gateway: str) -> None:
    plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, gateway_path=gateway)
    result, execute, _ = _invoke(
        cmd_uninstall.uninstall_cmd,
        ["--all", "--binaries", "--stop-sandboxes", "--yes"],
        plan,
        _completed(stdout=json.dumps(_LISTED)),
    )
    assert result.exit_code == 0, result.output
    execute.assert_called_once()
    ran = execute.call_args.args[0]
    assert ran.stop_sandboxes
    assert ran.running_sandboxes == (("cdx-enforce", "copy"), ("myapp-claude", "mount"))
    assert ran.live_sandboxes == ("myapp-claude",)


def test_dry_run_says_a_real_run_would_stop(gateway: str) -> None:
    plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, gateway_path=gateway)
    result, execute, _ = _invoke(
        cmd_uninstall.uninstall_cmd, ["--dry-run"], plan, _completed(stdout=json.dumps(_LISTED))
    )
    assert result.exit_code == 0, result.output
    execute.assert_not_called()
    out = _one_line(result.output)
    assert "a real run would stop before any change" in out
    assert "(cdx-enforce, myapp-claude)" in out


@pytest.mark.parametrize(
    "listed",
    [
        # Only stopped sandboxes: nothing runs.
        _completed(stdout=json.dumps({"sandboxes": [_LISTED["sandboxes"][2]]})),
        # Sandboxes are not supported here (exit 3): none can run.
        _completed(returncode=3, stderr="✗ OpenShell sandboxes are not supported here"),
    ],
)
def test_no_running_sandbox_does_not_refuse(gateway: str, listed) -> None:
    plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, gateway_path=gateway)
    result, execute, _ = _invoke(cmd_uninstall.uninstall_cmd, ["--yes"], plan, listed)
    assert result.exit_code == 0, result.output
    execute.assert_called_once()
    assert execute.call_args.args[0].running_sandboxes == ()


def _list_then(listed, *, teardown_help=True):
    """A subprocess.run fake: ``sandbox list`` answers *listed* (or raises it)."""

    def fake_run(argv, **_):
        if argv[-1] == "--help":
            return _completed(stdout="Flags:\n  --keep-images\n") if teardown_help else _completed(returncode=1)
        if isinstance(listed, BaseException):
            raise listed
        return listed

    return fake_run


# GAP-0448: a list that cannot answer is not "no sandbox runs".
_UNANSWERED = {
    "error exit": (
        _completed(
            returncode=1, stderr="✗ the sandbox daemon is not running; start it with `defenseclaw-gateway start`"
        ),
        "`sandbox list` failed: the sandbox daemon is not running",
    ),
    "timeout": (subprocess.TimeoutExpired(["defenseclaw-gateway"], 10), "did not answer within 10 seconds"),
    "bad JSON": (_completed(stdout="{not json"), "printed no sandbox list"),
    "JSON without a sandbox list": (_completed(stdout='{"enabled": true}'), "printed no sandbox list"),
    "cannot run": (PermissionError(13, "Permission denied"), "could not run: Permission denied"),
}


@pytest.mark.parametrize("case", sorted(_UNANSWERED))
def test_an_unanswered_sandbox_list_refuses_before_any_change(gateway: str, case: str) -> None:
    listed, reason = _UNANSWERED[case]
    plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, gateway_path=gateway)
    result, execute, _ = _invoke(cmd_uninstall.uninstall_cmd, ["--all", "--yes"], plan, _list_then(listed))
    assert result.exit_code == 1, result.output
    execute.assert_not_called()
    out = _one_line(result.output)
    assert "the sandbox list could not be read (" in out
    assert reason in out
    assert "a running sandbox may hold work never pulled back" in out
    assert "nothing was changed" in out
    assert "Run `defenseclaw sandbox list` to check" in out
    assert "then run this command again, or add --stop-sandboxes" in out

    # --stop-sandboxes still lets the teardown run.
    result, execute, _ = _invoke(
        cmd_uninstall.uninstall_cmd, ["--all", "--stop-sandboxes", "--yes"], plan, _list_then(listed)
    )
    assert result.exit_code == 0, result.output
    execute.assert_called_once()
    assert reason in execute.call_args.args[0].sandbox_list_error


def test_an_unanswered_sandbox_list_refuses_reset_and_a_dry_run_says_so(gateway: str) -> None:
    listed = _completed(returncode=1, stderr="✗ the sandbox daemon is not running")
    plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, gateway_path=gateway)
    result, execute, _ = _invoke(cmd_uninstall.reset_cmd, ["--yes"], plan, _list_then(listed))
    assert result.exit_code == 1, result.output
    execute.assert_not_called()
    assert "the sandbox list could not be read" in _one_line(result.output)
    result, execute, _ = _invoke(cmd_uninstall.uninstall_cmd, ["--dry-run"], plan, _list_then(listed))
    assert result.exit_code == 0, result.output
    execute.assert_not_called()
    assert "a real run would stop before any change: the sandbox list could not be read" in _one_line(result.output)


def test_an_unanswered_list_does_not_refuse_where_the_teardown_deletes_nothing(tmp_path: Path, gateway: str) -> None:
    listed = _completed(returncode=1, stderr='✗ unknown command "list"')
    # A gateway without `sandbox teardown` deletes no sandbox.
    plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, gateway_path=gateway)
    result, execute, _ = _invoke(cmd_uninstall.uninstall_cmd, ["--yes"], plan, _list_then(listed, teardown_help=False))
    assert result.exit_code == 0, result.output
    execute.assert_called_once()
    # No gateway binary: nothing lists, nothing is deleted.
    plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, gateway_path=str(tmp_path / "gone"))
    result, execute, run = _invoke(cmd_uninstall.uninstall_cmd, ["--yes"], plan, _list_then(listed))
    assert result.exit_code == 0, result.output
    execute.assert_called_once()
    run.assert_not_called()
    # No sandbox state for the account: no list at all (today's behaviour).
    plan = cmd_uninstall.UninstallPlan(sandbox_teardown=False, gateway_path=gateway)
    result, execute, run = _invoke(cmd_uninstall.uninstall_cmd, ["--yes"], plan, _list_then(listed))
    assert result.exit_code == 0, result.output
    execute.assert_called_once()
    run.assert_not_called()


def test_every_phase_but_a_stopped_one_may_run() -> None:
    # GAP-0449: error may still run its containers, stopping still runs its
    # workload; an unknown or empty phase is not known to be stopped.
    live = ["creating", "provisioning", "starting", "ready", "stopping", "deleting", "error", "unknown", "", "Ready"]
    stopped = ["stopped", "completed", "deleted", "missing"]
    rows = [{"name": f"live-{i}", "workdir_mode": "copy", "phase": phase} for i, phase in enumerate(live)]
    rows += [{"name": f"stopped-{phase}", "workdir_mode": "copy", "phase": phase} for phase in stopped]
    rows.append({"name": "no-phase", "workdir_mode": "mount"})
    running = cmd_uninstall._running_sandboxes(rows)
    assert {name for name, _ in running} == {f"live-{i}" for i in range(len(live))} | {"no-phase"}


def test_plan_names_an_unanswered_sandbox_list() -> None:
    for stop, want in (
        (False, "this run stops before any change; check with `defenseclaw sandbox list`, or add --stop-sandboxes"),
        (True, "any running sandbox is stopped and deleted (--stop-sandboxes)"),
    ):
        plan = cmd_uninstall.UninstallPlan(
            sandbox_teardown=True, sandbox_list_error="`sandbox list` failed: boom", stop_sandboxes=stop
        )
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cmd_uninstall._render_plan(plan, dry_run=True)
        out = _one_line(buf.getvalue())
        assert "the sandbox list could not be read (`sandbox list` failed: boom)" in out
        assert want in out


def test_skipped_teardown_does_not_list_or_refuse(gateway: str) -> None:
    plan = cmd_uninstall.UninstallPlan(sandbox_teardown=False, sandbox_teardown_skipped=True, gateway_path=gateway)
    result, execute, run = _invoke(
        cmd_uninstall.uninstall_cmd,
        ["--skip-sandbox-teardown", "--yes"],
        plan,
        _completed(stdout=json.dumps(_LISTED)),
    )
    assert result.exit_code == 0, result.output
    execute.assert_called_once()
    run.assert_not_called()


def test_reset_refuses_running_sandboxes_too(gateway: str) -> None:
    plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, gateway_path=gateway)
    result, execute, _ = _invoke(cmd_uninstall.reset_cmd, ["--yes"], plan, _completed(stdout=json.dumps(_LISTED)))
    assert result.exit_code == 1, result.output
    execute.assert_not_called()
    assert "add --stop-sandboxes" in _one_line(result.output)
    result, execute, _ = _invoke(
        cmd_uninstall.reset_cmd, ["--stop-sandboxes", "--yes"], plan, _completed(stdout=json.dumps(_LISTED))
    )
    assert result.exit_code == 0, result.output
    execute.assert_called_once()


def test_plan_validation_refuses_running_sandboxes() -> None:
    running = (("cdx-enforce", "copy"),)
    with pytest.raises(click.ClickException, match="1 OpenShell sandbox runs for this account"):
        cmd_uninstall._validate_plan(cmd_uninstall.UninstallPlan(sandbox_teardown=True, running_sandboxes=running))
    cmd_uninstall._validate_plan(
        cmd_uninstall.UninstallPlan(sandbox_teardown=True, running_sandboxes=running, stop_sandboxes=True)
    )


def test_plan_names_the_running_sandboxes() -> None:
    running = (("cdx-enforce", "copy"),)
    for stop, want in (
        (
            False,
            "running sandboxes (cdx-enforce) stop this run before any change: stop them first, or add --stop-sandboxes",
        ),
        (True, "running sandboxes (cdx-enforce) are stopped and deleted (--stop-sandboxes)"),
    ):
        plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, running_sandboxes=running, stop_sandboxes=stop)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cmd_uninstall._render_plan(plan, dry_run=True)
        assert want in _one_line(buf.getvalue())


def test_teardown_says_it_is_running_before_it_waits(gateway: str) -> None:
    plan = cmd_uninstall.UninstallPlan(sandbox_teardown=True, gateway_path=gateway)
    buf = io.StringIO()
    seen = []

    def fake_run(argv, **_):
        if argv[-1] == "--help":
            return _completed(stdout="Flags:\n  --keep-images\n")
        seen.append(buf.getvalue())
        return _completed(stdout="✓ teardown complete\n")

    with patch("subprocess.run", side_effect=fake_run), contextlib.redirect_stdout(buf):
        cmd_uninstall._sandbox_teardown(plan)
    # Printed before the teardown, which shows its own output only at the end.
    assert "tearing down DefenseClaw's OpenShell sandboxes" in seen[0]
