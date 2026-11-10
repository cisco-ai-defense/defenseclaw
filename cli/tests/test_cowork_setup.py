# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""``defenseclaw setup cowork``: the Cowork account plugin and its status rows."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import click
import pytest
from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw import cowork
from defenseclaw.commands import cmd_doctor, cmd_setup, cmd_setup_cowork, cmd_status, cmd_uninstall
from defenseclaw.commands.cmd_setup import setup as setup_group
from defenseclaw.config import PerConnectorGuardrailConfig
from defenseclaw.inventory import claude_desktop

from tests.helpers import cleanup_app, make_app_context

GATEWAY = "/opt/dc/bin/defenseclaw-gateway"


def _hooks_doc() -> dict:
    command = "/home/u/.defenseclaw/hooks/claude-code-hook.sh"
    return {
        "hooks": {
            event: [{"hooks": [{"type": "command", "command": command, "timeout": 30}]}]
            for event in sorted(cowork.COWORK_EVENTS)
        }
    }


def _windows_hooks_doc(guard: Path, data_dir: Path, launcher: Path) -> dict:
    return {
        "hooks": {
            event: [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": str(guard),
                            "args": ["cowork-guard", str(data_dir), str(launcher), event],
                            "timeout": 30,
                        }
                    ]
                }
            ]
            for event in sorted(cowork.COWORK_EVENTS)
        }
    }


def _health(**row) -> dict:
    return {"connectors": [{"name": "claudecode", "surfaces": {"cowork": row}}]}


def _now(seconds: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


def _gateway(returncode: int = 0, stdout: str = "", stderr: str = ""):
    """Stand in for run_pinned_executable(defenseclaw-gateway connector cowork-plugin)."""
    calls: list[list[str]] = []

    def run(argv, **_kwargs):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, returncode, stdout, stderr)

    return run, calls


@pytest.fixture
def app():
    ctx, tmp_dir, db_path = make_app_context()
    ctx.cfg.guardrail.enabled = True
    ctx.cfg.guardrail.connectors = {"claudecode": PerConnectorGuardrailConfig(mode="observe")}
    with (
        patch.object(cowork, "managed_host", return_value=""),
        patch.object(cowork, "claude_desktop_installed", return_value=True),
        patch.object(cowork, "open_claude", return_value=True),
        patch.object(cmd_setup, "_gateway_lifecycle_resolution", return_value=(GATEWAY, "")),
    ):
        yield ctx
    cleanup_app(ctx, db_path, tmp_dir)


def _setup(app, *args: str, gateway=None, input: str | None = None):
    run, calls = gateway or _gateway(stdout=json.dumps(_hooks_doc()))
    with patch("defenseclaw.pinned_exec.run_pinned_executable", side_effect=run):
        result = CliRunner().invoke(setup_group, ["cowork", *args], obj=app, input=input)
    return result, calls


def _data_dir(app) -> str:
    return str(app.cfg.data_dir)


def test_cowork_names_found_gateway_with_unsafe_acl(app) -> None:
    reason = "refusing to run the gateway: ACL grants write access to untrusted SID S-1-5-32-545; Restore its ACL"
    with (
        patch.object(cmd_setup, "_gateway_lifecycle_resolution", return_value=(None, reason)),
    ):
        with pytest.raises(click.ClickException) as exc:
            cmd_setup_cowork._render_hooks(app.cfg)

    assert "S-1-5-32-545" in str(exc.value)
    assert "Restore its ACL" in str(exc.value)
    assert "was not found" not in str(exc.value)


def test_cowork_missing_gateway_keeps_install_guidance(app) -> None:
    with (
        patch.object(cmd_setup, "_gateway_lifecycle_resolution", return_value=(None, "")),
    ):
        with pytest.raises(click.ClickException) as exc:
            cmd_setup_cowork._render_hooks(app.cfg)

    assert "was not found" in str(exc.value)
    assert "Run the DefenseClaw installer" in str(exc.value)


def test_plugin_zip_has_only_the_manifest_and_hooks() -> None:
    data = cowork.plugin_zip_bytes(_hooks_doc(), "1.0.3", "1.0.8")
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        assert sorted(zf.namelist()) == [".claude-plugin/plugin.json", "hooks/hooks.json"]
        manifest = json.loads(zf.read(".claude-plugin/plugin.json"))
        assert manifest["name"] == "defenseclaw" and manifest["version"] == "1.0.3"
        assert json.loads(zf.read("hooks/hooks.json")) == _hooks_doc()
    assert cowork.plugin_zip_bytes(_hooks_doc(), "1.0.3", "1.0.8") == data
    extra = _hooks_doc()
    extra["hooks"]["MessageDisplay"] = extra["hooks"]["Stop"]
    with pytest.raises(ValueError):
        cowork.validate_hooks_document(extra)


@pytest.mark.parametrize("layout", ["one-line", "native"])
def test_windows_plugin_bundles_guard_for_every_event(tmp_path: Path, layout: str) -> None:
    root = tmp_path / "DC %!&^() account"
    if layout == "one-line":
        launcher = root / "bin" / "defenseclaw-hook.exe"
        source = root / "bin" / "defenseclaw-hook-guard.exe"
    else:
        launcher = root / "HookRuntime" / "defenseclaw-hook.exe"
        source = root / "Programs" / "DefenseClaw" / "bin" / "defenseclaw-hook-guard.exe"
    source.parent.mkdir(parents=True)
    guard_body = (
        b"MZ\x00guard"
        if os.name == "nt"
        else b'#!/bin/sh\nif [ -f "$2.cowork-uninstalled" ]; then\n'
        b"  printf '%s\\n' '{\"systemMessage\":\"Customize > Plugins\"}'\n"
        b"else\n  printf '%s\\n' '{\"ordinary\":true}'\nfi\nprintf '%s\\n' \"$@\" >&2\n"
    )
    source.write_bytes(guard_body)
    data_dir = root / "data"
    rendered = _windows_hooks_doc(source, data_dir, launcher)
    data = cowork.plugin_zip_bytes(rendered, "1.0.3", "1.0.9")
    assert all(rendered["hooks"][event][0]["hooks"][0]["command"] == str(source) for event in cowork.COWORK_EVENTS)
    if os.name != "nt":
        source.chmod(0o700)
        for event in cowork.COWORK_EVENTS:
            args = rendered["hooks"][event][0]["hooks"][0]["args"]
            result = subprocess.run([str(source), *args], text=True, capture_output=True, timeout=5)
            assert result.returncode == 0 and json.loads(result.stdout) == {"ordinary": True}
            assert result.stderr.splitlines() == args
    source.unlink()
    if os.name != "nt":
        Path(str(data_dir) + ".cowork-uninstalled").write_text("removed\n", encoding="utf-8")
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        assert zf.read("hooks/defenseclaw-hook-guard.exe") == guard_body
        assert "bin/defenseclaw-hook-guard.exe" not in zf.namelist()
        hooks = json.loads(zf.read("hooks/hooks.json"))["hooks"]
        plugin_root = root / "plugin"
        if os.name != "nt":
            zf.extract("hooks/defenseclaw-hook-guard.exe", plugin_root)
            (plugin_root / "hooks" / "defenseclaw-hook-guard.exe").chmod(0o700)
        for event in cowork.COWORK_EVENTS:
            handler = hooks[event][0]["hooks"][0]
            assert handler["command"] == "${CLAUDE_PLUGIN_ROOT}/hooks/defenseclaw-hook-guard.exe"
            assert handler["args"] == ["cowork-guard", str(data_dir), str(launcher), event]
            if os.name != "nt":
                command = handler["command"].replace("${CLAUDE_PLUGIN_ROOT}", str(plugin_root))
                result = subprocess.run([command, *handler["args"]], text=True, capture_output=True, timeout=5)
                assert result.returncode == 0 and "Customize" in result.stdout
                assert result.stderr.splitlines() == handler["args"]


@pytest.fixture(scope="module")
def _windows_handler_binaries(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    if os.name != "nt":
        pytest.skip("Windows executable runtime")
    build_dir = tmp_path_factory.mktemp("cowork-guard-build")
    repo = Path(__file__).resolve().parents[2]
    guard_binary = build_dir / "built-guard.exe"
    launcher_binary = build_dir / "built-launcher.exe"
    launcher_source = build_dir / "launcher.go"
    launcher_source.write_text(
        'package main\nimport ("fmt"; "os")\nfunc main() { '
        'if os.Getenv("DC_COWORK_TEST_DENY") == "1" { os.Exit(2) }; '
        'fmt.Println(`{"ordinary":true}`) }\n',
        encoding="utf-8",
    )
    build_env = {**os.environ, "GOTOOLCHAIN": "go1.26.4"}
    subprocess.run(
        ["go", "build", "-ldflags", "-H=windowsgui", "-o", str(guard_binary), "./cmd/defenseclaw-hook-guard"],
        cwd=repo,
        env=build_env,
        check=True,
        timeout=180,
    )
    subprocess.run(
        ["go", "build", "-o", str(launcher_binary), str(launcher_source)],
        cwd=repo,
        env=build_env,
        check=True,
        timeout=180,
    )
    return guard_binary, launcher_binary


@pytest.mark.parametrize("layout", ["one-line", "native"])
def test_windows_packaged_handler_runs_after_binary_removal(
    tmp_path: Path, layout: str, _windows_handler_binaries: tuple[Path, Path]
) -> None:
    """Start each retained handler, including the path used by PreToolUse."""
    guard_binary, launcher_binary = _windows_handler_binaries
    root = tmp_path / "DC %!&^() account"
    if layout == "one-line":
        launcher = root / "bin" / "defenseclaw-hook.exe"
        source = root / "bin" / "defenseclaw-hook-guard.exe"
    else:
        launcher = root / "HookRuntime" / "defenseclaw-hook.exe"
        source = root / "Programs" / "DefenseClaw" / "bin" / "defenseclaw-hook-guard.exe"
    source.parent.mkdir(parents=True)
    launcher.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(guard_binary, source)
    shutil.copyfile(launcher_binary, launcher)
    data_dir = root / "data"
    (data_dir / "cowork").mkdir(parents=True)
    (data_dir / "config.yaml").write_text("installed\n", encoding="utf-8")
    archive = cowork.plugin_zip_bytes(_windows_hooks_doc(source, data_dir, launcher), "1.0.3", "1.0.9")
    plugin_root = root / "plugin"
    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        zf.extractall(plugin_root)
        hooks = json.loads(zf.read("hooks/hooks.json"))["hooks"]

    def invoke(event: str, *, deny: bool = False) -> subprocess.CompletedProcess[str]:
        handler = hooks[event][0]["hooks"][0]
        command = handler["command"].replace("${CLAUDE_PLUGIN_ROOT}", str(plugin_root))
        return subprocess.run(
            [command, *handler["args"]],
            input="{}",
            text=True,
            capture_output=True,
            timeout=30,
            env={**os.environ, "DC_COWORK_TEST_DENY": "1" if deny else "0"},
        )

    for event in sorted(cowork.COWORK_EVENTS):
        result = invoke(event)
        assert result.returncode == 0 and json.loads(result.stdout) == {"ordinary": True}, (event, result)
    assert invoke("PreToolUse", deny=True).returncode == 2
    source.unlink()
    assert invoke("PreToolUse").returncode == 0
    launcher.unlink()
    assert invoke("PreToolUse").returncode == 2
    shutil.rmtree(data_dir)
    marker = Path(cowork.uninstalled_marker_path(str(data_dir)))
    marker.write_text("removed\n", encoding="utf-8")
    for event in sorted(cowork.COWORK_EVENTS):
        for suffix in (".notice", ".context"):
            shutil.rmtree(str(marker) + suffix, ignore_errors=True)
        result = invoke(event)
        assert result.returncode == 0 and "Customize" in result.stdout, (event, result)
        if event == "UserPromptSubmit":
            assert "additionalContext" in result.stdout


def test_build_bumps_and_a_rebuild_clears_the_confirmation(app) -> None:
    first, calls = _setup(app, "--yes")
    assert first.exit_code == 0, first.output
    assert calls[0][:3] == [GATEWAY, "connector", "cowork-plugin"]
    assert "observe mode: records only" in first.output and "--mode action" in first.output
    v1 = cowork.load_state(_data_dir(app))["version"]

    def health(_cfg):
        stamp = _now(1)
        return _health(last_activity_at=stamp, last_session_start_at=stamp), ""

    with patch("defenseclaw.commands.cmd_setup_cowork._gateway_health", side_effect=health):
        waited, _ = _setup(app, "--yes", "--wait", "--timeout", "10")
    assert waited.exit_code == 0, waited.output
    assert "Cowork is protected: a Cowork session reached" in waited.output
    assert "observe mode: records only" in waited.output
    state = cowork.load_state(_data_dir(app))
    assert state["version"] > v1 and state["last_event_at"] and state["confirmed_at"]
    assert cowork.cowork_status(app.cfg, None, gateway_running=True).protected

    rebuilt, _ = _setup(app, "--yes")
    assert rebuilt.exit_code == 0, rebuilt.output
    state = cowork.load_state(_data_dir(app))
    assert "last_event_at" not in state and "confirmed_at" not in state and state["previous_event_at"]
    row = cowork.cowork_status(app.cfg, {"connectors": [{"name": "claudecode"}]}, gateway_running=True)
    assert not row.protected and row.reason_code == "cowork_no_events" and "earlier plugin build" in row.detail
    with zipfile.ZipFile(cowork.zip_path(_data_dir(app))) as zf:
        assert json.loads(zf.read(".claude-plugin/plugin.json"))["version"] == state["version"]


@pytest.mark.parametrize(
    ("gateway", "message"),
    [
        (
            _gateway(1, "", 'Error: unknown command "cowork-plugin" for "defenseclaw-gateway connector"'),
            "cannot build the Cowork plugin; update DefenseClaw",
        ),
        (
            _gateway(
                1,
                json.dumps({"error": "the Claude Code connector is not set up: x", "reason": "claudecode_not_set_up"}),
            ),
            "Run defenseclaw setup claude-code",
        ),
        (_gateway(0, "not json"), "The Cowork plugin was not built"),
        (_gateway(0, json.dumps({"hooks": {"Stop": []}})), "The Cowork plugin was not built"),
    ],
)
def test_gateway_refusals_write_nothing(app, gateway, message) -> None:
    result, _ = _setup(app, "--yes", gateway=gateway)
    assert result.exit_code == 1
    assert message in result.output and "Nothing was changed" in result.output
    assert not os.path.exists(cowork.state_dir(_data_dir(app)))


def test_claude_code_prerequisite_yes_and_decline(app) -> None:
    app.cfg.guardrail.connectors = {}
    not_set_up = json.dumps({"error": "x", "reason": "claudecode_not_set_up"})
    declined, _ = _setup(app, gateway=_gateway(1, not_set_up), input="n\n")
    assert declined.exit_code == 1
    assert "Cowork needs the Claude Code connector" in declined.output
    assert not os.path.exists(cowork.state_dir(_data_dir(app)))

    old, _ = _setup(app, "--yes", gateway=_gateway(1, "", 'Error: unknown command "cowork-plugin"'))
    assert old.exit_code == 1 and "update DefenseClaw" in old.output
    assert not app.cfg.guardrail.connectors

    answers = iter([(1, not_set_up), (0, json.dumps(_hooks_doc()))])

    def run(argv, **_kwargs):
        code, out = next(answers)
        return subprocess.CompletedProcess(argv, code, out, "")

    def enable(**kwargs):
        assert kwargs == {"yes": True}
        app.cfg.guardrail.connectors = {"claudecode": PerConnectorGuardrailConfig(mode="action")}

    with (
        patch("defenseclaw.pinned_exec.run_pinned_executable", side_effect=run),
        patch.object(cmd_setup.setup_claude_code, "callback", side_effect=lambda **kw: enable(**{"yes": kw["yes"]})),
        patch("defenseclaw.config.load", side_effect=lambda: app.cfg),
    ):
        result = CliRunner().invoke(setup_group, ["cowork", "--yes"], obj=app)
    assert result.exit_code == 0, result.output
    assert "action mode: policy hits are blocked" in result.output
    assert os.path.exists(cowork.zip_path(_data_dir(app)))


@pytest.mark.parametrize(("host_os", "shown"), [("linux", True), ("darwin", False)])
def test_setup_cowork_says_cowork_on_linux_is_a_preview(app, host_os, shown) -> None:
    # Cowork audit P4-3: the support matrix lists Cowork on Linux as Preview.
    notice = "Cowork on Linux is a preview: Claude Desktop for Linux is a beta, and Cowork on Linux is not certified."
    with patch("defenseclaw.platform_support.host_os", return_value=host_os):
        result, _ = _setup(app, "--yes")
    assert result.exit_code == 0, result.output
    assert (notice in " ".join(result.output.split())) is shown, result.output


def test_setup_cowork_refuses_beside_a_managed_install(app) -> None:
    with (
        patch.object(cowork, "managed_host", return_value="standalone"),
        patch("defenseclaw.enforce.asset_lists.audit_managed_config_refusal") as audit,
    ):
        result, calls = _setup(app, "--yes")
    assert result.exit_code == 3
    assert "managed by your organization" in result.output and "machine policy" in result.output
    audit.assert_called_once_with("cowork-plugin", "setup cowork")
    assert not calls and not os.path.exists(cowork.state_dir(_data_dir(app)))


def test_doctor_and_status_cowork_rows(app) -> None:
    from defenseclaw.commands.cmd_status import status as status_cmd

    def doctor_row(authenticated):
        r = cmd_doctor._DoctorResult()
        with patch.object(cmd_doctor, "_authenticated_gateway_health", return_value=(authenticated, "", True)):
            cmd_doctor._check_cowork(app.cfg, {"gateway": {}}, r)
        rows = [c for c in r.checks if c.get("check_id") == "doctor.cowork"]
        assert len(rows) == 1
        return rows[0]

    row = doctor_row({})
    assert row["status"] == "warn" and row["reason_code"] == "cowork_plugin_not_built"

    cowork.save_state(_data_dir(app), {"build": 1, "version": "1.0.1", "built_at": _now(-60)})
    row = doctor_row(None)
    assert row["status"] == "warn" and row["reason_code"] == "cowork_health_unavailable"
    row = doctor_row(_health(last_activity_at=_now()))
    assert row["status"] == "pass" and "observe mode: records only" in row["detail"]

    with patch.object(cmd_status, "_fetch_runtime_bound_health", return_value=_health(last_activity_at=_now())):
        result = CliRunner().invoke(status_cmd, ["--json"], obj=app, catch_exceptions=False)
    payload = json.loads(result.output)
    assert payload["cowork"]["protected"] is True and payload["cowork"]["plugin_version"] == "1.0.1"
    with patch.object(cmd_status, "_fetch_runtime_bound_health", return_value=None):
        result = CliRunner().invoke(status_cmd, ["--json"], obj=app, catch_exceptions=False)
    payload = json.loads(result.output)
    assert payload["cowork"]["protected"] is False and payload["cowork"]["reason_code"] == "cowork_gateway_down"


def test_uninstall_dry_run_names_the_cowork_removal_step(app) -> None:
    cowork.save_state(_data_dir(app), {"build": 1, "version": "1.0.1"})
    plan = cmd_uninstall.UninstallPlan(data_dir=_data_dir(app))
    with (
        patch.object(cmd_uninstall, "_build_plan", return_value=plan),
        patch.object(cmd_uninstall, "_render_plan"),
        patch.object(cmd_uninstall, "_execute_plan") as execute,
    ):
        result = CliRunner().invoke(cmd_uninstall.uninstall_cmd, ["--dry-run"])
    assert result.exit_code == 0, result.output
    assert (
        "The DefenseClaw Cowork plugin stays in your Claude account. Remove it in Claude: Customize > Plugins."
        in result.output
    )
    assert "Customize > Plugins, then the ... menu > Remove" in result.output
    assert "older plugins may block" in result.output
    execute.assert_not_called()


def test_completed_uninstall_records_cowork_removal(app) -> None:
    data_dir = _data_dir(app)
    cowork.save_state(data_dir, {"build": 1, "version": "1.0.1"})
    plan = cmd_uninstall.UninstallPlan(data_dir=data_dir, remove_data_dir=True)
    with (
        patch.object(cmd_uninstall, "_build_plan", return_value=plan),
        patch.object(cmd_uninstall, "_render_plan"),
        patch.object(cmd_uninstall, "_execute_plan"),
        patch.object(cmd_uninstall, "_configured_gateway_ports", return_value=frozenset()),
        patch.object(cmd_uninstall, "_remove_marked_native_otel_left"),
        patch.object(cmd_uninstall, "_render_kept_and_next_steps"),
    ):
        result = CliRunner().invoke(cmd_uninstall.uninstall_cmd, ["--all", "--yes"])
    assert result.exit_code == 0, result.output
    assert Path(cowork.uninstalled_marker_path(data_dir)).read_text(encoding="utf-8") == "removed\n"
    assert "Customize > Plugins, then the ... menu > Remove" in result.output


def test_new_cowork_build_clears_a_previous_removal_record(app) -> None:
    data_dir = _data_dir(app)
    assert cowork.uninstalled_marker_path(data_dir + os.sep) == cowork.uninstalled_marker_path(data_dir)
    cowork.mark_uninstalled(data_dir)
    result, _ = _setup(app, "--yes")
    assert result.exit_code == 0, result.output
    assert not os.path.exists(cowork.uninstalled_marker_path(data_dir))


def test_live_activity_before_the_build_is_not_protection(app) -> None:
    cowork.save_state(_data_dir(app), {"build": 2, "version": "1.0.2", "built_at": _now()})
    stale = _health(last_activity_at=_now(-120), last_session_start_at=_now(-120))
    row = cowork.cowork_status(app.cfg, stale, gateway_running=True)
    assert not row.protected and row.reason_code == "cowork_no_events"
    assert "earlier plugin build" in row.detail
    assert cowork.cowork_status(app.cfg, _health(last_activity_at=_now(5)), gateway_running=True).protected


def test_doctor_warns_without_authenticated_status_despite_a_recorded_event(app) -> None:
    built = _now(-60)
    cowork.save_state(_data_dir(app), {"build": 1, "version": "1.0.1", "built_at": built, "last_event_at": _now(-30)})
    r = cmd_doctor._DoctorResult()
    with patch.object(cmd_doctor, "_authenticated_gateway_health", return_value=(None, "HTTP 401", True)):
        cmd_doctor._check_cowork(app.cfg, {"gateway": {}}, r)
    row = next(c for c in r.checks if c.get("check_id") == "doctor.cowork")
    assert row["status"] == "warn" and row["reason_code"] == "cowork_health_unavailable"
    assert "last confirmed" in row["detail"]


def test_wait_takes_the_newest_cowork_event(app) -> None:
    from defenseclaw.commands import cmd_setup_cowork

    started = datetime.now(timezone.utc)
    newer = (started + timedelta(seconds=2)).isoformat()
    older_start = (started - timedelta(seconds=60)).isoformat()
    health = _health(last_activity_at=newer, last_session_start_at=older_start)
    with patch.object(cmd_setup_cowork, "_gateway_health", return_value=(health, "")):
        seen = cmd_setup_cowork._wait_for_cowork(app.cfg, started, 10)
    assert seen is not None and seen.isoformat() == newer


def test_version_never_reuses_the_zip_on_disk(app) -> None:
    data_dir = _data_dir(app)
    now = datetime(2026, 11, 3, 20, 0, 0, tzinfo=timezone.utc)
    build, version = cowork.next_version({}, now, data_dir)
    cowork.write_plugin_zip(data_dir, cowork.plugin_zip_bytes(_hooks_doc(), version, "1.0.8"))
    again, _ = cowork.next_version({}, now, data_dir)
    assert again == build + 1


@pytest.mark.parametrize(
    ("pid", "refused"),
    [(4242, "authenticated status returned HTTP 401"), (4242, ""), (0, "")],
    ids=["refuses-status", "hung", "stopped"],
)
def test_status_cowork_row_tells_an_unreadable_gateway_from_a_stopped_one(app, pid, refused) -> None:
    from defenseclaw.commands.cmd_status import status as status_cmd

    cowork.save_state(
        _data_dir(app), {"build": 1, "version": "1.0.1", "built_at": _now(-60), "last_event_at": _now(-30)}
    )
    want = "cowork_health_unavailable" if pid else "cowork_gateway_down"
    step = "defenseclaw-gateway status" if pid else "defenseclaw-gateway start"
    with (
        patch.object(cmd_status, "_fetch_runtime_bound_health", return_value=None),
        patch.object(cmd_status, "_live_gateway_pid", return_value=pid),
        patch.object(cmd_status, "_status_refused_detail", return_value=refused),
        patch.object(cmd_status, "_sidecar_listener_state", return_value=(False, "not running")),
        patch.object(cmd_doctor, "_foreign_gateway_port_holder", return_value=""),
    ):
        as_json = CliRunner().invoke(status_cmd, ["--json"], obj=app, catch_exceptions=False)
        human = CliRunner().invoke(status_cmd, [], obj=app, catch_exceptions=False)
    row = json.loads(as_json.output)["cowork"]
    assert row["protected"] is False and row["reason_code"] == want and row["step"] == step
    assert f"Next: {step}" in human.output
    if pid:
        assert "last confirmed" in row["detail"]


def test_a_state_without_a_build_time_proves_nothing(app) -> None:
    cowork.save_state(_data_dir(app), {"build": 1, "version": "1.0.1", "last_event_at": _now(-30)})
    row = cowork.cowork_status(app.cfg, _health(last_activity_at=_now()), gateway_running=True)
    assert not row.protected and row.reason_code == "cowork_no_events"


def test_a_state_with_an_invalid_build_time_ignores_even_a_far_future_event(app) -> None:
    cowork.save_state(
        _data_dir(app),
        {"build": 1, "version": "1.0.1", "built_at": "not a time", "last_event_at": "9999-12-31T23:59:59.999999+00:00"},
    )
    row = cowork.cowork_status(app.cfg, _health(last_activity_at=_now()), gateway_running=True)
    assert not row.protected and row.reason_code == "cowork_no_events"


def test_claude_desktop_roots_match_the_go_table() -> None:
    """GAP-0024 (cowork-1-0-8): the Python copy is the Go table, root for root.

    The Go "prefer" key (which MSIX folder Go lists first when more match
    than it reads) is left out: the Python check only asks whether any data
    folder exists, for which the order does not matter.
    """
    table_path = os.path.join(os.path.dirname(__file__), "..", "..", "internal", "claudedesktop", "roots.json")
    with open(table_path, encoding="utf-8") as fh:
        table = json.load(fh)
    want = {goos: tuple((r["deployment"], r["base"], r["path"]) for r in rows) for goos, rows in table.items()}
    assert claude_desktop.CLAUDE_DESKTOP_ROOTS == want


@pytest.mark.parametrize(
    ("platform", "deployment", "base", "rel"),
    [(p, d, b, r) for p, rows in claude_desktop.CLAUDE_DESKTOP_ROOTS.items() for d, b, r in rows],
)
def test_claude_desktop_installed_finds_every_data_root(
    tmp_path, monkeypatch, platform: str, deployment: str, base: str, rel: str
) -> None:
    """Each data folder alone (3p included: Claude-3p) counts as Claude Desktop."""
    home = tmp_path / "home"
    folders = {
        "home": home,
        "config": home / ".config",
        "appdata": home / "AppData" / "Roaming",
        "localappdata": home / "AppData" / "Local",
    }
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setenv("APPDATA", str(folders["appdata"]))
    monkeypatch.setenv("LOCALAPPDATA", str(folders["localappdata"]))
    if platform == "darwin":
        monkeypatch.setattr(cowork.os.path, "isdir", _isdir_outside_applications)
    assert not any(os.path.isdir(p) for p in cowork._claude_desktop_dirs(platform))
    data = folders[base].joinpath(*rel.replace("*", "pzs8sxrjxfjjc").split("/"))
    data.mkdir(parents=True)
    assert str(data) in claude_desktop.claude_desktop_data_dirs(platform), deployment
    assert any(os.path.isdir(p) for p in cowork._claude_desktop_dirs(platform))


_real_isdir = os.path.isdir


def _isdir_outside_applications(path: str) -> bool:
    # The build host's own /Applications/Claude.app must not count.
    return not str(path).startswith("/Applications/") and _real_isdir(path)


@pytest.mark.parametrize("xdg", ["relative/cfg", "", "   "])
def test_claude_desktop_relative_xdg_config_home_falls_back_to_dot_config(tmp_path, monkeypatch, xdg: str) -> None:
    """A relative XDG_CONFIG_HOME is ignored, as in Go: ~/.config is read."""
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", xdg)
    assert str(home / ".config" / "Claude-3p") in claude_desktop.claude_desktop_data_dirs("linux")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    assert str(tmp_path / "xdg" / "Claude-3p") in claude_desktop.claude_desktop_data_dirs("linux")


def _write_gateway_activity(app, at: str) -> None:
    path = os.path.join(cowork.state_dir(_data_dir(app)), cowork.ACTIVITY_NAME)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"last_activity_at": at, "last_session_start_at": at}, fh)


def test_gateway_activity_file_name_is_the_go_constant() -> None:
    go = os.path.join(os.path.dirname(__file__), "..", "..", "internal", "gateway", "claude_cowork_activity.go")
    with open(go, encoding="utf-8") as fh:
        assert f'const CoworkActivityFile = "{cowork.ACTIVITY_NAME}"' in fh.read()


def test_protection_survives_a_gateway_restart(app) -> None:
    """GAP-0038: the gateway's record of its last Cowork call outlives its
    in-memory counters, so a restart does not read as 'not protected yet'."""
    cowork.save_state(_data_dir(app), {"build": 3, "version": "1.0.3", "built_at": _now(-600)})
    _write_gateway_activity(app, _now(-300))
    restarted = {"connectors": [{"name": "claudecode"}]}

    row = cowork.cowork_status(app.cfg, restarted, gateway_running=True)

    assert row.protected and row.reason_code == ""
    assert "none since the gateway restarted" in row.detail and row.last_event_at
    live = cowork.cowork_status(app.cfg, _health(last_activity_at=_now(-5)), gateway_running=True)
    assert live.protected and "none since the gateway restarted" not in live.detail
    r = cmd_doctor._DoctorResult()
    with patch.object(cmd_doctor, "_authenticated_gateway_health", return_value=(restarted, "", True)):
        cmd_doctor._check_cowork(app.cfg, {"gateway": {}}, r)
    assert next(c for c in r.checks if c.get("check_id") == "doctor.cowork")["status"] == "pass"


def _with_windows_drive_paths(data: bytes) -> bytes:
    """Give the hook arguments of a built plugin the drive-letter paths a Windows
    host writes. The builder runs here on the host path rules, but the status
    reader judges the archive by Windows rules, and Python 3.13 no longer reads
    a path with one leading slash as absolute there."""
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as src, zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as dst:
        for info in src.infolist():
            body = src.read(info.filename)
            if info.filename == "hooks/hooks.json":
                doc = json.loads(body)
                for groups in doc["hooks"].values():
                    for group in groups:
                        for handler in group["hooks"]:
                            handler["args"][1] = "C:\\ProgramData\\DefenseClaw"
                            handler["args"][2] = "C:\\Program Files\\DefenseClaw\\defenseclaw-hook.exe"
                body = (json.dumps(doc, indent=2) + "\n").encode()
            dst.writestr(info, body)
    return out.getvalue()


def test_released_windows_cowork_plugin_requires_rebuild(app, monkeypatch, tmp_path: Path) -> None:
    released = Path(__file__).resolve().parents[2] / (
        "internal/gateway/connector/testdata/released-carriers/1.0.8/cowork-plugin-hooks-windows.json"
    )
    archive = Path(cowork.zip_path(_data_dir(app)))
    archive.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive, "w") as zf:
        zf.write(released, "hooks/hooks.json")
    cowork.save_state(_data_dir(app), {"build": 8, "version": "1.0.8", "built_at": _now(-600)})
    _write_gateway_activity(app, _now(-300))
    monkeypatch.setattr(cowork.sys, "platform", "win32")
    health = {"connectors": [{"name": "claudecode"}]}

    row = cowork.cowork_status(app.cfg, health, gateway_running=True)
    assert row is not None and not row.protected
    assert row.reason_code == "cowork_plugin_stale"
    assert row.step == "defenseclaw setup cowork"
    check = cmd_doctor._DoctorResult()
    with patch.object(cmd_doctor, "_authenticated_gateway_health", return_value=(health, "", True)):
        cmd_doctor._check_cowork(app.cfg, {"gateway": {}}, check)
    doctor_row = next(c for c in check.checks if c.get("check_id") == "doctor.cowork")
    assert doctor_row["status"] == "warn" and doctor_row["reason_code"] == "cowork_plugin_stale"

    source = tmp_path / "bin" / "defenseclaw-hook-guard.exe"
    source.parent.mkdir()
    source.write_bytes(b"MZ current guard")
    current = _windows_hooks_doc(source, tmp_path / "account", tmp_path / "bin" / "defenseclaw-hook.exe")
    archive.write_bytes(_with_windows_drive_paths(cowork.plugin_zip_bytes(current, "1.0.9-test", "1.0.9")))
    assert cowork.cowork_status(app.cfg, health, gateway_running=True).protected


def test_gateway_activity_before_the_build_is_not_protection(app) -> None:
    cowork.save_state(_data_dir(app), {"build": 4, "version": "1.0.4", "built_at": _now(-60)})
    _write_gateway_activity(app, _now(-600))

    row = cowork.cowork_status(app.cfg, {"connectors": [{"name": "claudecode"}]}, gateway_running=True)

    assert not row.protected and row.reason_code == "cowork_no_events"
    assert "earlier plugin build" in row.detail


def test_plugin_write_refusal_is_one_sentence(tmp_path) -> None:
    """GAP-0054: a refused plugin folder ends in one sentence, not a traceback."""
    message = cowork.plugin_write_refusal(str(tmp_path), OSError("refusing to protect foreign-owned directory: x"))
    assert message.startswith("Cannot build the Cowork plugin in ")
    assert message.endswith("defenseclaw setup cowork again.")


def test_plugin_write_refusal_names_the_administrators_owner_and_the_fix(tmp_path, monkeypatch) -> None:
    from defenseclaw import file_permissions

    monkeypatch.setattr(cowork.os, "name", "nt")
    monkeypatch.setattr(file_permissions, "_windows_acl_snapshot", lambda path: ("S-1-5-32-544", False, []))
    monkeypatch.setattr(file_permissions, "_windows_current_user_sid", lambda: "S-1-5-21-1-2-3-1001")
    message = cowork.plugin_write_refusal(str(tmp_path), OSError("refusing"))
    assert (
        "belongs to the Administrators group because it was created from an elevated administrator session" in message
    )
    assert '/setowner "*S-1-5-21-1-2-3-1001"' in message
