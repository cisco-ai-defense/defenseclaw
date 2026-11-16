"""Quickstart must keep an existing connector's workspace and find its hooks."""

from __future__ import annotations

import hashlib
import json
import ntpath
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from click.testing import CliRunner
from defenseclaw import bootstrap, connector_paths
from defenseclaw.commands import cmd_doctor, cmd_init, cmd_status
from defenseclaw.commands.cmd_quickstart import quickstart_cmd
from defenseclaw.config import default_config, load, prepare_fresh_v8_config

_GOLDEN = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "internal/gateway/connector/testdata/hook_registration_every_connector.json"
    ).read_text(encoding="utf-8")
)


def _stage_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, connector: str) -> tuple[Path, Path]:
    home = tmp_path / "home"
    home.mkdir()
    data_dir = home / ".defenseclaw"
    workspace = home / "ws"
    workspace.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("DEFENSECLAW_HOME", str(data_dir))
    monkeypatch.chdir(tmp_path)

    cfg = default_config()
    prepare_fresh_v8_config(cfg)
    cfg.claw.mode = connector
    cfg.guardrail.connector = connector
    cfg.claw.workspace_dir = str(workspace)
    cfg.save()

    case = next(
        (
            c
            for c in _GOLDEN["cases"]
            if c["connector"] == connector and c["scope"] == "workspace" and c["os"] == "posix"
        ),
        None,
    )
    if case is None:
        # Kiro reads project hooks too; the Go golden only has
        # their user-scope render because Setup's primary file is global.
        relative = {
            "kiro": ".kiro/hooks/defenseclaw.json",
        }[connector]
        path = workspace / relative
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"hooks": [{"command": f"defenseclaw {connector}-hook.sh"}]}), encoding="utf-8")
        paths = [str(path)]
    else:
        paths = []
        for file in case["files"]:
            path = Path(file["path"].replace("{home}", str(home)).replace("{data_dir}", str(data_dir)))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                file["content"].replace("{home}", str(home)).replace("{data_dir}", str(data_dir)),
                encoding="utf-8",
            )
            paths.append(str(path))
    lock = data_dir / "hook_contract_lock.json"
    lock.write_text(
        json.dumps({"version": 2, "connectors": {connector: {"locations": {"hook_config_paths": paths}}}}),
        encoding="utf-8",
    )
    lock.chmod(0o600)
    return workspace, Path(paths[0])


def _first_run(connector: str):
    return bootstrap.run_first_run(
        bootstrap.FirstRunOptions(
            connector=connector,
            profile="observe",
            skip_install=True,
            start_gateway=False,
            verify=True,
        )
    )


@pytest.mark.skipif(sys.platform == "win32", reason="the shared golden case is POSIX")
def test_devin_workspace_survives_real_first_run_and_agrees_with_status_doctor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, hooks = _stage_workspace(tmp_path, monkeypatch, "devin")
    original_hash = hashlib.sha256(hooks.read_bytes()).hexdigest()
    observed: list[str] = []
    readiness = bootstrap._connector_readiness

    def observe(cfg, connector):
        observed.append(cfg.claw.workspace_dir)
        return readiness(cfg, connector)

    monkeypatch.setattr(bootstrap, "_connector_readiness", observe)
    report = _first_run("devin")
    saved = load()
    assert any(step.name == "Connector" for step in report.readiness), [
        (step.name, step.status, step.detail) for step in report.setup
    ]
    connector_step = next(step for step in report.readiness if step.name == "Connector")

    assert observed == [str(workspace)]
    assert (connector_step.status, connector_step.detail) == ("pass", "Devin project hooks found")
    assert saved.claw.workspace_dir == str(workspace)
    assert "workspace (" + str(workspace) + ")" == cmd_status._connector_scope_text(saved)
    assert cmd_status._hook_runtime_degraded_suffix(saved, "devin") == ""
    doctor = cmd_doctor._DoctorResult(passive=True)
    cmd_doctor._check_connector_hooks(saved, "devin", doctor)
    assert any(row["label"] == "Devin hooks" and row["status"] == "pass" for row in doctor.checks)
    assert hashlib.sha256(hooks.read_bytes()).hexdigest() == original_hash


@pytest.mark.skipif(sys.platform == "win32", reason="the shared golden case is POSIX")
@pytest.mark.parametrize("connector", ["copilot",  "kiro"])
def test_real_first_run_keeps_workspace_hook_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, connector: str
) -> None:
    workspace, hooks = _stage_workspace(tmp_path, monkeypatch, connector)

    report = _first_run(connector)
    assert any(item.name == "Connector" for item in report.readiness), report.to_dict()
    step = next(item for item in report.readiness if item.name == "Connector")
    saved = load()

    assert step.status == "pass", step.detail
    assert saved.claw.workspace_dir == str(workspace)
    assert hooks.is_file()
    assert cmd_status._connector_scope_text(saved) == f"workspace ({workspace})"
    assert cmd_doctor._workspace_dir(saved) == str(workspace)


@pytest.mark.skipif(sys.platform == "win32", reason="the staged golden case is POSIX")
def test_other_connector_keeps_existing_first_run_scope_transition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stage_workspace(tmp_path, monkeypatch, "devin")

    report = _first_run("codex")

    assert any(item.name == "Connector" for item in report.readiness), report.to_dict()
    assert load().claw.workspace_dir == ""


@pytest.mark.skipif(sys.platform == "win32", reason="the staged golden case is POSIX")
def test_quickstart_refuses_a_different_connector_without_moving_the_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, _ = _stage_workspace(tmp_path, monkeypatch, "devin")

    result = CliRunner().invoke(quickstart_cmd, ["--connector", "codex", "--force", "--skip-gateway"])

    assert result.exit_code == 2, result.output
    assert "already guards: devin" in result.output
    assert load().claw.workspace_dir == str(workspace)


@pytest.mark.skipif(sys.platform == "win32", reason="the staged golden case is POSIX")
def test_init_adding_copilot_to_pinned_devin_starts_at_global_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, _ = _stage_workspace(tmp_path, monkeypatch, "devin")

    result = CliRunner().invoke(
        cmd_init.init_cmd,
        [
            "--non-interactive",
            "--action-connectors",
            "devin,copilot",
            "--no-start-gateway",
            "--no-verify",
            "--skip-install",
        ],
    )

    assert result.exit_code == 0, result.output
    saved = load()
    assert saved.claw.workspace_dir == ""
    assert saved.active_connectors() == ["copilot", "devin"]
    assert str(workspace) not in result.output


@pytest.mark.skipif(sys.platform == "win32", reason="the staged golden case is POSIX")
def test_init_rerunning_pinned_devin_keeps_project_hooks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace, _ = _stage_workspace(tmp_path, monkeypatch, "devin")

    result = CliRunner().invoke(
        cmd_init.init_cmd,
        ["--non-interactive", "--connector", "devin", "--no-start-gateway", "--skip-install"],
    )

    assert result.exit_code == 0, result.output
    saved = load()
    assert saved.claw.workspace_dir == str(workspace)
    assert saved.active_connectors() == ["devin"]
    assert "Devin project hooks found" in result.output


@pytest.mark.skipif(sys.platform == "win32", reason="the staged golden case is POSIX")
def test_backend_adding_copilot_to_pinned_devin_starts_at_global_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stage_workspace(tmp_path, monkeypatch, "devin")
    primary = {
        "connector": "devin",
        "profile": "observe",
        "fail_mode": None,
        "human_approval": None,
        "hilt_min_severity": None,
    }
    extra = {**primary, "connector": "copilot"}

    report = bootstrap.run_first_run(
        bootstrap.FirstRunOptions(
            connector="devin",
            connector_settings=[primary, extra],
            profile="observe",
            skip_install=True,
            start_gateway=False,
            verify=False,
        )
    )
    assert report.status != "needs_attention", report.to_dict()
    activated, _ = cmd_init._activate_additional_connectors(primary, [extra], start_gateway=False, quiet=True)

    saved = load()
    assert activated == ["copilot", "devin"]
    assert saved.claw.workspace_dir == ""
    assert saved.active_connectors() == ["copilot", "devin"]


@pytest.mark.skipif(sys.platform == "win32", reason="the staged golden case is POSIX")
def test_missing_hooks_warn_without_unpinning_the_selected_connector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, hooks = _stage_workspace(tmp_path, monkeypatch, "devin")
    hooks.unlink()

    report = _first_run("devin")

    step = next(item for item in report.readiness if item.name == "Connector")
    assert (step.status, step.detail) == ("skip", "Devin hooks not found yet — written when the gateway starts")
    saved = load()
    assert saved.claw.workspace_dir == str(workspace)
    assert bootstrap._connector_readiness(saved, "devin").status == "warn"


@pytest.mark.skipif(sys.platform == "win32", reason="the staged golden case is POSIX")
def test_failed_first_run_restores_the_pinned_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace, _ = _stage_workspace(tmp_path, monkeypatch, "devin")
    original_config = (Path(os.environ["DEFENSECLAW_HOME"]) / "config.yaml").read_bytes()
    monkeypatch.setattr(
        bootstrap,
        "targeted_readiness",
        lambda _cfg, _options: [bootstrap.StepResult("Injected failure", "fail", "retry")],
    )

    report = _first_run("devin")

    assert any(step.name == "First-run rollback" for step in report.setup)
    assert load().claw.workspace_dir == str(workspace)
    assert (Path(os.environ["DEFENSECLAW_HOME"]) / "config.yaml").read_bytes() == original_config


@pytest.mark.parametrize(
    "connector,relative",
    [
        ("devin", r".devin\hooks.v1.json"),
        ("copilot", r".github\hooks\defenseclaw.json"),
        ("kiro", r".kiro\hooks\defenseclaw.json"),
    ],
)
@pytest.mark.parametrize(
    "stored",
    [
        r"c:\Users\Sample\Repo",
        "C:/Users/Sample/Repo/",
        r"C:\Users/Sample\Repo/",
        r"C:\Users\Sample\Repo\\",
        r"C:\Users\SAMPLE~1\Repo",
        r"~\Repo",
        r"%USERPROFILE%\Repo",
    ],
)
def test_windows_path_forms_use_the_status_doctor_workspace_resolver(
    monkeypatch: pytest.MonkeyPatch, connector: str, relative: str, stored: str
) -> None:
    # A Windows path cannot be made into a real directory on a POSIX runner.
    # Keep the shared Config resolver as the boundary and emulate isfile with
    # ntpath, as the native Windows filesystem does.
    workspace = r"C:\Users\Sample\Repo"
    expected = ntpath.normcase(ntpath.join(workspace, relative))
    seen: list[str] = []

    def file_exists(path: str) -> bool:
        seen.append(path)
        return ntpath.normcase(ntpath.normpath(path)) == expected

    cfg = SimpleNamespace(
        claw=SimpleNamespace(workspace_dir=stored),
        connector_workspace_dir=lambda: workspace,
    )
    monkeypatch.setattr(connector_paths, "_workspace_dir", lambda raw=None: raw or "")
    monkeypatch.setattr(bootstrap.os.path, "isfile", file_exists)

    step = bootstrap._connector_readiness(cfg, connector)

    assert step.status == "pass", (connector, stored, seen)
    assert cmd_status._connector_scope_text(cfg) == f"workspace ({workspace})"
    assert cmd_doctor._workspace_dir(cfg) == workspace
    assert any(ntpath.normcase(ntpath.normpath(path)) == expected for path in seen)
