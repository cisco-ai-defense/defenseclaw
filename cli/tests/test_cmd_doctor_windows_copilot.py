"""Focused native-Windows Copilot Doctor contract regressions."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from defenseclaw.commands.cmd_doctor import (
    _check_copilot_hooks,
    _check_hook_contract_lock,
    _DoctorResult,
)
from defenseclaw.doctor_hooks import (
    _COPILOT_CONTRACT_EVENTS,
    _COPILOT_REQUIRED_HOOKS,
    validate_windows_copilot_hook_registration,
)


def _powershell_command(runtime: Path, event: str) -> str:
    literal = str(runtime).replace("'", "''")
    return (
        "$ErrorActionPreference='Stop'; "
        "$env:NoDefaultCurrentDirectoryInExePath='1'; "
        r"$hookProcess=Microsoft.PowerShell.Management\Start-Process "
        f"-FilePath '{literal}' "
        f"-ArgumentList @('hook','--connector','copilot','--event','{event}') "
        "-NoNewWindow -Wait -PassThru; exit $hookProcess.ExitCode"
    )


def _fixture(
    tmp_path: Path,
    *,
    contract_id: str = "copilot-hooks-v2",
    workspace: bool = False,
    record_location: bool = True,
) -> tuple[Path, Path, Path]:
    install = tmp_path / "DefenseClaw Install"
    data = tmp_path / ".defenseclaw"
    config = (
        tmp_path / "repo" / ".github" / "hooks" / "defenseclaw.json"
        if workspace
        else tmp_path / ".copilot" / "hooks" / "defenseclaw.json"
    )
    install.mkdir()
    data.mkdir()
    config.parent.mkdir(parents=True)
    runtime = install / "defenseclaw-hook.exe"
    runtime.write_bytes(b"MZfixture")
    required_hooks = _COPILOT_CONTRACT_EVENTS[contract_id]
    hooks = {
        event: [
            {
                "type": "command",
                "powershell": _powershell_command(runtime, event),
                "timeoutSec": 30,
            }
        ]
        for event in required_hooks
    }
    config.write_text(json.dumps({"version": 1, "hooks": hooks}), encoding="utf-8")
    locations = {"hook_config_paths": [str(config)]} if record_location else {}
    agent_version = "1.0.75" if contract_id == "copilot-hooks-v1" else "1.0.76"
    lock = {
        "version": 2,
        "connectors": {
            "copilot": {
                "contract_id": contract_id,
                "compatibility_status": "known",
                "raw_agent_version": agent_version,
                "normalized_agent_version": agent_version,
                "hook_script_version": "v7",
                "locations": locations,
            }
        },
    }
    (data / "hook_contract_lock.json").write_text(json.dumps(lock), encoding="utf-8")
    return install, data, config


def _validate(install: Path, data: Path, config: Path):
    return validate_windows_copilot_hook_registration(
        config_path=str(config),
        data_dir=str(data),
        install_root=str(install),
        search_path=str(install),
        pathext=".EXE;.CMD",
    )


def test_windows_copilot_doctor_accepts_complete_synchronous_contract(tmp_path: Path) -> None:
    install, data, config = _fixture(tmp_path)

    check = _validate(install, data, config)

    assert check.state == "healthy", check.detail
    assert f"entries={len(_COPILOT_REQUIRED_HOOKS)}" in check.detail
    assert "contract=copilot-hooks-v2" in check.detail
    assert check.target.endswith("defenseclaw-hook.exe")


def test_windows_copilot_doctor_accepts_bounded_v1_contract(tmp_path: Path) -> None:
    install, data, config = _fixture(tmp_path, contract_id="copilot-hooks-v1")

    check = _validate(install, data, config)

    assert check.state == "healthy", check.detail
    assert f"entries={len(_COPILOT_CONTRACT_EVENTS['copilot-hooks-v1'])}" in check.detail
    assert "contract=copilot-hooks-v1" in check.detail


def test_windows_copilot_services_and_contract_rows_share_deep_validator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install, data, config = _fixture(tmp_path)
    cfg = SimpleNamespace(
        data_dir=str(data),
        claw=SimpleNamespace(workspace_dir=""),
        deployment_mode="single_user",
    )
    monkeypatch.setattr(
        "defenseclaw.inventory.agent_discovery._windows_acl_write_error",
        lambda _path: None,
    )

    services = _DoctorResult()
    _check_copilot_hooks(
        cfg,
        services,
        platform_name="nt",
        config_path=str(config),
        install_root=str(install),
        search_path=str(install),
        pathext=".EXE;.CMD",
    )
    assert services.checks[-1]["status"] == "pass", services.checks[-1]

    contract = _DoctorResult()
    _check_hook_contract_lock(
        cfg,
        "copilot",
        contract,
        platform_name="nt",
        config_path=str(config),
        install_root=str(install),
        search_path=str(install),
        pathext=".EXE;.CMD",
    )
    assert contract.checks[-1]["status"] == "pass", contract.checks[-1]
    assert "runtime_state" not in contract.checks[-1]["detail"]


def test_windows_copilot_workspace_uses_native_repository_registration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install, data, config = _fixture(tmp_path, workspace=True, record_location=False)
    cfg = SimpleNamespace(
        data_dir=str(data),
        claw=SimpleNamespace(workspace_dir=str(tmp_path / "repo")),
        deployment_mode="single_user",
    )
    monkeypatch.setattr(
        "defenseclaw.inventory.agent_discovery._windows_acl_write_error",
        lambda _path: None,
    )

    result = _DoctorResult()
    _check_copilot_hooks(
        cfg,
        result,
        platform_name="nt",
        install_root=str(install),
        search_path=str(install),
        pathext=".EXE;.CMD",
    )

    assert result.failed == 0, result.checks
    assert result.checks[-1]["status"] == "pass"
    assert "healthy Windows-native Copilot" in result.checks[-1]["detail"]
    assert config.is_file()


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("duplicated-call-operator", "duplicated call operator"),
        ("legacy-unbound-command", "synchronous wait/stdin/stdout/exit contract"),
        ("missing-event", "is missing"),
        ("wrong-event-binding", "handler is bound to"),
        ("wrong-timeout", "expected 30"),
        ("mixed-command-fields", "mixes the Windows powershell handler"),
        ("disabled", "disableAllHooks"),
        ("split-target", "inconsistent PowerShell targets"),
    ],
)
def test_windows_copilot_doctor_classifies_tamper(
    tmp_path: Path,
    mutation: str,
    expected: str,
) -> None:
    install, data, config = _fixture(tmp_path)
    document = json.loads(config.read_text(encoding="utf-8"))
    if mutation == "duplicated-call-operator":
        document["hooks"]["preToolUse"][0]["powershell"] = (
            f"& & '{install / 'defenseclaw-hook.exe'}' hook --connector copilot"
        )
    elif mutation == "legacy-unbound-command":
        document["hooks"]["preToolUse"][0]["powershell"] = (
            "$ErrorActionPreference='Stop'; "
            "$env:NoDefaultCurrentDirectoryInExePath='1'; "
            r"$hookProcess=Microsoft.PowerShell.Management\Start-Process "
            f"-FilePath '{install / 'defenseclaw-hook.exe'}' "
            "-ArgumentList @('hook','--connector','copilot') "
            "-NoNewWindow -Wait -PassThru; exit $hookProcess.ExitCode"
        )
    elif mutation == "missing-event":
        document["hooks"].pop("permissionRequest")
    elif mutation == "wrong-event-binding":
        document["hooks"]["preToolUse"][0]["powershell"] = _powershell_command(
            install / "defenseclaw-hook.exe",
            "postToolUse",
        )
    elif mutation == "wrong-timeout":
        document["hooks"]["agentStop"][0]["timeoutSec"] = 29
    elif mutation == "mixed-command-fields":
        document["hooks"]["preToolUse"][0]["bash"] = "foreign"
    elif mutation == "disabled":
        document["disableAllHooks"] = True
    elif mutation == "split-target":
        alternate = install / "alternate" / "defenseclaw-hook.exe"
        alternate.parent.mkdir()
        alternate.write_bytes(b"MZfixture")
        document["hooks"]["preToolUse"][0]["powershell"] = _powershell_command(
            alternate,
            "preToolUse",
        )
    config.write_text(json.dumps(document), encoding="utf-8")

    check = _validate(install, data, config)

    assert not check.healthy
    assert expected in check.detail
    assert "setup copilot --yes --restart" in check.detail
