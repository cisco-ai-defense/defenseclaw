# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""A 0.8.x per-user Setup install beside this one: companion lookup, older-install refusal, port markers (cowork GAP-0100..0102)."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw import bootstrap  # noqa: E402
from defenseclaw.commands import cmd_uninstall, legacy_setup_install  # noqa: E402


def test_init_reports_this_installs_scanners_not_the_first_on_path() -> None:
    # GAP-0100: with a 0.8.x Setup bin folder first on PATH, shutil.which named its scanners.
    managed = {
        "skill-scanner": r"C:\Users\u\dc\.venv\Scripts\skill-scanner.exe",
        "mcp-scanner": r"C:\Users\u\dc\.venv\Scripts\mcp-scanner.exe",
    }
    with (
        patch.object(bootstrap, "resolve_scanner_binary", side_effect=managed.get),
        patch("shutil.which", return_value=r"C:\Users\u\AppData\Local\Programs\DefenseClaw\bin\skill-scanner.EXE"),
    ):
        steps = bootstrap._scanner_availability(object())  # type: ignore[arg-type]
    assert [s.detail for s in steps] == list(managed.values())
    assert {s.status for s in steps} == {"pass"}


# ---- GAP-0101


def _install(local: Path) -> legacy_setup_install.LegacySetupInstall:
    root = local / "Programs" / "DefenseClaw"
    return legacy_setup_install.LegacySetupInstall(
        root=str(root),
        version="0.8.10",
        data_root=str(local / ".defenseclaw"),
        cache=str(local / "DefenseClaw" / "InstallerCache"),
        hook_state=str(local / "DefenseClaw" / "HookRuntime" / "hook-runtime-state.json"),
    )


def _settings(path: Path, command: str) -> str:
    path.write_text(json.dumps({"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": command}]}]}}))
    return str(path)


def test_hooks_that_run_from_the_0_8_install_are_found(tmp_path: Path) -> None:
    install = _install(tmp_path / "Local")
    exe = os.path.join(install.root, "bin", "defenseclaw-hook.exe")
    runtime = os.path.join(os.path.dirname(install.hook_state), "defenseclaw-hook.exe")
    a = _settings(tmp_path / "a.json", f'"{exe}" hook --connector claudecode')
    b = _settings(tmp_path / "b.json", runtime.upper() + " hook --connector claudecode")
    c = _settings(tmp_path / "c.json", exe.replace("\\", "/") + " hook")
    assert legacy_setup_install.hook_entries(install, [a, b, c]) == [a, b, c]


def test_foreign_hooks_and_other_defenseclaw_folders_are_not_claimed(tmp_path: Path) -> None:
    install = _install(tmp_path / "Local")
    sibling = os.path.join(str(Path(install.root).parent), "DefenseClaw Other", "bin", "defenseclaw-hook.exe")
    files = [
        _settings(tmp_path / "other.json", r"C:\OtherProduct\defenseclaw-hook.exe hook"),
        _settings(tmp_path / "new.json", str(tmp_path / ".local" / "bin" / "defenseclaw-hook.exe") + " hook"),
        _settings(tmp_path / "sibling.json", sibling + " hook"),
        str(tmp_path / "missing.json"),
    ]
    assert legacy_setup_install.hook_entries(install, files) == []


def test_refusal_names_the_install_and_the_next_step(tmp_path: Path) -> None:
    install = _install(tmp_path / "Local")
    text = legacy_setup_install.hook_refusal(install, [r"C:\Users\u\.claude\settings.json"], "defenseclaw init")
    assert "DefenseClaw Setup 0.8.10 at " + install.root in text
    assert r"C:\Users\u\.claude\settings.json" in text
    assert "`defenseclaw uninstall`" in text
    assert "`defenseclaw init` again" in text
    assert "changes nothing" in text


def test_first_run_refuses_before_changing_anything(tmp_path: Path) -> None:
    install = _install(tmp_path / "Local")
    settings = _settings(tmp_path / "settings.json", os.path.join(install.root, "bin", "defenseclaw-hook.exe") + " hook")
    with (
        patch.object(legacy_setup_install, "find", return_value=install),
        patch.object(bootstrap, "connector_config_files", return_value=[settings]),
    ):
        refusal = bootstrap._first_run_legacy_hook_refusal(("claudecode", "none"), "defenseclaw init")
    assert "defenseclaw uninstall" in refusal and settings in refusal


def test_first_run_without_a_0_8_install_is_unchanged(tmp_path: Path) -> None:
    with patch.object(legacy_setup_install, "find", return_value=None):
        assert bootstrap._first_run_legacy_hook_refusal(("claudecode",), "defenseclaw init") == ""


def test_a_0_8_install_without_hooks_in_the_settings_does_not_stop_init(tmp_path: Path) -> None:
    install = _install(tmp_path / "Local")
    settings = _settings(tmp_path / "settings.json", r"C:\OtherProduct\hook.exe")
    with (
        patch.object(legacy_setup_install, "find", return_value=install),
        patch.object(bootstrap, "connector_config_files", return_value=[settings]),
    ):
        assert bootstrap._first_run_legacy_hook_refusal(("claudecode",), "defenseclaw init") == ""


# ---- GAP-0102


@pytest.mark.parametrize(
    ("stop_gateway", "stopped", "expected"),
    [
        (True, True, 1),  # the default uninstall: gateway stopped, data and programs kept
        (True, False, 0),  # nothing was running to stop
        (False, True, 0),  # the gateway may still run
    ],
)
def test_uninstall_drops_this_accounts_port_claims(stop_gateway, stopped, expected) -> None:
    plan = cmd_uninstall.UninstallPlan(
        platform_name="win32",
        data_dir=r"C:\Users\u\.defenseclaw",
        install_root=r"C:\Users\u\.local\bin",
        stop_gateway=stop_gateway,
        remove_data_dir=True,
        remove_binaries=True,
    )
    with (
        patch.object(cmd_uninstall, "_validate_plan"),
        patch.object(cmd_uninstall, "_stop_gateway", return_value=stopped),
        patch.object(cmd_uninstall, "_configured_claim_ports", return_value=frozenset({18970})),
        patch.object(cmd_uninstall, "_connector_teardown"),
        patch.object(cmd_uninstall, "_sandbox_teardown"),
        patch.object(cmd_uninstall, "_turn_guardrail_off"),
        patch.object(cmd_uninstall, "_remove_probe_created_state"),
        patch.object(cmd_uninstall, "_remove_created_dirs"),
        patch.object(cmd_uninstall, "_remove_orphan_copilot_plugin"),
        patch.object(cmd_uninstall, "_remove_mcp_writer_backups"),
        patch.object(cmd_uninstall, "_remove_legacy_codex_candidate"),
        patch.object(cmd_uninstall, "_remove_empty_plugin_cache"),
        patch.object(cmd_uninstall, "_requires_deferred_cleanup", return_value=False),
        patch.object(cmd_uninstall, "_remove_data_dir"),
        patch.object(cmd_uninstall, "_remove_binaries"),
        patch.object(cmd_uninstall, "_render_execution_result"),
        patch.object(cmd_uninstall, "remove_own_api_port_claims") as claims,
    ):
        cmd_uninstall._execute_plan(plan)
    assert claims.call_count == expected
