# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Authenticated native Windows uninstall handoff tests."""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_uninstall
from defenseclaw.commands import windows_native_uninstall as native
from defenseclaw.file_permissions import UnsafePathError

_VERSION = "1.2.3"
_SOURCE = "0123456789abcdef0123456789abcdef01234567"


def _request(root: Path, *, wipe_data: bool = False) -> native.NativeWindowsUninstallRequest:
    setup = root / "DefenseClawSetup-x64.exe"
    argv = [str(setup), "/uninstall", "/quiet"]
    if wipe_data:
        argv.append("DELETEUSERDATA=1")
    return native.NativeWindowsUninstallRequest(
        platform_name="win32",
        wipe_data=wipe_data,
        install_root=str(root / "Programs" / "DefenseClaw"),
        state_path=str(root / "install-state.json"),
        payload_manifest_path=str(root / "payload-manifest.json"),
        setup_path=str(setup),
        version=_VERSION,
        source_commit=_SOURCE,
        state_sha256="1" * 64,
        payload_manifest_sha256="2" * 64,
        argv=tuple(argv),
    )


def _write_pe(path: Path, *, machine: int = 0x8664, source: str = _SOURCE) -> None:
    image = bytearray(256)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (64).to_bytes(4, "little")
    image[64:68] = b"PE\0\0"
    image[68:70] = machine.to_bytes(2, "little")
    image.extend(f"defenseclaw-setup-{source}".encode())
    path.write_bytes(image)


@contextlib.contextmanager
def _ordinary_setup_stream(path: str):
    with open(path, "rb") as stream:
        yield stream


def _install_state(local_app_data: Path, profile: Path) -> dict[str, object]:
    install_root = local_app_data / "Programs" / "DefenseClaw"
    return {
        "schema_version": 1,
        "version": _VERSION,
        "source_commit": _SOURCE,
        "distribution_flavor": "oss",
        "install_kind": "native-windows-exe",
        "install_scope": "user",
        "install_root": str(install_root),
        "command_dir": str(install_root / "bin"),
        "data_root": str(profile / ".defenseclaw"),
        "runtime": str(install_root / "runtime" / "python"),
        "maintenance_path": str(
            local_app_data / "DefenseClaw" / "InstallerCache" / "DefenseClawSetup-x64.exe"
        ),
        "path_entry_owned": True,
        "connector": "codex",
        "mode": "observe",
        "unsigned_local_artifact": False,
        "release_signing_required": True,
        "toolchain": {"go": "go1.25.0"},
        "installed_at_utc": "2026-07-28T12:00:00Z",
        "transaction_id": "1" * 32,
    }


def _payload_manifest() -> dict[str, object]:
    return {
        "schema_version": 2,
        "version": _VERSION,
        "source_commit": _SOURCE,
        "distribution_flavor": "oss",
        "python_version": "3.13.7",
        "gateway_archive": "gateway.zip",
        "wheel": "cli.whl",
        "python_embed": "python.zip",
        "yara_compat_wheel": "yara.whl",
        "upgrade_manifest": "upgrade-manifest.json",
        "site_packages": "site-packages.zip",
        "launcher": "defenseclaw.cmd",
        "startup_launcher": "defenseclaw-startup.exe",
        "cosign_verifier": "cosign.exe",
        "unsigned": False,
        "authenticode": {"schema_version": 1, "files": {}},
        "toolchain": {"go": "go1.25.0"},
        "files": {"defenseclaw-hook-launcher.exe": "3" * 64},
    }


def _native_tree(root: Path) -> tuple[Path, Path]:
    local_app_data = root / "known-local"
    profile = root / "known-profile"
    installer = local_app_data / "Programs" / "DefenseClaw" / "installer"
    cache = local_app_data / "DefenseClaw" / "InstallerCache"
    installer.mkdir(parents=True)
    cache.mkdir(parents=True)
    profile.mkdir()
    (installer / "install-state.json").write_text(
        json.dumps(_install_state(local_app_data, profile)),
        encoding="utf-8",
    )
    (installer / "payload-manifest.json").write_text(
        json.dumps(_payload_manifest()),
        encoding="utf-8",
    )
    _write_pe(cache / "DefenseClawSetup-x64.exe")
    return local_app_data, profile


def _prepare_from_tree(
    local_app_data: Path,
    profile: Path,
    *,
    wipe_data: bool = False,
) -> native.NativeWindowsUninstallRequest | None:
    folders = {
        native._LOCAL_APP_DATA_FOLDER_ID: str(local_app_data),
        native._PROFILE_FOLDER_ID: str(profile),
    }
    with (
        patch.object(native, "_known_folder_path", side_effect=folders.__getitem__),
        patch.object(native, "_validate_private_path"),
    ):
        return native.prepare_native_windows_uninstall(
            wipe_data=wipe_data,
            platform_name="win32",
        )


def test_prepare_uses_known_folders_and_exact_fixed_argv(tmp_path: Path) -> None:
    local_app_data, profile = _native_tree(tmp_path)

    request = _prepare_from_tree(local_app_data, profile, wipe_data=True)

    assert request is not None
    assert request.argv == (
        str(local_app_data / "DefenseClaw" / "InstallerCache" / "DefenseClawSetup-x64.exe"),
        "/uninstall",
        "/quiet",
        "DELETEUSERDATA=1",
    )
    assert request.install_root == str(local_app_data / "Programs" / "DefenseClaw")
    assert request.version == _VERSION
    assert request.source_commit == _SOURCE


def test_prepare_non_windows_leaves_generic_flow_unchanged() -> None:
    with patch.object(native, "_known_folder_path") as known_folder:
        assert native.prepare_native_windows_uninstall(wipe_data=False, platform_name="linux") is None
    known_folder.assert_not_called()


def test_prepare_ignores_environment_shadow_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    known_local = tmp_path / "known-local"
    known_profile = tmp_path / "known-profile"
    shadow = tmp_path / "shadow"
    shadow_state = shadow / "Programs" / "DefenseClaw" / "installer"
    shadow_state.mkdir(parents=True)
    (shadow_state / "install-state.json").write_text("{}", encoding="utf-8")
    known_local.mkdir()
    known_profile.mkdir()
    monkeypatch.setenv("LOCALAPPDATA", str(shadow))
    folders = {
        native._LOCAL_APP_DATA_FOLDER_ID: str(known_local),
        native._PROFILE_FOLDER_ID: str(known_profile),
    }

    with patch.object(native, "_known_folder_path", side_effect=folders.__getitem__):
        assert native.prepare_native_windows_uninstall(wipe_data=False, platform_name="win32") is None


def test_prepare_refuses_missing_cached_setup(tmp_path: Path) -> None:
    local_app_data, profile = _native_tree(tmp_path)
    setup = local_app_data / "DefenseClaw" / "InstallerCache" / "DefenseClawSetup-x64.exe"

    def validate(path: str, *, label: str, directory: bool) -> None:
        del directory
        if os.path.normcase(path) == os.path.normcase(str(setup)):
            raise native.NativeWindowsUninstallRefusal(f"{label} is missing")

    folders = {
        native._LOCAL_APP_DATA_FOLDER_ID: str(local_app_data),
        native._PROFILE_FOLDER_ID: str(profile),
    }
    with (
        patch.object(native, "_known_folder_path", side_effect=folders.__getitem__),
        patch.object(native, "_validate_private_path", side_effect=validate),
        pytest.raises(native.NativeWindowsUninstallRefusal, match="cached native Setup is missing"),
    ):
        native.prepare_native_windows_uninstall(wipe_data=False, platform_name="win32")


def test_prepare_refuses_payload_source_custody_mismatch(tmp_path: Path) -> None:
    local_app_data, profile = _native_tree(tmp_path)
    manifest = local_app_data / "Programs" / "DefenseClaw" / "installer" / "payload-manifest.json"
    value = _payload_manifest()
    value["source_commit"] = "f" * 40
    manifest.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(native.NativeWindowsUninstallRefusal, match="does not match"):
        _prepare_from_tree(local_app_data, profile)


def test_prepare_refuses_unsupported_marker_identity(tmp_path: Path) -> None:
    local_app_data, profile = _native_tree(tmp_path)
    state_path = local_app_data / "Programs" / "DefenseClaw" / "installer" / "install-state.json"
    state = _install_state(local_app_data, profile)
    state["install_kind"] = "pip"
    state_path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(native.NativeWindowsUninstallRefusal, match="signed user installation"):
        _prepare_from_tree(local_app_data, profile)


@pytest.mark.parametrize(
    ("acl_problem", "message"),
    [
        ("owner SID S-1-5-21-other is not the current user", "current-user owned"),
        ("ACL grants write access to untrusted SID S-1-5-32-545", "private DACL"),
    ],
)
def test_private_path_refuses_wrong_owner_and_broad_dacl(
    tmp_path: Path,
    acl_problem: str,
    message: str,
) -> None:
    target = tmp_path / "state.json"
    target.write_text("{}", encoding="utf-8")
    with (
        patch("defenseclaw.file_permissions.reject_reparse_path"),
        patch("defenseclaw.file_permissions.windows_acl_write_error", return_value=acl_problem),
        pytest.raises(native.NativeWindowsUninstallRefusal, match=message),
    ):
        native._validate_private_path(str(target), label="native installer state", directory=False)


def test_private_path_refuses_reparse(tmp_path: Path) -> None:
    target = tmp_path / "state.json"
    target.write_text("{}", encoding="utf-8")
    with (
        patch(
            "defenseclaw.file_permissions.reject_reparse_path",
            side_effect=UnsafePathError("reparse point"),
        ),
        pytest.raises(native.NativeWindowsUninstallRefusal, match="reparse point"),
    ):
        native._validate_private_path(str(target), label="native installer state", directory=False)


@pytest.mark.skipif(os.name != "nt", reason="Windows handle custody")
def test_locked_setup_handle_reads_exact_regular_file(tmp_path: Path) -> None:
    setup = tmp_path / "DefenseClawSetup-x64.exe"
    _write_pe(setup)

    with native._open_locked_setup(str(setup)) as stream:
        assert native._portable_executable_machine(stream) == native._IMAGE_FILE_MACHINE_AMD64
        digest, source = native._setup_digest_and_source(stream)

    assert len(digest) == 64
    assert source == _SOURCE


def test_execute_uses_locked_authenticated_setup_and_preserves_3010(tmp_path: Path) -> None:
    request = _request(tmp_path)
    _write_pe(Path(request.setup_path))
    completed = subprocess.CompletedProcess(list(request.argv), 3010, "", "")
    with (
        patch.object(native, "prepare_native_windows_uninstall", return_value=request),
        patch.object(native, "_open_locked_setup", side_effect=_ordinary_setup_stream),
        patch.object(native, "_validate_private_path"),
        patch.object(native, "_verify_setup_authenticode") as verify,
        patch.object(native.subprocess, "run", return_value=completed) as run,
    ):
        outcome = native.execute_native_windows_uninstall(request)

    assert outcome.returncode == 3010
    assert outcome.restart_required
    verify.assert_called_once_with(request.setup_path, expected_version=_VERSION)
    assert run.call_args.args[0] == list(request.argv)
    assert run.call_args.kwargs["shell"] is False
    assert run.call_args.kwargs["close_fds"] is True


def test_execute_refuses_replaced_installer_state(tmp_path: Path) -> None:
    request = _request(tmp_path)
    replaced = native.NativeWindowsUninstallRequest(
        **{**request.__dict__, "state_sha256": "f" * 64}
    )
    with (
        patch.object(native, "prepare_native_windows_uninstall", return_value=replaced),
        pytest.raises(native.NativeWindowsUninstallRefusal, match="changed before"),
    ):
        native.execute_native_windows_uninstall(request)


def test_execute_refuses_wrong_architecture(tmp_path: Path) -> None:
    request = _request(tmp_path)
    _write_pe(Path(request.setup_path), machine=0xAA64)
    with (
        patch.object(native, "prepare_native_windows_uninstall", return_value=request),
        patch.object(native, "_open_locked_setup", side_effect=_ordinary_setup_stream),
        patch.object(native, "_validate_private_path"),
        pytest.raises(native.NativeWindowsUninstallRefusal, match="not a Windows x64"),
    ):
        native.execute_native_windows_uninstall(request)


def test_execute_refuses_wrong_source_build_identity(tmp_path: Path) -> None:
    request = _request(tmp_path)
    _write_pe(Path(request.setup_path), source="f" * 40)
    with (
        patch.object(native, "prepare_native_windows_uninstall", return_value=request),
        patch.object(native, "_open_locked_setup", side_effect=_ordinary_setup_stream),
        patch.object(native, "_validate_private_path"),
        pytest.raises(native.NativeWindowsUninstallRefusal, match="source identity differs"),
    ):
        native.execute_native_windows_uninstall(request)


def test_execute_refuses_digest_change_during_authentication(tmp_path: Path) -> None:
    request = _request(tmp_path)
    _write_pe(Path(request.setup_path))
    with (
        patch.object(native, "prepare_native_windows_uninstall", return_value=request),
        patch.object(native, "_open_locked_setup", side_effect=_ordinary_setup_stream),
        patch.object(native, "_validate_private_path"),
        patch.object(native, "_verify_setup_authenticode"),
        patch.object(
            native,
            "_setup_digest_and_source",
            side_effect=[("1" * 64, _SOURCE), ("2" * 64, _SOURCE)],
        ),
        pytest.raises(native.NativeWindowsUninstallRefusal, match="digest changed"),
    ):
        native.execute_native_windows_uninstall(request)


@pytest.mark.parametrize(
    ("publisher", "product_version"),
    [
        ("Other Publisher", _VERSION),
        ("Cisco Systems, Inc.", "9.9.9"),
    ],
)
def test_authenticode_refuses_wrong_signer_or_version_and_checks_fixed_argv(
    publisher: str,
    product_version: str,
) -> None:
    result = subprocess.CompletedProcess(
        [],
        0,
        json.dumps(
            {
                "Status": "Valid",
                "Publisher": publisher,
                "SignatureType": "Authenticode",
                "ProductVersion": product_version,
            }
        ),
        "",
    )
    with (
        patch.object(native, "_system_powershell_path", return_value=r"C:\Windows\powershell.exe"),
        patch.object(native.subprocess, "run", return_value=result) as run,
        pytest.raises(native.NativeWindowsUninstallRefusal, match="not trusted"),
    ):
        native._verify_setup_authenticode(r"C:\cache\DefenseClawSetup-x64.exe", expected_version=_VERSION)

    argv = run.call_args.args[0]
    assert argv[:4] == [
        r"C:\Windows\powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
    ]
    assert argv[-1] == r"C:\cache\DefenseClawSetup-x64.exe"
    assert run.call_args.kwargs["shell"] is False


@pytest.mark.parametrize(
    ("returncode", "expected_text"),
    [
        (0, "uninstall completed"),
        (3010, "restart required"),
        (1603, "refused the uninstall"),
    ],
)
def test_command_dispatches_native_before_generic_guard_with_exact_outcome(
    tmp_path: Path,
    returncode: int,
    expected_text: str,
) -> None:
    request = _request(tmp_path)
    runner = CliRunner()
    with (
        patch.object(native, "prepare_native_windows_uninstall", return_value=request),
        patch.object(
            native,
            "execute_native_windows_uninstall",
            return_value=native.NativeWindowsUninstallOutcome(returncode),
        ) as execute,
        patch.object(cmd_uninstall, "_build_plan") as generic_plan,
    ):
        result = runner.invoke(cmd_uninstall.uninstall_cmd, ["--yes"])

    assert result.exit_code == returncode
    assert expected_text in result.output
    execute.assert_called_once_with(request)
    generic_plan.assert_not_called()


def test_command_native_dry_run_does_not_dispatch(tmp_path: Path) -> None:
    request = _request(tmp_path)
    runner = CliRunner()
    with (
        patch.object(native, "prepare_native_windows_uninstall", return_value=request),
        patch.object(native, "execute_native_windows_uninstall") as execute,
        patch.object(cmd_uninstall, "_build_plan") as generic_plan,
    ):
        result = runner.invoke(cmd_uninstall.uninstall_cmd, ["--dry-run"])

    assert result.exit_code == 0
    assert "dry-run" in result.output
    execute.assert_not_called()
    generic_plan.assert_not_called()


def test_command_without_native_state_uses_existing_generic_path() -> None:
    runner = CliRunner()
    plan = cmd_uninstall.UninstallPlan()
    with (
        patch.object(native, "prepare_native_windows_uninstall", return_value=None),
        patch.object(cmd_uninstall, "_build_plan", return_value=plan) as generic_plan,
        patch.object(cmd_uninstall, "_render_plan"),
        patch.object(cmd_uninstall, "_execute_plan") as execute,
    ):
        result = runner.invoke(cmd_uninstall.uninstall_cmd, ["--yes"])

    assert result.exit_code == 0
    generic_plan.assert_called_once()
    execute.assert_called_once_with(plan)
