# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import tomllib
from click.testing import CliRunner
from defenseclaw import connector_paths
from defenseclaw import credential_protection as credential_protection_module
from defenseclaw.commands.cmd_credential_protection import (
    credential_protection,
    setup_credential_protection,
)
from defenseclaw.commands.cmd_doctor import _check_credential_protection, _DoctorResult
from defenseclaw.commands.cmd_setup import setup
from defenseclaw.commands.cmd_status import (
    _credential_protection_payload,
    _print_credential_protection_status,
)
from defenseclaw.context import AppContext
from defenseclaw.credential_protection import (
    CredentialProtectionError,
    ModuleResources,
    _credential_gateway_lifecycle,
    _driver_environment,
    _privileged_gateway_binary,
    _registered_mcp_environment,
    _sgw_environment,
    _trusted_execution_environment,
    credential_protection_default_enabled,
    has_sgw_mcp_registrations,
    install_module,
    launch_agent,
    mcp_connector_status,
    mcp_reconciliation_failed,
    mcp_removal_failed,
    open_broker,
    reconcile_mcp_connector_roster,
    reconcile_mcp_connectors,
    remove_managed_mcp_connectors,
    resolve_module_resources,
    rollback_mcp_reconciliation,
    rollback_mcp_removal,
    safe_status,
    setup_broker,
    setup_broker_for_runtime,
)
from defenseclaw.main import cli


class FakeProcess:
    def __init__(self, replies: list[subprocess.CompletedProcess[str]]):
        self.replies = list(replies)
        self.calls: list[tuple[list[str], dict]] = []

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        if not self.replies:
            raise AssertionError(f"unexpected process call: {argv}")
        return self.replies.pop(0)


def _completed(document: dict, returncode: int = 0, *, stderr: str = ""):
    return subprocess.CompletedProcess([], returncode, json.dumps(document), stderr)


def _driver_error(code: str):
    return _completed(
        {},
        returncode=1,
        stderr=json.dumps({"schema_version": 1, "error": {"code": code, "message": "redacted"}}),
    )


def _module_status(state: str = "ready", ready: bool = True) -> dict:
    return {
        "schema_version": 1,
        "state": state,
        "ready": ready,
        "components": {
            "approval_ui": {
                "required": True,
                "available": True,
                "redistribution_status": "approved",
            }
        },
        "node": {"path": "/private/node", "version": "22.4.1", "minimum": "20.0.0"},
        "module": {
            "installed": state == "ready",
            "version": "0.1.19",
            "path": "/private/package",
        },
    }


def _command_document(extra: list[str] | None = None) -> dict:
    return {
        "schema_version": 1,
        "argv": ["/usr/local/bin/node", "/tmp/sgw-package/dist/cli.js", *(extra or [])],
        "cwd": "/tmp/sgw-package",
        "env": {
            "SGW_EXECUTION_ENGINE": "rust",
            "SGW_AGENT_NAME": "DefenseClaw",
            "SGW_DISABLE_UPDATE_CHECK": "1",
        },
    }


def _mcp_command_document() -> dict:
    document = _command_document()
    document["argv"][1] = "/tmp/sgw-package/dist/mcp-server.js"
    return document


def _test_registered_mcp_env(connector: str = "codex") -> dict[str, str]:
    return _registered_mcp_environment(dict(_mcp_command_document()["env"]), connector)


def _managed_mcp_entry(
    data_dir: str,
    generation: str = "0.2.0-test-linux-x64-g1",
    *,
    connector: str = "codex",
) -> dict:
    entrypoint = Path(data_dir) / "modules" / "s-gw" / generation / "package" / "dist" / "mcp-server.js"
    return {
        "command": "/usr/local/bin/node",
        "args": [str(entrypoint)],
        "env": _test_registered_mcp_env(connector),
    }


def _managed_mcp_command_document(
    data_dir: str,
    generation: str,
    *,
    command: str = "/usr/local/bin/node",
    connector: str = "codex",
) -> dict:
    entry = _managed_mcp_entry(data_dir, generation, connector=connector)
    entry["command"] = command
    document = _mcp_command_document()
    document["argv"] = [entry["command"], *entry["args"]]
    document["cwd"] = str(Path(entry["args"][0]).parents[1])
    return document


def _resources(tmp_path: Path, *, with_artifact: bool = False) -> ModuleResources:
    driver = tmp_path / "sgw_module.py"
    manifest = tmp_path / "s-gw-module.json"
    driver.write_text("# fixture\n", encoding="utf-8")
    manifest.write_text('{"schema_version":1}', encoding="utf-8")
    if not with_artifact:
        return ModuleResources(driver, manifest)
    artifact = tmp_path / "module.tar.gz"
    artifact.write_bytes(b"module archive")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    return ModuleResources(driver, manifest, artifact, digest)


def test_resource_resolver_accepts_root_checksum_with_resource_relative_path(tmp_path, monkeypatch):
    package_data = tmp_path / "sgw"
    artifact = package_data / "modules" / "linux-x64" / "s-gw-module.tar.gz"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"module")
    driver = package_data / "sgw_module.py"
    driver.write_text("# fixture\n", encoding="utf-8")
    manifest = package_data / "s-gw-module.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "artifact": {"resource_template": "_data/sgw/modules/{target}/s-gw-module.tar.gz"},
            }
        ),
        encoding="utf-8",
    )
    expected = hashlib.sha256(artifact.read_bytes()).hexdigest()
    (package_data / "checksums.txt").write_text(
        f"{expected}  modules/linux-x64/s-gw-module.tar.gz\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "defenseclaw.credential_protection._candidate_data_dirs",
        lambda: [package_data, tmp_path / "release"],
    )
    monkeypatch.setattr("defenseclaw.credential_protection._target_name", lambda: "linux-x64")

    resolved = resolve_module_resources()

    assert resolved.artifact == artifact
    assert resolved.artifact_sha256 == expected


def test_fresh_default_requires_a_checksum_verified_staged_artifact(tmp_path, monkeypatch):
    resources = _resources(tmp_path, with_artifact=True)
    monkeypatch.setattr(
        "defenseclaw.credential_protection.resolve_module_resources",
        lambda: resources,
    )

    assert credential_protection_default_enabled() is True

    assert resources.artifact is not None
    resources.artifact.write_bytes(b"tampered")
    assert credential_protection_default_enabled() is False


def test_fresh_default_rejects_missing_digest_and_symlink(tmp_path, monkeypatch):
    resources = _resources(tmp_path, with_artifact=True)
    assert resources.artifact is not None

    monkeypatch.setattr(
        "defenseclaw.credential_protection.resolve_module_resources",
        lambda: ModuleResources(resources.driver, resources.manifest, resources.artifact),
    )
    assert credential_protection_default_enabled() is False

    link = tmp_path / "linked-module.tar.gz"
    link.symlink_to(resources.artifact)
    monkeypatch.setattr(
        "defenseclaw.credential_protection.resolve_module_resources",
        lambda: ModuleResources(resources.driver, resources.manifest, link, resources.artifact_sha256),
    )
    assert credential_protection_default_enabled() is False


def test_fresh_default_is_disabled_when_module_resources_are_missing(monkeypatch):
    def missing_resources():
        raise CredentialProtectionError("driver_missing")

    monkeypatch.setattr(
        "defenseclaw.credential_protection.resolve_module_resources",
        missing_resources,
    )

    assert credential_protection_default_enabled() is False


def test_source_fallback_does_not_mix_partial_packaged_resources(tmp_path, monkeypatch):
    package_data = tmp_path / "package-data"
    source_release = tmp_path / "release"
    source_driver = tmp_path / "scripts" / "sgw_module.py"
    source_driver.parent.mkdir()
    source_driver.write_text("# source fixture\n", encoding="utf-8")
    source_release.mkdir()
    manifest = source_release / "s-gw-module.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "artifact": {
                    "resource_template": "_data/sgw/modules/{target}/s-gw-module.tar.gz",
                },
            }
        ),
        encoding="utf-8",
    )

    partial_artifact = package_data / "modules" / "linux-x64" / "s-gw-module.tar.gz"
    partial_artifact.parent.mkdir(parents=True)
    partial_artifact.write_bytes(b"partial package")
    (package_data / "checksums.txt").write_text(
        f"{hashlib.sha256(partial_artifact.read_bytes()).hexdigest()}  modules/linux-x64/s-gw-module.tar.gz\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "defenseclaw.credential_protection._candidate_data_dirs",
        lambda: [package_data, source_release],
    )
    monkeypatch.setattr("defenseclaw.credential_protection._target_name", lambda: "linux-x64")

    resolved = resolve_module_resources()

    assert resolved.driver == source_driver
    assert resolved.artifact is None
    assert credential_protection_default_enabled() is False


def test_safe_status_returns_only_allowlisted_metadata(tmp_path):
    broker = {
        "ready": True,
        "storePath": "/private/store-with-secret-name",
        "secret_handle": "s-gw:api-token:do-not-print",
        "unlock": {"activeSource": "macos-keychain", "account": "private-user"},
        "macAppPath": {"path": "/Applications/s-gw.app", "exists": True},
    }
    fake = FakeProcess(
        [
            _completed(_module_status()),
            _completed(_command_document(["status"])),
            _completed(broker),
        ]
    )

    status = safe_status(
        str(tmp_path),
        enabled=True,
        resources=_resources(tmp_path),
        runner=fake,
    )

    assert status == {
        "enabled": True,
        "state": "ready",
        "ready": True,
        "installed": True,
        "version": "0.1.19",
        "node_version": "22.4.1",
        "minimum_node_version": "20.0.0",
        "broker_state": "ready",
        "ui_available": True,
        "error_code": "",
    }
    rendered = json.dumps(status)
    assert "do-not-print" not in rendered
    assert "/private" not in rendered
    assert all(kwargs["shell"] is False for _, kwargs in fake.calls)


def test_status_and_broker_processes_do_not_inherit_ambient_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("RAW_API_TOKEN", "raw-secret-that-must-stay-out")
    monkeypatch.setenv("NODE_OPTIONS", "--require=/tmp/untrusted.js")
    fake = FakeProcess(
        [
            _completed(_module_status()),
            _completed(_command_document(["status"])),
            _completed({"ready": True, "unlock": {"activeSource": "macos-keychain"}}),
        ]
    )

    status = safe_status(
        str(tmp_path),
        enabled=True,
        resources=_resources(tmp_path),
        runner=fake,
    )

    assert status["ready"] is True
    for _argv, kwargs in fake.calls:
        assert "RAW_API_TOKEN" not in kwargs["env"]
        assert "NODE_OPTIONS" not in kwargs["env"]
    assert fake.calls[2][1]["env"]["SGW_AGENT_NAME"] == "DefenseClaw"


def test_linux_status_reports_verified_web_approval_console(tmp_path):
    fake = FakeProcess(
        [
            _completed(_module_status()),
            _completed(_command_document(["status"])),
            _completed(
                {
                    "ready": True,
                    "consoleUrl": "http://127.0.0.1:8718/",
                    "unlock": {"activeSource": "secret-service"},
                    "macAppPath": {"exists": False},
                    "windowsClientLauncherPath": {"exists": False},
                }
            ),
        ]
    )

    status = safe_status(
        str(tmp_path),
        enabled=True,
        resources=_resources(tmp_path),
        runner=fake,
    )

    assert status["ready"] is True
    assert status["ui_available"] is True
    assert "consoleUrl" not in status


def test_unverified_web_console_is_not_reported_available(tmp_path):
    module = _module_status()
    module["components"]["approval_ui"]["redistribution_status"] = "not_approved"
    fake = FakeProcess(
        [
            _completed(module),
            _completed(_command_document(["status"])),
            _completed(
                {
                    "ready": True,
                    "consoleUrl": "http://127.0.0.1:8718/",
                    "unlock": {"activeSource": "secret-service"},
                    "macAppPath": {"exists": True},
                }
            ),
        ]
    )

    status = safe_status(
        str(tmp_path),
        enabled=True,
        resources=_resources(tmp_path),
        runner=fake,
    )

    assert status["ui_available"] is False


def test_verified_ui_is_not_reported_available_when_broker_runtime_fails(tmp_path):
    fake = FakeProcess(
        [
            _completed(_module_status()),
            _completed(_command_document(["status"])),
            subprocess.CompletedProcess([], 1, "", "private broker failure"),
        ]
    )

    status = safe_status(
        str(tmp_path),
        enabled=True,
        resources=_resources(tmp_path),
        runner=fake,
    )

    assert status["installed"] is True
    assert status["ready"] is False
    assert status["ui_available"] is False
    assert "private broker failure" not in json.dumps(status)


def test_sgw_json_output_is_bounded_before_json_decode(tmp_path):
    oversized = "import sys; sys.stdout.write('x' * (1024 * 1024 + 1))"
    with patch(
        "defenseclaw.credential_protection._prepare_cli_command",
        return_value=([sys.executable, "-c", oversized], str(tmp_path), {}),
    ):
        from defenseclaw.credential_protection import _run_sgw_json

        with pytest.raises(CredentialProtectionError) as caught:
            _run_sgw_json(str(tmp_path), ["status"])

    assert caught.value.code == "sgw_output_too_large"


def test_safe_status_reports_missing_node_without_running_sgw(tmp_path):
    fake = FakeProcess([_completed(_module_status("node_missing", False))])

    status = safe_status(
        str(tmp_path),
        enabled=True,
        resources=_resources(tmp_path),
        runner=fake,
    )

    assert status["ready"] is False
    assert status["error_code"] == "node_missing"
    assert len(fake.calls) == 1


@pytest.mark.parametrize("bad_home", ["/", "bad\x00home"])
def test_status_rejects_unsafe_home_paths_without_starting_driver(tmp_path, bad_home):
    fake = FakeProcess([])

    status = safe_status(
        bad_home,
        enabled=True,
        resources=_resources(tmp_path),
        runner=fake,
    )

    assert status["error_code"] == "command_invalid"
    assert fake.calls == []


def test_driver_failure_does_not_expose_stderr(tmp_path):
    secret = "raw-secret-that-must-not-escape"
    fake = FakeProcess(
        [
            subprocess.CompletedProcess(
                [],
                1,
                "",
                json.dumps(
                    {
                        "schema_version": 1,
                        "state": "error",
                        "error": {"code": "node_missing", "message": secret},
                    }
                ),
            )
        ]
    )

    status = safe_status(
        str(tmp_path),
        enabled=True,
        resources=_resources(tmp_path),
        runner=fake,
    )

    assert status["error_code"] == "node_missing"
    assert secret not in json.dumps(status)


def test_driver_timeout_is_reported_with_a_safe_code(tmp_path):
    def timed_out(_argv, **_kwargs):
        raise subprocess.TimeoutExpired(["private", "argv"], 30, output="secret-output")

    status = safe_status(
        str(tmp_path),
        enabled=True,
        resources=_resources(tmp_path),
        runner=timed_out,
    )

    assert status["error_code"] == "driver_timeout"
    assert "secret-output" not in json.dumps(status)


def test_driver_output_is_bounded(tmp_path):
    fake = FakeProcess([subprocess.CompletedProcess([], 0, "x" * (1024 * 1024 + 1), "")])

    status = safe_status(
        str(tmp_path),
        enabled=True,
        resources=_resources(tmp_path),
        runner=fake,
    )

    assert status["error_code"] == "driver_output_too_large"


def test_duplicate_driver_json_keys_fail_closed(tmp_path):
    duplicate = '{"schema_version":1,"state":"ready","state":"node_missing"}'
    fake = FakeProcess([subprocess.CompletedProcess([], 0, duplicate, "")])

    status = safe_status(
        str(tmp_path),
        enabled=True,
        resources=_resources(tmp_path),
        runner=fake,
    )

    assert status["error_code"] == "driver_output_invalid"


def test_open_broker_uses_only_the_trusted_native_gateway(tmp_path, monkeypatch):
    gateway = tmp_path / "defenseclaw-gateway"
    data_dir = tmp_path / "data"
    monkeypatch.setenv("NODE_OPTIONS", "--require=/tmp/injected.js")
    monkeypatch.setenv("LD_PRELOAD", "/tmp/injected.so")
    fake = FakeProcess([_completed({"schema_version": 1, "status": "opened"})])

    with patch(
        "defenseclaw.credential_protection._privileged_gateway_binary",
        return_value=str(gateway),
    ):
        open_broker(str(data_dir), gateway_binary=str(gateway), runner=fake)

    argv, kwargs = fake.calls[0]
    assert argv == [
        str(gateway),
        "sgw-console-open",
        "--data-dir",
        str(data_dir),
    ]
    assert kwargs["cwd"] is None
    assert kwargs["shell"] is False
    assert "NODE_OPTIONS" not in kwargs["env"]
    assert "LD_PRELOAD" not in kwargs["env"]


@pytest.mark.parametrize(
    "document",
    [
        {"schema_version": 1, "status": "opened", "token": "must-not-exist"},
        {"schema_version": 1, "status": "unknown"},
        {"schema_version": 2, "status": "opened"},
    ],
)
def test_open_broker_rejects_noncanonical_native_status(tmp_path, document):
    gateway = tmp_path / "defenseclaw-gateway"
    fake = FakeProcess([_completed(document)])
    with patch(
        "defenseclaw.credential_protection._privileged_gateway_binary",
        return_value=str(gateway),
    ):
        with pytest.raises(CredentialProtectionError) as caught:
            open_broker(str(tmp_path / "data"), gateway_binary=str(gateway), runner=fake)
    assert caught.value.code == "sgw_output_invalid"


def test_privileged_gateway_resolver_rejects_symlink(tmp_path):
    target = tmp_path / "real-gateway"
    target.write_text("fixture", encoding="utf-8")
    target.chmod(0o700)
    link = tmp_path / "defenseclaw-gateway"
    link.symlink_to(target)

    with pytest.raises(CredentialProtectionError) as caught:
        _privileged_gateway_binary(str(link))
    assert caught.value.code == "driver_missing"


@pytest.mark.skipif(os.name != "nt", reason="Windows permission projection contract")
def test_privileged_gateway_resolver_accepts_windows_synthetic_mode_bits(tmp_path):
    gateway = tmp_path / "defenseclaw-gateway.exe"
    gateway.write_bytes(b"fixture")

    assert _privileged_gateway_binary(str(gateway)) == os.path.realpath(gateway)


def test_status_never_echoes_untrusted_version_fields(tmp_path):
    document = _module_status()
    document["module"]["version"] = "raw secret / private path"
    fake = FakeProcess([_completed(document)])

    status = safe_status(
        str(tmp_path),
        enabled=True,
        resources=_resources(tmp_path),
        runner=fake,
    )

    assert status["ready"] is False
    assert status["error_code"] == "module_invalid"
    assert "raw secret" not in json.dumps(status)


def test_install_verifies_artifact_and_uses_driver_contract(tmp_path):
    resources = _resources(tmp_path, with_artifact=True)
    ready_to_install = _module_status("ready_to_install", True)
    ready_to_install["module"]["installed"] = False
    fake = FakeProcess(
        [
            _completed(_module_status("not_installed", False)),
            _completed(ready_to_install),
            _completed(_module_status()),
        ]
    )

    result = install_module(str(tmp_path), resources=resources, runner=fake)

    assert result["ready"] is True
    install_argv = fake.calls[2][0]
    assert install_argv[-5:] == [
        "install",
        "--artifact",
        str(resources.artifact),
        "--sha256",
        resources.artifact_sha256,
    ]


def test_install_repairs_a_corrupt_same_release_module(tmp_path):
    resources = _resources(tmp_path, with_artifact=True)
    ready_to_install = _module_status("ready_to_install", True)
    ready_to_install["module"]["installed"] = False
    repaired = _module_status()
    repaired["module"]["path"] = "/private/package-generation-2"
    fake = FakeProcess(
        [
            _driver_error("artifact_invalid"),
            _completed(ready_to_install),
            _completed(repaired),
        ]
    )

    result = install_module(str(tmp_path), resources=resources, runner=fake)

    assert result["ready"] is True
    assert result["module"]["path"] == "/private/package-generation-2"
    assert fake.calls[0][0][-1] == "status"
    assert fake.calls[1][0][-1] == "probe"
    assert fake.calls[2][0][-5] == "install"


def test_setup_is_idempotent_when_module_is_already_installed(tmp_path):
    fake = FakeProcess(
        [
            _completed(_module_status()),
            _completed(
                _command_document(["setup", "--no-open-console", "--no-service", "--no-menubar", "--no-agents"])
            ),
            _completed({"ok": True, "storePath": "/private/store"}),
            _completed(_module_status()),
            _completed(_command_document(["status"])),
            _completed(
                {
                    "ready": True,
                    "unlock": {"activeSource": "macos-keychain"},
                    "macAppPath": {"exists": True},
                }
            ),
        ]
    )

    result = setup_broker(
        str(tmp_path),
        resources=_resources(tmp_path),
        runner=fake,
    )

    assert result["ready"] is True
    assert "storePath" not in result


def test_setup_disables_sgw_agent_autoregistration(tmp_path):
    fake = FakeProcess(
        [
            _completed(_module_status()),
            _completed(
                _command_document(["setup", "--no-open-console", "--no-service", "--no-menubar", "--no-agents"])
            ),
            _completed({"ok": True}),
            _completed(_module_status()),
            _completed(_command_document(["status"])),
            _completed(
                {
                    "ready": True,
                    "unlock": {"activeSource": "macos-keychain"},
                }
            ),
        ]
    )

    setup_broker(
        str(tmp_path),
        resources=_resources(tmp_path),
        runner=fake,
    )

    driver_argv = fake.calls[1][0]
    assert driver_argv[-9:] == [
        "command",
        "--entrypoint",
        "cli",
        "--",
        "setup",
        "--no-open-console",
        "--no-service",
        "--no-menubar",
        "--no-agents",
    ]


def test_windows_broker_repair_stops_and_restarts_running_gateway(tmp_path):
    steps: list[str] = []

    result = setup_broker_for_runtime(
        str(tmp_path),
        already_enabled=True,
        platform_name="win32",
        gateway_was_running=True,
        stop_gateway=lambda: steps.append("stop") or True,
        restart_gateway=lambda: steps.append("restart") or True,
        broker_setup=lambda: steps.append("setup") or {"ready": True},
    )

    assert result == {"ready": True}
    assert steps == ["stop", "setup", "restart"]


def test_windows_broker_lifecycle_uses_privileged_gateway_resolver(tmp_path):
    gateway = tmp_path / "defenseclaw-gateway.exe"
    completed = subprocess.CompletedProcess([], 0, "", "")
    with (
        patch(
            "defenseclaw.credential_protection._privileged_gateway_binary",
            return_value=str(gateway),
        ) as resolve_gateway,
        patch(
            "defenseclaw.credential_protection.shutil.which",
            side_effect=AssertionError("lifecycle must not consult PATH"),
        ),
        patch(
            "defenseclaw.credential_protection.subprocess.run",
            return_value=completed,
        ) as run_gateway,
    ):
        assert _credential_gateway_lifecycle("stop") is True

    resolve_gateway.assert_called_once_with()
    run_gateway.assert_called_once_with(
        [str(gateway), "stop"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_windows_broker_lifecycle_fails_closed_without_trusted_gateway():
    with (
        patch(
            "defenseclaw.credential_protection._privileged_gateway_binary",
            side_effect=CredentialProtectionError("driver_missing"),
        ),
        patch("defenseclaw.credential_protection.subprocess.run") as run_gateway,
    ):
        assert _credential_gateway_lifecycle("restart") is False

    run_gateway.assert_not_called()


def test_windows_broker_repair_restarts_gateway_after_setup_failure(tmp_path):
    steps: list[str] = []

    def fail_setup():
        steps.append("setup")
        raise CredentialProtectionError("sgw_failed")

    with pytest.raises(CredentialProtectionError) as caught:
        setup_broker_for_runtime(
            str(tmp_path),
            already_enabled=True,
            platform_name="win32",
            gateway_was_running=True,
            stop_gateway=lambda: steps.append("stop") or True,
            restart_gateway=lambda: steps.append("restart") or True,
            broker_setup=fail_setup,
        )

    assert caught.value.code == "sgw_failed"
    assert steps == ["stop", "setup", "restart"]


def test_windows_broker_repair_preserves_stopped_gateway_state(tmp_path):
    lifecycle: list[str] = []

    result = setup_broker_for_runtime(
        str(tmp_path),
        already_enabled=True,
        platform_name="win32",
        gateway_was_running=False,
        stop_gateway=lambda: lifecycle.append("stop") or True,
        restart_gateway=lambda: lifecycle.append("restart") or True,
        broker_setup=lambda: {"ready": True},
    )

    assert result == {"ready": True}
    assert lifecycle == []


def test_windows_broker_repair_reports_restart_failure(tmp_path):
    with pytest.raises(CredentialProtectionError) as caught:
        setup_broker_for_runtime(
            str(tmp_path),
            already_enabled=True,
            platform_name="win32",
            gateway_was_running=True,
            stop_gateway=lambda: True,
            restart_gateway=lambda: False,
            broker_setup=lambda: {"ready": True},
        )

    assert caught.value.code == "gateway_lifecycle_failed"


def test_bootstrap_uses_shared_broker_lifecycle_wrapper(tmp_path):
    from defenseclaw.bootstrap import _setup_credential_protection_structured

    cfg = SimpleNamespace(
        data_dir=str(tmp_path),
        credential_protection=SimpleNamespace(enabled=True),
    )
    with (
        patch(
            "defenseclaw.credential_protection.setup_broker_for_runtime",
            return_value={"ready": True, "version": "0.2.0"},
        ) as setup_runtime,
        patch(
            "defenseclaw.credential_protection.reconcile_mcp_connector_roster",
            return_value=[],
        ) as reconcile,
    ):
        result = _setup_credential_protection_structured(
            cfg,
            removed_connectors=["cursor"],
        )

    assert result.status == "pass"
    setup_runtime.assert_called_once_with(str(tmp_path), already_enabled=True)
    reconcile.assert_called_once_with(cfg, removed_connectors=["cursor"])


def test_launch_preserves_argument_boundary_and_child_exit_code(tmp_path):
    launch_args = [
        "guard",
        "run",
        "codex",
        "--command",
        "/usr/local/bin/codex",
        "--",
        "--model",
        "gpt-5",
    ]
    fake = FakeProcess(
        [
            _completed(_command_document(launch_args)),
            subprocess.CompletedProcess([], 7, "", ""),
        ]
    )

    exit_code = launch_agent(
        str(tmp_path),
        "codex",
        ["--model", "gpt-5"],
        command="/usr/local/bin/codex",
        resources=_resources(tmp_path),
        runner=fake,
    )

    assert exit_code == 7
    driver_argv = fake.calls[0][0]
    assert driver_argv[-12:] == [
        "command",
        "--entrypoint",
        "cli",
        "--",
        "guard",
        "run",
        "codex",
        "--command",
        "/usr/local/bin/codex",
        "--",
        "--model",
    ] + ["gpt-5"]
    child_kwargs = fake.calls[1][1]
    assert child_kwargs["shell"] is False
    assert "capture_output" not in child_kwargs
    assert child_kwargs["env"]["SGW_AGENT_NAME"] == "Codex"


def test_launch_uses_minimal_environment_unless_inheritance_is_explicit(tmp_path, monkeypatch):
    monkeypatch.setenv("RAW_API_TOKEN", "raw-secret")
    monkeypatch.setenv("NODE_OPTIONS", "--require=/tmp/untrusted.js")
    monkeypatch.setenv("OPENCODE_CONFIG_DIR", "/tmp/opencode-config")
    launch_args = ["guard", "run", "codex", "--"]
    fake = FakeProcess(
        [
            _completed(_command_document(launch_args)),
            subprocess.CompletedProcess([], 0, "", ""),
        ]
    )

    launch_agent(
        str(tmp_path),
        "codex",
        [],
        resources=_resources(tmp_path),
        runner=fake,
    )

    child_env = fake.calls[1][1]["env"]
    assert "RAW_API_TOKEN" not in child_env
    assert "NODE_OPTIONS" not in child_env
    assert child_env["OPENCODE_CONFIG_DIR"] == "/tmp/opencode-config"
    assert child_env["SGW_AGENT_NAME"] == "Codex"


def test_child_command_lookup_does_not_inherit_ambient_path(monkeypatch):
    monkeypatch.setenv("PATH", "/tmp/untrusted-bin")
    monkeypatch.setenv("SystemRoot", "/tmp/untrusted-windows")
    monkeypatch.setenv("WINDIR", "/tmp/untrusted-windir")

    driver_env = _driver_environment()
    broker_env = _sgw_environment({"SGW_AGENT_NAME": "DefenseClaw"})

    for child_env in (driver_env, broker_env):
        assert "untrusted-bin" not in child_env["PATH"]
        assert child_env.get("SystemRoot") != "/tmp/untrusted-windows"
        assert child_env.get("WINDIR") != "/tmp/untrusted-windir"


def test_registered_mcp_environment_pins_control_environment(monkeypatch):
    hostile = {
        "NODE_OPTIONS": "--require=/tmp/injected.js",
        "NODE_PATH": "/tmp/modules",
        "NPM_CONFIG_NODE_OPTIONS": "--import=/tmp/injected.mjs",
        "NODE_EXTRA_CA_CERTS": "/tmp/ca.pem",
        "OPENSSL_CONF": "/tmp/openssl.cnf",
        "LD_PRELOAD": "/tmp/injected.so",
        "LD_LIBRARY_PATH": "/tmp/lib",
        "LD_AUDIT": "/tmp/audit.so",
        "DYLD_INSERT_LIBRARIES": "/tmp/injected.dylib",
        "DYLD_LIBRARY_PATH": "/tmp/lib",
        "DYLD_FRAMEWORK_PATH": "/tmp/frameworks",
        "DYLD_FALLBACK_LIBRARY_PATH": "/tmp/fallback-lib",
        "DYLD_FALLBACK_FRAMEWORK_PATH": "/tmp/fallback-frameworks",
        "GODEBUG": "http2debug=2",
        "NODE_DEBUG": "child_process",
        "NODE_DEBUG_NATIVE": "tls",
        "NODE_TLS_REJECT_UNAUTHORIZED": "0",
    }
    hostile.update(
        {
            "PATH": "/tmp/untrusted-bin",
            "SGW_HOME": "/tmp/other-store",
            "SGW_HELPER_SETTLE": "1",
            "SGW_LOGIN_SESSION_ID": "foreign-session",
            "SGW_MASTER_PASSPHRASE": "ambient-passphrase",
            "SGW_OP_CLI": "/tmp/fake-op",
            "SGW_RECOVERY_HOME": "/tmp/other-recovery",
            "SGW_SSH_CLI": "/tmp/fake-ssh",
            "SGW_STOP_CLI_PATH": "/tmp/other-cli",
            "SGW_TEST_MODE": "1",
            "SGW_WINDOWS_ACL_TEST_ROOT": "/tmp/acl-root",
            "SGW_WINDOWS_ACL_OPERATION_TIMEOUT_MS": "120000",
            "SGW_WINDOWS_CREDENTIAL_HELPER_TIMEOUT_MS": "120000",
            "SGW_WINDOWS_HELPER_OPERATION_TIMEOUT_MS": "120000",
            "SGW_WINDOWS_PROCESS_INSPECTION_TIMEOUT_MS": "120000",
            "SGW_WINDOWS_STARTUP_OPERATION_TIMEOUT_MS": "120000",
            "SGW_WINDOWS_STARTUP_TEST_ROOT": "/tmp/startup-root",
        }
    )
    for key, value in hostile.items():
        monkeypatch.setenv(key, value)

    env = _registered_mcp_environment(dict(_mcp_command_document()["env"]), "codex")

    assert env["SGW_AGENT_NAME"] == "Codex"
    assert env["DEFENSECLAW_MCP_OWNER"] == "s-gw-credential-protection-v1"
    assert env["SGW_HOME"] == str(Path.home() / ".s-gw")
    assert env["SGW_RECOVERY_HOME"] == str(Path.home() / ".s-gw-recovery")
    if os.name == "nt":
        trusted = _trusted_execution_environment()
        assert {key: env[key] for key in trusted} == trusted
    else:
        assert env["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin"
    assert all(env[key] == "" for key in hostile if key not in {"PATH", "SGW_HOME", "SGW_RECOVERY_HOME"})


def test_registered_mcp_environment_classifies_vendored_sgw_names():
    root = Path(__file__).resolve().parents[2]
    inputs = list((root / "third_party" / "s-gw" / "upstream" / "src").glob("**/*.ts"))
    inputs.extend((root / "third_party" / "s-gw" / "patches").glob("*.patch"))
    names: set[str] = set()
    for path in inputs:
        names.update(re.findall(r"SGW_[A-Z][A-Z0-9_]*", path.read_text(encoding="utf-8")))

    classified = credential_protection_module._MCP_PINNED_SGW_ENV | set(
        credential_protection_module._MCP_NEUTRALIZED_SGW_ENV
    )
    assert names <= classified


def test_windows_children_and_mcp_use_host_resolved_powershell(monkeypatch):
    trusted = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    monkeypatch.setenv("PATH", r"C:\untrusted-bin")
    monkeypatch.setenv("SystemRoot", r"C:\untrusted-root")
    monkeypatch.setenv("WINDIR", r"C:\untrusted-windir")

    with (
        patch("defenseclaw.credential_protection.os.name", "nt"),
        patch(
            "defenseclaw.credential_protection._trusted_windows_powershell",
            return_value=trusted,
        ),
    ):
        broker_env = _sgw_environment({"SGW_AGENT_NAME": "DefenseClaw"})
        mcp_env = _registered_mcp_environment(dict(_mcp_command_document()["env"]), "codex")

    for child_env in (broker_env, mcp_env):
        assert child_env["SGW_TRUSTED_POWERSHELL"] == trusted
        assert child_env["SystemRoot"] == r"C:\Windows"
        assert child_env["WINDIR"] == r"C:\Windows"
        assert "untrusted" not in child_env["PATH"].lower()


def test_launch_can_explicitly_send_ambient_credentials_to_local_guard(tmp_path, monkeypatch):
    monkeypatch.setenv("RAW_API_TOKEN", "raw-secret")
    monkeypatch.setenv("GODEBUG", "http2debug=2")
    monkeypatch.setenv("NODE_OPTIONS", "--require=/tmp/untrusted.js")
    monkeypatch.setenv("NODE_DEBUG", "child_process")
    monkeypatch.setenv("NODE_DEBUG_NATIVE", "tls")
    monkeypatch.setenv("NODE_EXTRA_CA_CERTS", "/tmp/untrusted-ca.pem")
    monkeypatch.setenv("NODE_TLS_REJECT_UNAUTHORIZED", "0")
    monkeypatch.setenv("OPENSSL_CONF", "/tmp/untrusted-openssl.cnf")
    launch_args = ["guard", "run", "codex", "--"]
    fake = FakeProcess(
        [
            _completed(_command_document(launch_args)),
            subprocess.CompletedProcess([], 0, "", ""),
        ]
    )

    launch_agent(
        str(tmp_path),
        "codex",
        [],
        inherit_environment=True,
        resources=_resources(tmp_path),
        runner=fake,
    )

    child_env = fake.calls[1][1]["env"]
    assert child_env["RAW_API_TOKEN"] == "raw-secret"
    assert "GODEBUG" not in child_env
    assert "NODE_DEBUG" not in child_env
    assert "NODE_DEBUG_NATIVE" not in child_env
    assert "NODE_OPTIONS" not in child_env
    assert "NODE_EXTRA_CA_CERTS" not in child_env
    assert "NODE_TLS_REJECT_UNAUTHORIZED" not in child_env
    assert "OPENSSL_CONF" not in child_env


def test_windows_inherited_guard_keeps_path_but_pins_powershell(tmp_path, monkeypatch):
    trusted = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    monkeypatch.setenv("PATH", r"C:\operator-bin")
    monkeypatch.setenv("SystemRoot", r"C:\untrusted-root")
    monkeypatch.setenv("WINDIR", r"C:\untrusted-windir")
    fake = FakeProcess(
        [
            _completed(_command_document(["guard", "run", "codex", "--"])),
            subprocess.CompletedProcess([], 0, "", ""),
        ]
    )

    with (
        patch("defenseclaw.credential_protection.os.name", "nt"),
        patch(
            "defenseclaw.credential_protection._trusted_windows_powershell",
            return_value=trusted,
        ),
    ):
        launch_agent(
            str(tmp_path),
            "codex",
            [],
            inherit_environment=True,
            resources=_resources(tmp_path),
            runner=fake,
        )

    child_env = fake.calls[1][1]["env"]
    assert child_env["PATH"] == r"C:\operator-bin"
    assert child_env["SGW_TRUSTED_POWERSHELL"] == trusted
    assert child_env["SystemRoot"] == r"C:\Windows"
    assert child_env["WINDIR"] == r"C:\Windows"


def test_launch_rejects_relative_explicit_agent_command(tmp_path):
    with pytest.raises(CredentialProtectionError) as caught:
        launch_agent(
            str(tmp_path),
            "codex",
            [],
            command="codex",
            resources=_resources(tmp_path),
            runner=FakeProcess([]),
        )

    assert caught.value.code == "command_invalid"


def test_launch_rejects_nul_in_agent_arguments(tmp_path):
    with pytest.raises(CredentialProtectionError) as caught:
        launch_agent(
            str(tmp_path),
            "codex",
            ["--model", "bad\x00value"],
            resources=_resources(tmp_path),
            runner=FakeProcess([]),
        )

    assert caught.value.code == "command_invalid"


def test_command_description_cannot_escape_installed_package(tmp_path):
    bad = _command_document(["guard", "run", "codex", "--"])
    bad["argv"][1] = "/tmp/other/cli.js"
    fake = FakeProcess([_completed(bad)])

    try:
        launch_agent(
            str(tmp_path),
            "codex",
            [],
            resources=_resources(tmp_path),
            runner=fake,
        )
    except CredentialProtectionError as exc:
        assert exc.code == "command_invalid"
    else:
        raise AssertionError("escaped command was accepted")
    assert len(fake.calls) == 1


def _connector_cfg(tmp_path: Path, connectors: list[str]):
    return SimpleNamespace(
        data_dir=str(tmp_path / "defenseclaw"),
        active_connectors=lambda: list(connectors),
        connector_workspace_dir=lambda: "",
        active_connector=lambda: connectors[0],
        mcp_servers=lambda connector: connector_paths.mcp_servers(connector),
    )


def _workspace_connector_cfg(data_dir: Path, connectors: list[str], workspace: list[Path]):
    return SimpleNamespace(
        data_dir=str(data_dir),
        active_connectors=lambda: list(connectors),
        connector_workspace_dir=lambda: str(workspace[0]),
        active_connector=lambda: connectors[0],
        claw=SimpleNamespace(config_file=""),
    )


def test_reconcile_uses_exact_driver_mcp_command_and_preserves_other_entries(tmp_path):
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    claude_path = home / ".claude.json"
    claude_path.write_text(
        json.dumps(
            {
                "theme": "dark",
                "mcpServers": {
                    "other": {"command": "/usr/bin/other", "args": ["serve"]},
                },
            }
        ),
        encoding="utf-8",
    )
    claude_path.chmod(0o600)
    codex_home = home / ".codex"
    codex_home.mkdir(mode=0o700)
    codex_config = codex_home / "config.toml"
    codex_config.write_text(
        '[mcp_servers.other]\ncommand = "/usr/bin/other"\nargs = ["serve"]\n',
        encoding="utf-8",
    )
    codex_config.chmod(0o600)
    cfg = _connector_cfg(tmp_path, ["claudecode", "codex", "zeptoclaw"])
    managed_entry = _managed_mcp_entry(cfg.data_dir)
    fake = FakeProcess([_completed(_managed_mcp_command_document(cfg.data_dir, "0.2.0-test-linux-x64-g1"))])

    with patch.dict(
        os.environ,
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "CODEX_HOME": str(codex_home),
            "DEFENSECLAW_HOME": cfg.data_dir,
        },
        clear=False,
    ):
        results = reconcile_mcp_connectors(
            cfg,
            resources=_resources(tmp_path),
            runner=fake,
        )

    assert [item["mcp_registration"] for item in results] == [
        "installed",
        "installed",
        "manual",
    ]
    assert results[1]["proxy_prompt_tokenization"] == "not_in_direct_upstream_path"
    assert results[2]["proxy_prompt_tokenization"] == "gateway_runtime_required"
    assert not mcp_reconciliation_failed(results)
    driver_argv = fake.calls[0][0]
    assert driver_argv[-6:] == [
        "--home",
        str(tmp_path / "defenseclaw"),
        "command",
        "--entrypoint",
        "mcp",
        "--",
    ]

    claude = json.loads(claude_path.read_text(encoding="utf-8"))
    assert claude["theme"] == "dark"
    assert claude["mcpServers"]["other"]["command"] == "/usr/bin/other"
    claude_sgw = claude["mcpServers"]["s-gw"]
    assert claude_sgw["command"] == "/usr/local/bin/node"
    assert claude_sgw["args"] == managed_entry["args"]
    assert claude_sgw["env"]["SGW_AGENT_NAME"] == "Claude Code"
    assert claude_sgw["env"]["SGW_HOME"] == str(home / ".s-gw")
    codex_text = codex_config.read_text(encoding="utf-8")
    assert "[mcp_servers.other]" in codex_text
    assert '[mcp_servers."s-gw"]' in codex_text
    assert "npx" not in codex_text
    assert "defenseclaw-tokenizer" not in codex_text
    codex = tomllib.loads(codex_text)
    assert codex["mcp_servers"]["s-gw"]["args"] == managed_entry["args"]
    assert codex["mcp_servers"]["s-gw"]["env"]["SGW_AGENT_NAME"] == "Codex"
    assert claude["mcpServers"]["s-gw"]["env"]["SGW_AGENT_NAME"] == "Claude Code"


def test_reconcile_refuses_conflicting_sgw_entry_without_overwrite(tmp_path):
    current = SimpleNamespace(
        name="s-gw",
        command="npx",
        args=["s-gw-mcp"],
        env={},
        cwd="",
        url="",
        disabled=False,
    )
    cfg = _connector_cfg(tmp_path, ["claudecode"])
    writes: list[tuple[str, dict]] = []

    results = reconcile_mcp_connectors(
        cfg,
        resources=_resources(tmp_path),
        runner=FakeProcess([_completed(_mcp_command_document())]),
        reader=lambda _connector: [current],
        writer=lambda connector, entry: writes.append((connector, entry)),
    )

    assert results == [
        {
            "connector": "claudecode",
            "mcp_registration": "conflict",
            "changed": False,
            "proxy_prompt_tokenization": "not_in_direct_upstream_path",
        }
    ]
    assert writes == []
    assert mcp_reconciliation_failed(results)


def test_mcp_status_reports_exact_existing_registration_without_paths(tmp_path):
    exact = SimpleNamespace(
        name="s-gw",
        command="/usr/local/bin/node",
        args=["/tmp/sgw-package/dist/mcp-server.js"],
        env=_test_registered_mcp_env(),
        cwd="",
        url="",
        disabled=False,
    )
    cfg = _connector_cfg(tmp_path, ["codex"])

    results = mcp_connector_status(
        cfg,
        resources=_resources(tmp_path),
        runner=FakeProcess([_completed(_mcp_command_document())]),
        reader=lambda _connector: [exact],
    )

    assert results[0]["mcp_registration"] == "unchanged"
    rendered = json.dumps(results)
    assert "/tmp/sgw-package" not in rendered
    assert "/usr/local/bin/node" not in rendered


def test_mcp_command_rejects_extra_driver_environment(tmp_path):
    document = _mcp_command_document()
    document["env"]["RAW_SECRET"] = "must-not-pass"
    cfg = _connector_cfg(tmp_path, ["codex"])

    try:
        reconcile_mcp_connectors(
            cfg,
            resources=_resources(tmp_path),
            runner=FakeProcess([_completed(document)]),
            reader=lambda _connector: [],
        )
    except CredentialProtectionError as exc:
        assert exc.code == "command_invalid"
        assert "RAW_SECRET" not in str(exc)
    else:
        raise AssertionError("extra driver environment was accepted")


def test_mcp_command_rejects_expanded_protocol_envelope(tmp_path):
    document = _mcp_command_document()
    document["alternate_argv"] = ["/tmp/untrusted"]
    cfg = _connector_cfg(tmp_path, ["codex"])

    with pytest.raises(CredentialProtectionError) as caught:
        reconcile_mcp_connectors(
            cfg,
            resources=_resources(tmp_path),
            runner=FakeProcess([_completed(document)]),
            reader=lambda _connector: [],
        )

    assert caught.value.code == "command_invalid"


def test_reconcile_preflights_conflicts_before_any_connector_write(tmp_path):
    conflict = SimpleNamespace(
        name="s-gw",
        command="/operator/command",
        args=[],
        env={},
        cwd="",
        url="",
        disabled=False,
    )
    cfg = _connector_cfg(tmp_path, ["codex", "claudecode"])
    writes: list[str] = []

    results = reconcile_mcp_connectors(
        cfg,
        resources=_resources(tmp_path),
        runner=FakeProcess([_completed(_mcp_command_document())]),
        reader=lambda connector: [conflict] if connector == "claudecode" else [],
        writer=lambda connector, _entry: writes.append(connector),
    )

    assert writes == []
    assert [item["mcp_registration"] for item in results] == ["missing", "conflict"]


def test_bound_repair_updates_generation_and_node_path(tmp_path):
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    data_dir = tmp_path / "defenseclaw"
    home.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    connectors = ["codex"]
    current_workspace = [workspace]
    cfg = _workspace_connector_cfg(data_dir, connectors, current_workspace)

    with patch.dict(
        os.environ,
        {
            "HOME": str(home),
            "CODEX_HOME": str(home / ".codex"),
            "DEFENSECLAW_HOME": str(data_dir),
        },
        clear=False,
    ):
        first = reconcile_mcp_connectors(
            cfg,
            resources=_resources(tmp_path),
            runner=FakeProcess([_completed(_managed_mcp_command_document(str(data_dir), "0.2.0-test-linux-x64-g1"))]),
        )
        second = reconcile_mcp_connectors(
            cfg,
            resources=_resources(tmp_path),
            runner=FakeProcess(
                [
                    _completed(
                        _managed_mcp_command_document(
                            str(data_dir),
                            "0.2.0-test-linux-x64-g2",
                            command="/opt/node-v2",
                        )
                    )
                ]
            ),
        )

    assert first[0]["mcp_registration"] == "installed"
    assert second[0]["mcp_registration"] == "updated"
    document = json.loads((workspace / ".mcp.json").read_text(encoding="utf-8"))
    installed = document["mcpServers"]["s-gw"]
    assert installed["command"] == "/opt/node-v2"
    assert Path(installed["args"][0]).parts[-4:] == (
        "0.2.0-test-linux-x64-g2",
        "package",
        "dist",
        "mcp-server.js",
    )
    journal = json.loads((data_dir / "credential-protection" / "mcp-registrations.json").read_text(encoding="utf-8"))
    assert journal["registrations"][0]["entry"] == installed


def test_bound_reconcile_serializes_target_and_journal_transactions(tmp_path, monkeypatch):
    home = tmp_path / "home"
    workspace_a = tmp_path / "workspace-a"
    workspace_b = tmp_path / "workspace-b"
    data_dir = tmp_path / "defenseclaw"
    for directory in (home, workspace_a, workspace_b):
        directory.mkdir(mode=0o700)
    codex_cfg = _workspace_connector_cfg(data_dir, ["codex"], [workspace_a])
    cursor_cfg = _workspace_connector_cfg(data_dir, ["cursor"], [workspace_b])
    resources = _resources(tmp_path)
    first_at_save = threading.Event()
    release_first = threading.Event()
    second_loaded = threading.Event()
    load_calls: list[str] = []
    call_guard = threading.Lock()
    real_load = credential_protection_module._load_mcp_bindings
    real_save = credential_protection_module._save_mcp_bindings

    def tracked_load(binding_home):
        with call_guard:
            load_calls.append(threading.current_thread().name)
            if len(load_calls) == 2:
                second_loaded.set()
        return real_load(binding_home)

    def pause_first_save(binding_home, bindings):
        if threading.current_thread().name == "first-reconcile":
            first_at_save.set()
            if not release_first.wait(5):
                raise AssertionError("timed out waiting to release the first MCP transaction")
        return real_save(binding_home, bindings)

    monkeypatch.setattr(credential_protection_module, "_load_mcp_bindings", tracked_load)
    monkeypatch.setattr(credential_protection_module, "_save_mcp_bindings", pause_first_save)
    errors: list[BaseException] = []

    def run_reconcile(cfg, generation):
        try:
            reconcile_mcp_connectors(
                cfg,
                resources=resources,
                runner=FakeProcess([_completed(_managed_mcp_command_document(str(data_dir), generation))]),
            )
        except BaseException as exc:  # noqa: BLE001 - thread failures are asserted below.
            errors.append(exc)

    env = {
        "HOME": str(home),
        "CODEX_HOME": str(home / ".codex"),
        "DEFENSECLAW_HOME": str(data_dir),
    }
    with patch.dict(os.environ, env, clear=False):
        first = threading.Thread(
            target=run_reconcile,
            args=(codex_cfg, "0.2.0-test-linux-x64-g1"),
            name="first-reconcile",
        )
        second = threading.Thread(
            target=run_reconcile,
            args=(cursor_cfg, "0.2.0-test-linux-x64-g1"),
            name="second-reconcile",
        )
        first.start()
        assert first_at_save.wait(5)
        second.start()
        assert not second_loaded.wait(0.25)
        release_first.set()
        first.join(5)
        second.join(5)

    assert not first.is_alive()
    assert not second.is_alive()
    assert errors == []
    assert second_loaded.is_set()
    journal = json.loads((data_dir / "credential-protection" / "mcp-registrations.json").read_text(encoding="utf-8"))
    assert [item["connector"] for item in journal["registrations"]] == ["codex", "cursor"]


def test_bound_remove_and_rollback_wait_for_the_journal_transaction_lock(tmp_path, monkeypatch):
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    data_dir = tmp_path / "defenseclaw"
    home.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    cfg = _workspace_connector_cfg(data_dir, ["codex"], [workspace])
    resources = _resources(tmp_path)
    env = {
        "HOME": str(home),
        "CODEX_HOME": str(home / ".codex"),
        "DEFENSECLAW_HOME": str(data_dir),
    }
    with patch.dict(os.environ, env, clear=False):
        reconcile_mcp_connectors(
            cfg,
            resources=resources,
            runner=FakeProcess([_completed(_managed_mcp_command_document(str(data_dir), "0.2.0-test-linux-x64-g1"))]),
        )

        entered_load = threading.Event()
        real_load = credential_protection_module._load_mcp_bindings

        def tracked_load(binding_home):
            entered_load.set()
            return real_load(binding_home)

        monkeypatch.setattr(credential_protection_module, "_load_mcp_bindings", tracked_load)
        removal: list[list[dict]] = []
        remove_errors: list[BaseException] = []

        def remove_entry():
            try:
                removal.append(remove_managed_mcp_connectors(cfg))
            except BaseException as exc:  # noqa: BLE001 - thread failures are asserted below.
                remove_errors.append(exc)

        with credential_protection_module._mcp_binding_transaction(str(data_dir)):
            worker = threading.Thread(target=remove_entry)
            worker.start()
            assert not entered_load.wait(0.25)
        worker.join(5)

        assert not worker.is_alive()
        assert remove_errors == []
        assert entered_load.is_set()
        assert removal and removal[0][0]["mcp_registration"] == "removed"

        entered_load.clear()
        rollback_result: list[bool] = []

        def restore_entry():
            rollback_result.append(rollback_mcp_removal(cfg, removal[0]))

        with credential_protection_module._mcp_binding_transaction(str(data_dir)):
            worker = threading.Thread(target=restore_entry)
            worker.start()
            assert not entered_load.wait(0.25)
        worker.join(5)

    assert not worker.is_alive()
    assert entered_load.is_set()
    assert rollback_result == [True]
    journal = json.loads((data_dir / "credential-protection" / "mcp-registrations.json").read_text(encoding="utf-8"))
    assert [item["connector"] for item in journal["registrations"]] == ["codex"]


def test_bound_config_rollback_restores_exact_generation(tmp_path):
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    data_dir = tmp_path / "defenseclaw"
    home.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    cfg = _workspace_connector_cfg(data_dir, ["codex"], [workspace])
    env = {
        "HOME": str(home),
        "CODEX_HOME": str(home / ".codex"),
        "DEFENSECLAW_HOME": str(data_dir),
    }

    with patch.dict(os.environ, env, clear=False):
        reconcile_mcp_connectors(
            cfg,
            resources=_resources(tmp_path),
            runner=FakeProcess([_completed(_managed_mcp_command_document(str(data_dir), "0.2.0-test-linux-x64-g1"))]),
        )
        original = json.loads((workspace / ".mcp.json").read_text(encoding="utf-8"))
        results = reconcile_mcp_connectors(
            cfg,
            resources=_resources(tmp_path),
            runner=FakeProcess([_completed(_managed_mcp_command_document(str(data_dir), "0.2.0-test-linux-x64-g2"))]),
        )

        assert rollback_mcp_reconciliation(cfg, results)

    restored = json.loads((workspace / ".mcp.json").read_text(encoding="utf-8"))
    journal = json.loads((data_dir / "credential-protection" / "mcp-registrations.json").read_text(encoding="utf-8"))
    assert restored == original
    assert journal["registrations"][0]["entry"] == original["mcpServers"]["s-gw"]


def test_bound_repair_rolls_back_generation_after_later_target_failure(tmp_path):
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    data_dir = tmp_path / "defenseclaw"
    home.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    connectors = ["codex"]
    current_workspace = [workspace]
    cfg = _workspace_connector_cfg(data_dir, connectors, current_workspace)

    env = {
        "HOME": str(home),
        "CODEX_HOME": str(home / ".codex"),
        "DEFENSECLAW_HOME": str(data_dir),
    }
    with patch.dict(os.environ, env, clear=False):
        reconcile_mcp_connectors(
            cfg,
            resources=_resources(tmp_path),
            runner=FakeProcess([_completed(_managed_mcp_command_document(str(data_dir), "0.2.0-test-linux-x64-g1"))]),
        )
        original = json.loads((workspace / ".mcp.json").read_text(encoding="utf-8"))
        connectors.append("cursor")
        real_cas = connector_paths.compare_and_swap_mcp_server_at_target

        def fail_cursor(connector, *args, **kwargs):
            if connector == "cursor":
                raise OSError("injected target failure")
            return real_cas(connector, *args, **kwargs)

        with patch.object(
            connector_paths,
            "compare_and_swap_mcp_server_at_target",
            side_effect=fail_cursor,
        ):
            results = reconcile_mcp_connectors(
                cfg,
                resources=_resources(tmp_path),
                runner=FakeProcess(
                    [_completed(_managed_mcp_command_document(str(data_dir), "0.2.0-test-linux-x64-g2"))]
                ),
            )

    assert mcp_reconciliation_failed(results)
    assert json.loads((workspace / ".mcp.json").read_text(encoding="utf-8")) == original


def test_bound_disable_sweeps_old_workspace_and_preserves_new_manual_entry(tmp_path):
    home = tmp_path / "home"
    workspace_a = tmp_path / "workspace-a"
    workspace_b = tmp_path / "workspace-b"
    data_dir = tmp_path / "defenseclaw"
    for path in (home, workspace_a, workspace_b):
        path.mkdir(mode=0o700)
    connectors = ["codex"]
    current_workspace = [workspace_a]
    cfg = _workspace_connector_cfg(data_dir, connectors, current_workspace)
    env = {
        "HOME": str(home),
        "CODEX_HOME": str(home / ".codex"),
        "DEFENSECLAW_HOME": str(data_dir),
    }
    with patch.dict(os.environ, env, clear=False):
        reconcile_mcp_connectors(
            cfg,
            resources=_resources(tmp_path),
            runner=FakeProcess([_completed(_managed_mcp_command_document(str(data_dir), "0.2.0-test-linux-x64-g1"))]),
        )
        current_workspace[0] = workspace_b
        connectors[:] = ["claudecode"]
        (workspace_b / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"s-gw": {"command": "/operator/s-gw", "args": ["serve"], "env": {}}}}),
            encoding="utf-8",
        )
        (workspace_b / ".mcp.json").chmod(0o600)
        results = remove_managed_mcp_connectors(cfg, include_inactive=True)

    old_document = json.loads((workspace_a / ".mcp.json").read_text(encoding="utf-8"))
    new_document = json.loads((workspace_b / ".mcp.json").read_text(encoding="utf-8"))
    assert "s-gw" not in old_document.get("mcpServers", {})
    assert new_document["mcpServers"]["s-gw"]["command"] == "/operator/s-gw"
    assert not mcp_removal_failed(results)
    assert not (data_dir / "credential-protection" / "mcp-registrations.json").exists()


def test_bound_disable_fails_closed_without_ownership_journal(tmp_path):
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    data_dir = tmp_path / "defenseclaw"
    home.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    cfg = _workspace_connector_cfg(data_dir, ["codex"], [workspace])
    managed = _managed_mcp_entry(str(data_dir))
    (workspace / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"s-gw": managed}}),
        encoding="utf-8",
    )
    (workspace / ".mcp.json").chmod(0o600)

    with patch.dict(
        os.environ,
        {"HOME": str(home), "DEFENSECLAW_HOME": str(data_dir)},
        clear=False,
    ):
        results = remove_managed_mcp_connectors(cfg)

    assert mcp_removal_failed(results)
    document = json.loads((workspace / ".mcp.json").read_text(encoding="utf-8"))
    assert document["mcpServers"]["s-gw"] == managed


def test_bound_disable_fails_closed_on_malformed_owned_target(tmp_path):
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    data_dir = tmp_path / "defenseclaw"
    home.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    cfg = _workspace_connector_cfg(data_dir, ["codex"], [workspace])
    with patch.dict(
        os.environ,
        {"HOME": str(home), "DEFENSECLAW_HOME": str(data_dir)},
        clear=False,
    ):
        reconcile_mcp_connectors(
            cfg,
            resources=_resources(tmp_path),
            runner=FakeProcess([_completed(_managed_mcp_command_document(str(data_dir), "0.2.0-test-linux-x64-g1"))]),
        )
        (workspace / ".mcp.json").write_text("{broken", encoding="utf-8")
        (workspace / ".mcp.json").chmod(0o600)
        results = remove_managed_mcp_connectors(cfg)

    assert mcp_removal_failed(results)
    assert (workspace / ".mcp.json").read_text(encoding="utf-8") == "{broken"


def test_bound_disable_fails_closed_on_malformed_ownership_journal(tmp_path):
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    data_dir = tmp_path / "defenseclaw"
    home.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    cfg = _workspace_connector_cfg(data_dir, ["codex"], [workspace])
    managed = _managed_mcp_entry(str(data_dir))
    target = workspace / ".mcp.json"
    target.write_text(json.dumps({"mcpServers": {"s-gw": managed}}), encoding="utf-8")
    target.chmod(0o600)
    journal_dir = data_dir / "credential-protection"
    journal_dir.mkdir(parents=True, mode=0o700)
    journal = journal_dir / "mcp-registrations.json"
    journal.write_text("{}\n", encoding="utf-8")
    journal.chmod(0o600)

    with (
        patch.dict(
            os.environ,
            {"HOME": str(home), "DEFENSECLAW_HOME": str(data_dir)},
            clear=False,
        ),
        pytest.raises(CredentialProtectionError) as caught,
    ):
        remove_managed_mcp_connectors(cfg)

    assert caught.value.code == "mcp_reconciliation_failed"
    assert json.loads(target.read_text(encoding="utf-8"))["mcpServers"]["s-gw"] == managed


def test_enabled_roster_reconcile_installs_connector_added_later(tmp_path):
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    data_dir = tmp_path / "defenseclaw"
    home.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    connectors: list[str] = []
    cfg = _workspace_connector_cfg(data_dir, connectors, [workspace])
    cfg.credential_protection = SimpleNamespace(enabled=True)
    connectors.append("codex")

    with patch.dict(
        os.environ,
        {
            "HOME": str(home),
            "CODEX_HOME": str(home / ".codex"),
            "DEFENSECLAW_HOME": str(data_dir),
        },
        clear=False,
    ):
        results = reconcile_mcp_connector_roster(
            cfg,
            resources=_resources(tmp_path),
            runner=FakeProcess([_completed(_managed_mcp_command_document(str(data_dir), "0.2.0-test-linux-x64-g1"))]),
        )

    assert results[0]["mcp_registration"] == "installed"
    document = json.loads((workspace / ".mcp.json").read_text(encoding="utf-8"))
    assert document["mcpServers"]["s-gw"]["env"]["DEFENSECLAW_MCP_OWNER"]


def test_enabled_roster_reconcile_removes_only_removed_connector(tmp_path):
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    data_dir = tmp_path / "defenseclaw"
    home.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    connectors = ["codex", "cursor"]
    cfg = _workspace_connector_cfg(data_dir, connectors, [workspace])
    cfg.credential_protection = SimpleNamespace(enabled=True)
    env = {
        "HOME": str(home),
        "CODEX_HOME": str(home / ".codex"),
        "DEFENSECLAW_HOME": str(data_dir),
    }

    with patch.dict(os.environ, env, clear=False):
        reconcile_mcp_connector_roster(
            cfg,
            resources=_resources(tmp_path),
            runner=FakeProcess([_completed(_managed_mcp_command_document(str(data_dir), "0.2.0-test-linux-x64-g1"))]),
        )
        connectors[:] = ["cursor"]
        reconcile_mcp_connector_roster(
            cfg,
            removed_connectors=["codex"],
            resources=_resources(tmp_path),
            runner=FakeProcess([_completed(_managed_mcp_command_document(str(data_dir), "0.2.0-test-linux-x64-g1"))]),
        )

    codex = json.loads((workspace / ".mcp.json").read_text(encoding="utf-8"))
    cursor = json.loads((workspace / ".cursor" / "mcp.json").read_text(encoding="utf-8"))
    assert "s-gw" not in codex.get("mcpServers", {})
    assert "s-gw" in cursor["mcpServers"]


def test_enabled_roster_reconcile_replaces_batch_transactionally(tmp_path):
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    data_dir = tmp_path / "defenseclaw"
    home.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    connectors = ["codex", "cursor"]
    cfg = _workspace_connector_cfg(data_dir, connectors, [workspace])
    cfg.credential_protection = SimpleNamespace(enabled=True)
    env = {
        "HOME": str(home),
        "USERPROFILE": str(home),
        "CODEX_HOME": str(home / ".codex"),
        "DEFENSECLAW_HOME": str(data_dir),
    }

    with patch.dict(os.environ, env, clear=False):
        reconcile_mcp_connector_roster(
            cfg,
            resources=_resources(tmp_path),
            runner=FakeProcess([_completed(_managed_mcp_command_document(str(data_dir), "0.2.0-test-linux-x64-g1"))]),
        )
        connectors[:] = ["openhands"]
        reconcile_mcp_connector_roster(
            cfg,
            removed_connectors=["codex", "cursor"],
            resources=_resources(tmp_path),
            runner=FakeProcess([_completed(_managed_mcp_command_document(str(data_dir), "0.2.0-test-linux-x64-g1"))]),
        )

    codex = json.loads((workspace / ".mcp.json").read_text(encoding="utf-8"))
    cursor = json.loads((workspace / ".cursor" / "mcp.json").read_text(encoding="utf-8"))
    openhands = json.loads((home / ".openhands" / "mcp.json").read_text(encoding="utf-8"))
    journal = json.loads((data_dir / "credential-protection" / "mcp-registrations.json").read_text(encoding="utf-8"))
    assert "s-gw" not in codex.get("mcpServers", {})
    assert "s-gw" not in cursor.get("mcpServers", {})
    assert "s-gw" in openhands["mcpServers"]
    assert [item["connector"] for item in journal["registrations"]] == ["openhands"]


def test_disabled_roster_reconcile_is_noop(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    cfg = _workspace_connector_cfg(tmp_path / "defenseclaw", ["codex"], [workspace])
    cfg.credential_protection = SimpleNamespace(enabled=False)

    def unexpected_runner(*_args, **_kwargs):
        raise AssertionError("disabled credential protection must not load s-gw")

    assert reconcile_mcp_connector_roster(cfg, runner=unexpected_runner) == []
    assert not (workspace / ".mcp.json").exists()


def test_enabled_roster_reconcile_restores_cleanup_when_active_conflicts(tmp_path):
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    data_dir = tmp_path / "defenseclaw"
    home.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    connectors = ["codex", "cursor"]
    cfg = _workspace_connector_cfg(data_dir, connectors, [workspace])
    cfg.credential_protection = SimpleNamespace(enabled=True)
    env = {
        "HOME": str(home),
        "USERPROFILE": str(home),
        "CODEX_HOME": str(home / ".codex"),
        "DEFENSECLAW_HOME": str(data_dir),
    }

    with patch.dict(os.environ, env, clear=False):
        reconcile_mcp_connector_roster(
            cfg,
            resources=_resources(tmp_path),
            runner=FakeProcess([_completed(_managed_mcp_command_document(str(data_dir), "0.2.0-test-linux-x64-g1"))]),
        )
        openhands_dir = home / ".openhands"
        openhands_dir.mkdir(mode=0o700)
        openhands_target = openhands_dir / "mcp.json"
        openhands_target.write_text(
            json.dumps({"mcpServers": {"s-gw": {"command": "/operator/s-gw", "args": ["serve"], "env": {}}}}),
            encoding="utf-8",
        )
        openhands_target.chmod(0o600)
        connectors[:] = ["openhands"]

        with pytest.raises(CredentialProtectionError) as caught:
            reconcile_mcp_connector_roster(
                cfg,
                removed_connectors=["codex", "cursor"],
                resources=_resources(tmp_path),
                runner=FakeProcess(
                    [_completed(_managed_mcp_command_document(str(data_dir), "0.2.0-test-linux-x64-g1"))]
                ),
            )

    assert caught.value.code == "mcp_reconciliation_failed"
    codex = json.loads((workspace / ".mcp.json").read_text(encoding="utf-8"))
    cursor = json.loads((workspace / ".cursor" / "mcp.json").read_text(encoding="utf-8"))
    journal = json.loads((data_dir / "credential-protection" / "mcp-registrations.json").read_text(encoding="utf-8"))
    assert "s-gw" in codex["mcpServers"]
    assert "s-gw" in cursor["mcpServers"]
    assert [item["connector"] for item in journal["registrations"]] == ["codex", "cursor"]


def test_reconcile_rolls_back_new_entries_after_later_write_failure(tmp_path):
    cfg = _connector_cfg(tmp_path, ["codex", "claudecode"])
    entries: dict[str, list[SimpleNamespace]] = {"codex": [], "claudecode": []}
    removed: list[str] = []

    def reader(connector):
        return entries[connector]

    def writer(connector, entry):
        if connector == "claudecode":
            raise OSError("injected write failure")
        entries[connector] = [SimpleNamespace(name="s-gw", cwd="", url="", disabled=False, **entry)]

    def remover(connector):
        removed.append(connector)
        entries[connector] = []

    results = reconcile_mcp_connectors(
        cfg,
        resources=_resources(tmp_path),
        runner=FakeProcess([_completed(_mcp_command_document())]),
        reader=reader,
        writer=writer,
        remover=remover,
    )

    assert removed == ["codex"]
    assert entries == {"codex": [], "claudecode": []}
    assert mcp_reconciliation_failed(results)


def test_disable_removes_only_exact_managed_entries(tmp_path):
    cfg = _connector_cfg(tmp_path, ["codex", "claudecode"])
    exact = SimpleNamespace(
        name="s-gw",
        cwd="",
        url="",
        disabled=False,
        **_managed_mcp_entry(cfg.data_dir),
    )
    conflict = SimpleNamespace(
        name="s-gw",
        command="/operator/s-gw",
        args=[],
        env={},
        cwd="",
        url="",
        disabled=False,
    )
    entries = {"codex": [exact], "claudecode": [conflict]}

    def remover(connector):
        entries[connector] = []

    results = remove_managed_mcp_connectors(
        cfg,
        resources=_resources(tmp_path),
        runner=FakeProcess([_completed(_managed_mcp_command_document(cfg.data_dir, "0.2.0-test-linux-x64-g1"))]),
        reader=lambda connector: entries[connector],
        remover=remover,
    )

    assert [item["mcp_registration"] for item in results] == ["removed", "conflict"]
    assert results[0]["changed"] is True
    assert entries["codex"] == []
    assert entries["claudecode"] == [conflict]
    assert not mcp_removal_failed(results)


def test_disable_sweeps_exact_registration_from_inactive_connector(tmp_path):
    cfg = _connector_cfg(tmp_path, ["claudecode"])
    expected = _managed_mcp_entry(cfg.data_dir)
    entries: dict[str, list[SimpleNamespace]] = {connector: [] for connector in connector_paths.KNOWN_CONNECTORS}
    entries["codex"] = [SimpleNamespace(name="s-gw", cwd="", url="", disabled=False, **expected)]
    results = remove_managed_mcp_connectors(
        cfg,
        include_inactive=True,
        resources=_resources(tmp_path),
        runner=FakeProcess([_completed(_managed_mcp_command_document(cfg.data_dir, "0.2.0-test-linux-x64-g1"))]),
        reader=lambda connector: entries[connector],
        remover=lambda connector: entries.__setitem__(connector, []),
    )

    codex = next(item for item in results if item["connector"] == "codex")
    assert codex["mcp_registration"] == "removed"
    assert codex["changed"] is True
    assert entries["codex"] == []


def test_disable_preserves_unmarked_external_same_name_without_loading_module(tmp_path):
    cfg = _connector_cfg(tmp_path, ["codex"])
    external = SimpleNamespace(
        name="s-gw",
        command="/operator/s-gw",
        args=["serve"],
        env={},
        cwd="",
        url="",
        disabled=False,
    )
    removed: list[str] = []

    results = remove_managed_mcp_connectors(
        cfg,
        resources=_resources(tmp_path),
        runner=FakeProcess([_completed(_managed_mcp_command_document(cfg.data_dir, "0.2.0-test-linux-x64-g1"))]),
        reader=lambda _connector: [external],
        remover=removed.append,
    )

    assert results[0]["mcp_registration"] == "conflict"
    assert removed == []


def test_disable_leaves_manual_inactive_registration_without_loading_module(tmp_path):
    entries = {connector: [] for connector in connector_paths.KNOWN_CONNECTORS}
    entries["zeptoclaw"] = [SimpleNamespace(name="s-gw")]
    cfg = _connector_cfg(tmp_path, ["codex"])

    results = remove_managed_mcp_connectors(
        cfg,
        include_inactive=True,
        reader=lambda connector: entries[connector],
    )

    zepto = next(item for item in results if item["connector"] == "zeptoclaw")
    assert zepto["mcp_registration"] == "manual"
    assert entries["zeptoclaw"]


def test_disable_rolls_back_prior_removals_after_later_failure(tmp_path):
    cfg = _connector_cfg(tmp_path, ["codex", "claudecode"])
    entries = {
        connector: [
            SimpleNamespace(
                name="s-gw",
                cwd="",
                url="",
                disabled=False,
                **_managed_mcp_entry(cfg.data_dir, connector=connector),
            )
        ]
        for connector in ["codex", "claudecode"]
    }

    def remover(connector):
        if connector == "claudecode":
            raise OSError("injected removal failure")
        entries[connector] = []

    def writer(connector, entry):
        entries[connector] = [SimpleNamespace(name="s-gw", cwd="", url="", disabled=False, **entry)]

    results = remove_managed_mcp_connectors(
        cfg,
        resources=_resources(tmp_path),
        runner=FakeProcess([_completed(_managed_mcp_command_document(cfg.data_dir, "0.2.0-test-linux-x64-g1"))]),
        reader=lambda connector: entries[connector],
        writer=writer,
        remover=remover,
    )

    assert all(entries[connector] for connector in entries)
    assert mcp_removal_failed(results)


def _app(tmp_path: Path, *, enabled: bool = False):
    app = AppContext()
    saved: list[bool] = []
    app.cfg = SimpleNamespace(
        data_dir=str(tmp_path),
        credential_protection=SimpleNamespace(enabled=enabled),
        save=lambda: saved.append(True),
    )
    return app, saved


@pytest.mark.parametrize("already_enabled", [False, True])
def test_setup_command_enables_only_after_broker_is_ready(tmp_path, already_enabled):
    app, saved = _app(tmp_path, enabled=already_enabled)
    runner = CliRunner()
    ready = {
        "ready": True,
        "version": "0.1.19",
    }
    with patch(
        "defenseclaw.commands.cmd_credential_protection.setup_broker_for_runtime",
        return_value=ready,
    ) as setup_runtime:
        result = runner.invoke(setup_credential_protection, ["--yes"], obj=app)

    assert result.exit_code == 0, result.output
    assert app.cfg.credential_protection.enabled is True
    assert saved == [True]
    setup_runtime.assert_called_once_with(str(tmp_path), already_enabled=already_enabled)


def test_setup_requires_explicit_confirmation_when_noninteractive(tmp_path):
    app, saved = _app(tmp_path)

    result = CliRunner().invoke(setup_credential_protection, [], obj=app)

    assert result.exit_code == 1
    assert "Pass --yes" in result.output
    assert app.cfg.credential_protection.enabled is False
    assert saved == []


def test_setup_rolls_back_new_mcp_entries_when_config_save_fails(tmp_path):
    app, _saved = _app(tmp_path)
    app.cfg.save = lambda: (_ for _ in ()).throw(OSError("injected save failure"))
    ready = {"ready": True, "version": "0.2.0"}
    installed = [
        {
            "connector": "codex",
            "mcp_registration": "installed",
            "changed": True,
            "proxy_prompt_tokenization": "not_in_direct_upstream_path",
        }
    ]
    with (
        patch(
            "defenseclaw.commands.cmd_credential_protection.setup_broker_for_runtime",
            return_value=ready,
        ),
        patch(
            "defenseclaw.commands.cmd_credential_protection.reconcile_mcp_connectors",
            return_value=installed,
        ),
        patch(
            "defenseclaw.commands.cmd_credential_protection.rollback_mcp_reconciliation",
            return_value=True,
        ) as rollback,
    ):
        result = CliRunner().invoke(setup_credential_protection, ["--yes"], obj=app)

    assert result.exit_code == 1
    assert app.cfg.credential_protection.enabled is False
    rollback.assert_called_once_with(app.cfg, installed)


def test_setup_command_leaves_config_disabled_on_failure(tmp_path):
    app, saved = _app(tmp_path)
    runner = CliRunner()
    unavailable = {
        "enabled": False,
        "ready": False,
        "state": "runner_unavailable",
        "error_code": "runner_unavailable",
    }
    with (
        patch(
            "defenseclaw.commands.cmd_credential_protection.setup_broker_for_runtime",
            side_effect=CredentialProtectionError("runner_unavailable"),
        ),
        patch(
            "defenseclaw.commands.cmd_credential_protection.safe_status",
            return_value=unavailable,
        ),
    ):
        result = runner.invoke(setup_credential_protection, ["--yes"], obj=app)

    assert result.exit_code == 1
    assert app.cfg.credential_protection.enabled is False
    assert saved == []
    assert "supported s-gw" in result.output
    assert "approved s-gw" not in result.output


def test_setup_command_reports_connector_conflict_and_stays_disabled(tmp_path):
    app, saved = _app(tmp_path)
    ready = {"ready": True, "version": "0.2.0"}
    conflict = [
        {
            "connector": "claudecode",
            "mcp_registration": "conflict",
            "changed": False,
            "proxy_prompt_tokenization": "not_in_direct_upstream_path",
        }
    ]
    with (
        patch(
            "defenseclaw.commands.cmd_credential_protection.setup_broker_for_runtime",
            return_value=ready,
        ),
        patch(
            "defenseclaw.commands.cmd_credential_protection.reconcile_mcp_connectors",
            return_value=conflict,
        ),
    ):
        result = CliRunner().invoke(setup_credential_protection, ["--yes"], obj=app)

    assert result.exit_code == 1
    assert app.cfg.credential_protection.enabled is False
    assert saved == []
    assert "MCP [claudecode]: conflict" in result.output
    assert "not in direct upstream path" in result.output
    assert "protected" not in result.output


def test_disable_preserves_shared_store_and_does_not_call_sgw(tmp_path):
    app, saved = _app(tmp_path, enabled=True)
    runner = CliRunner()
    with (
        patch("defenseclaw.commands.cmd_credential_protection.setup_broker_for_runtime") as setup_mock,
        patch(
            "defenseclaw.commands.cmd_credential_protection.remove_managed_mcp_connectors",
            return_value=[],
        ) as remove_mcp,
    ):
        result = runner.invoke(setup_credential_protection, ["--disable", "--yes"], obj=app)

    assert result.exit_code == 0, result.output
    assert app.cfg.credential_protection.enabled is False
    assert saved == [True]
    setup_mock.assert_not_called()
    remove_mcp.assert_called_once_with(app.cfg, include_inactive=True)
    assert not os.path.exists(tmp_path / ".s-gw")


def test_disable_is_noop_when_already_disabled_and_no_sgw_entries(tmp_path):
    app, saved = _app(tmp_path, enabled=False)
    app.cfg.active_connectors = lambda: ["codex"]
    app.cfg.mcp_servers = lambda _connector: []
    with patch(
        "defenseclaw.commands.cmd_credential_protection.remove_managed_mcp_connectors",
        side_effect=CredentialProtectionError("not_installed"),
    ) as remove_mcp:
        result = CliRunner().invoke(
            setup_credential_protection,
            ["--disable", "--yes"],
            obj=app,
        )

    assert result.exit_code == 0, result.output
    assert app.cfg.credential_protection.enabled is False
    assert saved == []
    remove_mcp.assert_not_called()
    assert "already disabled" in result.output


def test_disable_refuses_unverified_named_entry_when_module_is_unavailable(tmp_path):
    app, saved = _app(tmp_path, enabled=False)
    app.cfg.active_connectors = lambda: ["codex"]
    app.cfg.mcp_servers = lambda _connector: [SimpleNamespace(name="s-gw")]
    with patch(
        "defenseclaw.commands.cmd_credential_protection.remove_managed_mcp_connectors",
        side_effect=CredentialProtectionError("not_installed"),
    ) as remove_mcp:
        result = CliRunner().invoke(
            setup_credential_protection,
            ["--disable", "--yes"],
            obj=app,
        )

    assert result.exit_code == 1
    assert app.cfg.credential_protection.enabled is False
    assert saved == []
    remove_mcp.assert_called_once_with(app.cfg, include_inactive=True)
    assert "Could not safely identify managed MCP registrations" in result.output


def test_sgw_registration_inspection_refuses_partial_connector_reads(tmp_path):
    cfg = _connector_cfg(tmp_path, ["codex", "claudecode"])

    def reader(connector):
        if connector == "claudecode":
            raise OSError("injected read failure")
        return [SimpleNamespace(name="s-gw")]

    with pytest.raises(CredentialProtectionError) as caught:
        has_sgw_mcp_registrations(cfg, reader=reader)

    assert caught.value.code == "mcp_reconciliation_failed"


def test_disable_restores_mcp_entries_when_config_save_fails(tmp_path):
    app, _saved = _app(tmp_path, enabled=True)
    app.cfg.save = lambda: (_ for _ in ()).throw(OSError("injected save failure"))
    removed = [
        {
            "connector": "codex",
            "mcp_registration": "removed",
            "changed": True,
            "proxy_prompt_tokenization": "not_in_direct_upstream_path",
        }
    ]
    with (
        patch(
            "defenseclaw.commands.cmd_credential_protection.remove_managed_mcp_connectors",
            return_value=removed,
        ),
        patch(
            "defenseclaw.commands.cmd_credential_protection.rollback_mcp_removal",
            return_value=True,
        ) as rollback,
    ):
        result = CliRunner().invoke(
            setup_credential_protection,
            ["--disable", "--yes"],
            obj=app,
        )

    assert result.exit_code == 1
    assert app.cfg.credential_protection.enabled is True
    rollback.assert_called_once_with(app.cfg, removed)


def test_setup_dry_run_checks_runtime_without_mutating_config(tmp_path):
    app, saved = _app(tmp_path)
    runner = CliRunner()
    ready = {
        "enabled": True,
        "ready": True,
        "state": "ready",
        "version": "0.2.0",
    }
    with (
        patch(
            "defenseclaw.commands.cmd_credential_protection.safe_status",
            return_value=ready,
        ) as status_mock,
        patch("defenseclaw.commands.cmd_credential_protection.setup_broker_for_runtime") as setup_mock,
    ):
        result = runner.invoke(setup_credential_protection, ["--dry-run"], obj=app)

    assert result.exit_code == 0, result.output
    assert app.cfg.credential_protection.enabled is False
    assert saved == []
    status_mock.assert_called_once_with(str(tmp_path), enabled=True)
    setup_mock.assert_not_called()


def test_status_command_emits_safe_json(tmp_path):
    app, _ = _app(tmp_path, enabled=True)
    expected = {
        "enabled": True,
        "ready": False,
        "state": "node_missing",
        "error_code": "node_missing",
    }
    with patch(
        "defenseclaw.commands.cmd_credential_protection.safe_status",
        return_value=expected,
    ):
        result = CliRunner().invoke(credential_protection, ["status", "--json"], obj=app)

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        **expected,
        "scope": "credential_broker",
        "mcp_connectors": [],
    }


def test_disabled_status_offers_setup_without_mutating_config(tmp_path):
    app, saved = _app(tmp_path, enabled=False)
    with patch(
        "defenseclaw.commands.cmd_credential_protection.safe_status",
        return_value={"enabled": False, "ready": False, "state": "disabled"},
    ):
        result = CliRunner().invoke(credential_protection, ["status"], obj=app)

    assert result.exit_code == 0
    assert "setup credential-protection --yes" in result.output
    assert app.cfg.credential_protection.enabled is False
    assert saved == []


def test_open_command_reports_a_request_without_claiming_launch_success(tmp_path):
    app, _saved = _app(tmp_path, enabled=True)
    with patch("defenseclaw.commands.cmd_credential_protection.open_broker") as open_ui:
        result = CliRunner().invoke(credential_protection, ["open"], obj=app)

    assert result.exit_code == 0, result.output
    open_ui.assert_called_once_with(str(tmp_path))
    assert "Requested the authenticated s-gw approval console" in result.output
    assert "Opened" not in result.output


def test_main_status_payload_uses_allowlisted_credential_metadata(tmp_path):
    cfg = SimpleNamespace(
        data_dir=str(tmp_path),
        credential_protection=SimpleNamespace(enabled=True),
    )
    expected = {
        "enabled": True,
        "ready": True,
        "state": "ready",
        "installed": True,
        "version": "0.1.19",
        "node_version": "22.4.1",
        "minimum_node_version": "20.0.0",
        "broker_state": "ready",
        "ui_available": True,
        "error_code": "",
    }
    with patch(
        "defenseclaw.commands.cmd_status.credential_protection_status",
        return_value=expected,
    ):
        result = _credential_protection_payload(cfg)

    assert result == {
        **expected,
        "scope": "credential_broker_readiness",
        "connector_coverage": "not_checked",
        "connector_coverage_command": "defenseclaw credential-protection status",
    }
    assert "path" not in json.dumps(result)
    assert "handle" not in json.dumps(result)


def test_main_status_calls_a_ready_broker_ready_not_protected(tmp_path):
    cfg = SimpleNamespace(
        data_dir=str(tmp_path),
        credential_protection=SimpleNamespace(enabled=True),
    )
    ready = {
        "enabled": True,
        "ready": True,
        "state": "ready",
        "version": "0.2.0",
    }
    with (
        patch(
            "defenseclaw.commands.cmd_status.credential_protection_status",
            return_value=ready,
        ),
        patch("defenseclaw.commands.cmd_status._status_row") as status_row,
    ):
        _print_credential_protection_status(cfg)

    label, value = status_row.call_args.args
    assert label == "Credential broker"
    assert "ready" in value
    assert "protected" not in value
    assert "connector coverage not checked" in value
    assert "defenseclaw credential-protection status" in value


def test_doctor_fails_closed_when_enabled_broker_is_unavailable(tmp_path):
    cfg = SimpleNamespace(
        data_dir=str(tmp_path),
        credential_protection=SimpleNamespace(enabled=True),
    )
    unavailable = {
        "enabled": True,
        "ready": False,
        "state": "node_missing",
        "error_code": "node_missing",
    }
    result = _DoctorResult()
    with patch("defenseclaw.credential_protection.safe_status", return_value=unavailable):
        _check_credential_protection(cfg, result)

    assert result.failed == 1
    assert result.checks[0]["label"] == "Credential broker"
    assert "node missing" in result.checks[0]["detail"]
    assert "Node.js 20" in result.checks[0]["detail"]


def test_doctor_skips_disabled_credential_protection(tmp_path):
    cfg = SimpleNamespace(
        data_dir=str(tmp_path),
        credential_protection=SimpleNamespace(enabled=False),
    )
    result = _DoctorResult()
    with patch("defenseclaw.credential_protection.safe_status") as status_mock:
        _check_credential_protection(cfg, result)

    assert result.skipped == 1
    status_mock.assert_not_called()
    assert "setup credential-protection --yes" in result.checks[0]["detail"]


def test_doctor_fails_when_active_connector_mcp_registration_is_missing(tmp_path):
    cfg = SimpleNamespace(
        data_dir=str(tmp_path),
        credential_protection=SimpleNamespace(enabled=True),
    )
    ready = {"enabled": True, "ready": True, "state": "ready", "version": "0.2.0"}
    missing = [
        {
            "connector": "codex",
            "mcp_registration": "missing",
            "changed": False,
            "proxy_prompt_tokenization": "not_in_direct_upstream_path",
        }
    ]
    result = _DoctorResult()
    with (
        patch("defenseclaw.credential_protection.safe_status", return_value=ready),
        patch("defenseclaw.credential_protection.mcp_connector_status", return_value=missing),
    ):
        _check_credential_protection(cfg, result)

    assert result.failed == 1
    assert "codex=missing" in result.checks[0]["detail"]


def test_root_and_setup_help_register_credential_protection_commands():
    assert cli.commands["credential-protection"] is credential_protection
    assert setup.commands["credential-protection"] is setup_credential_protection

    result = CliRunner().invoke(credential_protection, ["launch", "--help"])

    assert result.exit_code == 0, result.output
    assert "Absolute path to an agent executable" in result.output
