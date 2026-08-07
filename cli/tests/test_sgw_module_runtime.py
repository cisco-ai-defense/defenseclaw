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

import argparse
import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
try:
    from scripts import build_sgw_module, sgw_module
finally:
    sys.path.pop(0)

DRIVER = ROOT / "scripts" / "sgw_module.py"
MODULE_MANIFEST = ROOT / "release" / "s-gw-module.json"
RUNTIME_MANIFEST = ROOT / "release" / "s-gw-runners.json"
TARGET = "linux-x64"
LICENSE_BUNDLE = "s-gw fixture dependency licenses\n"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def elf_payload(machine: int = 62, label: str = "fixture") -> bytes:
    value = bytearray(64)
    value[:4] = b"\x7fELF"
    value[4:7] = b"\x02\x01\x01"
    value[16:18] = (2).to_bytes(2, "little")
    value[18:20] = machine.to_bytes(2, "little")
    value[20:24] = (1).to_bytes(4, "little")
    value[24 : 24 + len(label)] = label.encode("ascii")
    return bytes(value)


def pe_payload(machine: int) -> bytes:
    value = bytearray(128)
    value[:2] = b"MZ"
    value[60:64] = (64).to_bytes(4, "little")
    value[64:68] = b"PE\0\0"
    value[68:70] = machine.to_bytes(2, "little")
    return bytes(value)


def macho_payload(cpu_type: int) -> bytes:
    return b"\xcf\xfa\xed\xfe" + cpu_type.to_bytes(4, "little") + bytes(24)


def fat_macho_payload(cpu_types: list[int], *, fat64: bool = False) -> bytes:
    record_size = 32 if fat64 else 20
    magic = b"\xca\xfe\xba\xbf" if fat64 else b"\xca\xfe\xba\xbe"
    header_size = 8 + record_size * len(cpu_types)
    slices = [macho_payload(cpu_type) for cpu_type in cpu_types]
    records = bytearray()
    offset = header_size
    for cpu_type, slice_value in zip(cpu_types, slices, strict=True):
        records.extend(cpu_type.to_bytes(4, "big"))
        records.extend((0).to_bytes(4, "big"))
        width = 8 if fat64 else 4
        records.extend(offset.to_bytes(width, "big"))
        records.extend(len(slice_value).to_bytes(width, "big"))
        records.extend((0).to_bytes(4, "big"))
        if fat64:
            records.extend((0).to_bytes(4, "big"))
        offset += len(slice_value)
    return magic + len(cpu_types).to_bytes(4, "big") + records + b"".join(slices)


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_patched_lock_keeps_advisory_fixed_versions_on_public_vendor(tmp_path: Path) -> None:
    manifest = json.loads(MODULE_MANIFEST.read_text(encoding="utf-8"))
    inventory_path = ROOT / manifest["source_inventory"]
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))

    assert manifest["upstream_repository"] == "https://github.com/sgateway/s-gw.git"
    assert manifest["upstream_revision"] == inventory["revision"]

    stage = tmp_path / "source"
    shutil.copytree(ROOT / manifest["source_path"], stage)
    build_sgw_module.apply_patches(stage, build_sgw_module.patch_queue(manifest))

    package_lock = json.loads((stage / "package-lock.json").read_text(encoding="utf-8"))
    packages = package_lock["packages"]
    expected = {
        "node_modules/@hono/node-server": "2.1.0",
        "node_modules/@modelcontextprotocol/sdk": "1.30.0",
        "node_modules/fast-uri": "3.1.5",
        "node_modules/hono": "4.13.0",
        "node_modules/ip-address": "10.4.0",
        "node_modules/nanoid": "3.3.17",
        "node_modules/postcss": "8.5.25",
    }
    assert {name: packages[name]["version"] for name in expected} == expected


def signature(private_key: Ed25519PrivateKey, payload: bytes) -> str:
    return base64.b64encode(private_key.sign(payload)).decode("ascii")


def configure_signing(runtime: dict) -> Ed25519PrivateKey:
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    runtime["redistribution_status"] = "approved"
    runtime["signature_policy"] = {
        "algorithm": sgw_module.COMPONENT_SIGNATURE_ALGORITHM,
        "public_key": public_pem.decode("ascii"),
        "public_key_sha256": hashlib.sha256(public_pem).hexdigest(),
    }
    return private_key


def set_module_signature(runtime: dict, private_key: Ed25519PrivateKey, files: dict[str, str]) -> None:
    module = json.loads(MODULE_MANIFEST.read_text(encoding="utf-8"))
    installed_sha256 = sgw_module.module_inventory_sha256(files)
    target_record = runtime["targets"][TARGET]
    admission = {
        "schema_version": 1,
        "mode": "linux-sealed-memfd-v1",
        "signature_scope": "installed-runner-bytes",
        "dependency_policy": "system-only-v1",
    }
    admission_sha256 = sgw_module.runner_launch_admission_sha256(TARGET, admission)
    target_record["runner_launch_admission"] = admission
    target_record["module_installed_sha256"] = installed_sha256
    target_record["module_signature"] = signature(
        private_key,
        sgw_module.module_signature_payload(
            TARGET,
            module,
            installed_sha256,
            admission_sha256,
            sgw_module.runner_contract_sha256(),
        ),
    )


def sign_component(
    runtime: dict,
    private_key: Ed25519PrivateKey,
    name: str,
    source: Path,
    installed_files: dict[str, str],
) -> None:
    record = runtime["targets"][TARGET]["components"][name]
    artifact_sha256 = digest(source)
    installed_sha256 = sgw_module.component_inventory_sha256(installed_files)
    record["path"] = str(source)
    record["sha256"] = artifact_sha256
    record["installed_sha256"] = installed_sha256
    record["signature"] = signature(
        private_key,
        sgw_module.component_signature_payload(
            TARGET,
            name,
            record["destination"],
            artifact_sha256,
            installed_sha256,
        ),
    )


def runtime_fixture(tmp_path: Path) -> tuple[Path, dict, Ed25519PrivateKey]:
    runner = tmp_path / "s-gw-core"
    helper = tmp_path / "s-gw-secret-service-helper"
    licenses = tmp_path / "THIRD_PARTY_LICENSES.txt"
    runner.write_bytes(elf_payload(label="runner"))
    helper.write_bytes(elf_payload(label="helper"))
    licenses.write_text(LICENSE_BUNDLE, encoding="utf-8")

    ui_source = tmp_path / "console-ui"
    (ui_source / "assets").mkdir(parents=True)
    (ui_source / "index.html").write_text("<main>s-gw approval</main>\n", encoding="utf-8")
    write_json(
        ui_source / "capabilities.json",
        {
            "schema_version": 1,
            "capabilities": [
                "defenseclaw.pending-enrollment.v1",
                "defenseclaw.approval-console-session.v1",
            ],
        },
    )
    (ui_source / "assets" / "app.js").write_text("console.log('approval');\n", encoding="utf-8")
    ui_archive = tmp_path / "s-gw-console-ui.tar.gz"
    with tarfile.open(ui_archive, "w:gz") as archive:
        archive.add(ui_source, arcname="console-ui")

    runtime = json.loads(RUNTIME_MANIFEST.read_text(encoding="utf-8"))
    private_key = configure_signing(runtime)
    records = runtime["targets"][TARGET]["components"]
    sign_component(
        runtime,
        private_key,
        "runner",
        runner,
        {records["runner"]["destination"]: digest(runner)},
    )
    sign_component(
        runtime,
        private_key,
        "credential_helper",
        helper,
        {records["credential_helper"]["destination"]: digest(helper)},
    )
    ui_files = {
        f"dist/console-ui/{item.relative_to(ui_source).as_posix()}": digest(item)
        for item in ui_source.rglob("*")
        if item.is_file()
    }
    sign_component(runtime, private_key, "approval_ui", ui_archive, ui_files)
    sign_component(
        runtime,
        private_key,
        "license_bundle",
        licenses,
        {records["license_bundle"]["destination"]: digest(licenses)},
    )
    set_module_signature(runtime, private_key, {"placeholder": "0" * 64})
    path = tmp_path / "runtime.json"
    write_json(path, runtime)
    return path, runtime, private_key


def module_fixture(tmp_path: Path) -> Path:
    manifest = json.loads(MODULE_MANIFEST.read_text(encoding="utf-8"))
    path = tmp_path / "module.json"
    write_json(path, manifest)
    return path


def package_artifact(
    tmp_path: Path,
    runtime_path: Path,
    runtime: dict,
    private_key: Ed25519PrivateKey,
) -> tuple[Path, dict]:
    package = tmp_path / "package"
    (package / "dist" / "native" / TARGET).mkdir(parents=True)
    (package / "dist" / "console-ui" / "assets").mkdir(parents=True)
    (package / "node_modules" / "tiny-runtime").mkdir(parents=True)
    (package / "package.json").write_text('{"name":"@s-gw/s-gw","version":"0.2.0"}\n', encoding="utf-8")
    (package / "dist" / "cli.js").write_text("export {};\n", encoding="utf-8")
    (package / "dist" / "mcp-server.js").write_text("export {};\n", encoding="utf-8")
    (package / "THIRD_PARTY_LICENSES.txt").write_text(LICENSE_BUNDLE, encoding="utf-8")
    runner_path = package / "dist" / "native" / TARGET / "s-gw-core"
    helper_path = package / "dist" / "native" / TARGET / "s-gw-secret-service-helper"
    runner_path.write_bytes(elf_payload(label="runner"))
    helper_path.write_bytes(elf_payload(label="helper"))
    runner_path.chmod(0o755)
    helper_path.chmod(0o755)
    ui_index = package / "dist" / "console-ui" / "index.html"
    ui_capabilities = package / "dist" / "console-ui" / "capabilities.json"
    ui_asset = package / "dist" / "console-ui" / "assets" / "app.js"
    dependency = package / "node_modules" / "tiny-runtime" / "index.js"
    ui_index.write_text("<main>s-gw approval</main>\n", encoding="utf-8")
    write_json(
        ui_capabilities,
        {
            "schema_version": 1,
            "capabilities": [
                "defenseclaw.pending-enrollment.v1",
                "defenseclaw.approval-console-session.v1",
            ],
        },
    )
    ui_asset.write_text("console.log('approval');\n", encoding="utf-8")
    dependency.write_text("export const runtime = true;\n", encoding="utf-8")

    paths = (
        "package.json",
        "dist/cli.js",
        "dist/mcp-server.js",
        "THIRD_PARTY_LICENSES.txt",
        f"dist/native/{TARGET}/s-gw-core",
        f"dist/native/{TARGET}/s-gw-secret-service-helper",
        "dist/console-ui/index.html",
        "dist/console-ui/capabilities.json",
        "dist/console-ui/assets/app.js",
        "node_modules/tiny-runtime/index.js",
    )
    files = {relative: digest(package / relative) for relative in paths}
    set_module_signature(runtime, private_key, files)
    write_json(runtime_path, runtime)
    approved = runtime["targets"][TARGET]["components"]
    components = {
        "runner": {
            "artifact_sha256": approved["runner"]["sha256"],
            "installed_sha256": approved["runner"]["installed_sha256"],
            "signature": approved["runner"]["signature"],
            "destination": approved["runner"]["destination"],
            "files": [f"dist/native/{TARGET}/s-gw-core"],
        },
        "credential_helper": {
            "artifact_sha256": approved["credential_helper"]["sha256"],
            "installed_sha256": approved["credential_helper"]["installed_sha256"],
            "signature": approved["credential_helper"]["signature"],
            "destination": approved["credential_helper"]["destination"],
            "files": [f"dist/native/{TARGET}/s-gw-secret-service-helper"],
        },
        "approval_ui": {
            "artifact_sha256": approved["approval_ui"]["sha256"],
            "installed_sha256": approved["approval_ui"]["installed_sha256"],
            "signature": approved["approval_ui"]["signature"],
            "destination": approved["approval_ui"]["destination"],
            "files": [
                "dist/console-ui/assets/app.js",
                "dist/console-ui/capabilities.json",
                "dist/console-ui/index.html",
            ],
        },
        "license_bundle": {
            "artifact_sha256": approved["license_bundle"]["sha256"],
            "installed_sha256": approved["license_bundle"]["installed_sha256"],
            "signature": approved["license_bundle"]["signature"],
            "destination": approved["license_bundle"]["destination"],
            "files": ["THIRD_PARTY_LICENSES.txt"],
        },
    }
    metadata = {
        "schema_version": 1,
        "package_name": "@s-gw/s-gw",
        "package_version": "0.2.0",
        "upstream_revision": "652b042ef61da6170cb26aa8e4d8e446dc1c9b22",
        "upstream_tree": "0451e84cbfa65c5050df309c1b045344b75dae10",
        "minimum_node_version": "20.0.0",
        "build_toolchain": {"node": "24.18.1", "npm": "11.16.0"},
        "target": TARGET,
        "production_ready": True,
        "inventory_excludes": ["defenseclaw-module.json"],
        "signature_policy": {
            "algorithm": sgw_module.COMPONENT_SIGNATURE_ALGORITHM,
            "public_key_sha256": runtime["signature_policy"]["public_key_sha256"],
        },
        "runner_contract": sgw_module.RUNNER_CONTRACT,
        "runner_contract_sha256": sgw_module.runner_contract_sha256(),
        "runner_launch_admission": runtime["targets"][TARGET]["runner_launch_admission"],
        "runner_launch_admission_sha256": sgw_module.runner_launch_admission_sha256(
            TARGET,
            runtime["targets"][TARGET]["runner_launch_admission"],
        ),
        "module_installed_sha256": runtime["targets"][TARGET]["module_installed_sha256"],
        "module_signature": runtime["targets"][TARGET]["module_signature"],
        "components": components,
        "runner": {
            "path": f"dist/native/{TARGET}/s-gw-core",
            "sha256": files[f"dist/native/{TARGET}/s-gw-core"],
            "signature": approved["runner"]["signature"],
        },
        "files": files,
    }
    write_json(package / "defenseclaw-module.json", metadata)

    artifact = tmp_path / "module.tar.gz"
    with tarfile.open(artifact, "w:gz") as archive:
        archive.add(package, arcname="package")
    return artifact, metadata


def run_driver(
    manifest: Path,
    runtime: Path,
    home: Path,
    node: str,
    *arguments: str,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["DEFENSECLAW_SGW_RUNNER_MANIFEST"] = str(runtime)
    return subprocess.run(
        [
            sys.executable,
            str(DRIVER),
            "--manifest",
            str(manifest),
            "--home",
            str(home),
            "--node",
            node,
            "--target",
            TARGET,
            *arguments,
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def test_release_manifest_requires_unlock_and_approval_components() -> None:
    runtime = json.loads(RUNTIME_MANIFEST.read_text(encoding="utf-8"))
    expected = {"runner", "credential_helper", "approval_ui", "license_bundle"}
    assert runtime["redistribution_status"] == "not_approved"
    assert runtime["signature_policy"] == {
        "algorithm": sgw_module.COMPONENT_SIGNATURE_ALGORITHM,
        "public_key": None,
        "public_key_sha256": None,
    }
    assert runtime["runner_contract"] == sgw_module.RUNNER_CONTRACT
    assert len(sgw_module.runner_contract_sha256()) == 64
    assert runtime["runner_contract"]["console_arguments"] == [
        "console",
        "open",
        "--protocol-version",
        "1",
    ]
    assert "console_bootstrap" not in runtime["runner_contract"]
    for target, record in runtime["targets"].items():
        assert set(record["components"]) == expected
        assert record["components"]["approval_ui"]["destination"] == "dist/console-ui"
        assert record["components"]["approval_ui"]["required_files"] == ["index.html", "capabilities.json"]
        assert record["components"]["approval_ui"]["required_directories"] == ["assets"]
        assert record["components"]["approval_ui"]["required_capabilities"] == [
            "defenseclaw.pending-enrollment.v1",
            "defenseclaw.approval-console-session.v1",
        ]
        assert record["components"]["license_bundle"] == {
            "filename": "THIRD_PARTY_LICENSES.txt",
            "path": None,
            "sha256": None,
            "installed_sha256": None,
            "signature": None,
            "destination": "THIRD_PARTY_LICENSES.txt",
            "format": "file",
            "executable": False,
        }
        assert record["module_installed_sha256"] is None
        assert record["module_signature"] is None
        assert record["runner_launch_admission"] is None
        assert all(component["path"] is None for component in record["components"].values()), target
        assert all(component["installed_sha256"] is None for component in record["components"].values())
        assert all(component["signature"] is None for component in record["components"].values())


@pytest.mark.parametrize(
    ("target", "payload"),
    (
        ("linux-x64", elf_payload(62)),
        ("linux-arm64", elf_payload(183)),
        ("win32-x64", pe_payload(0x8664)),
        ("win32-arm64", pe_payload(0xAA64)),
        ("darwin-x64", macho_payload(0x01000007)),
        ("darwin-arm64", macho_payload(0x0100000C)),
        ("darwin-x64", fat_macho_payload([0x01000007, 0x0100000C])),
        ("darwin-arm64", fat_macho_payload([0x01000007, 0x0100000C], fat64=True)),
    ),
)
def test_native_component_architecture_matches_exact_target(tmp_path: Path, target: str, payload: bytes) -> None:
    candidate = tmp_path / "native-component"
    candidate.write_bytes(payload)

    build_sgw_module.validate_native_architecture(candidate, target, "runner")


@pytest.mark.parametrize(
    ("target", "payload"),
    (
        ("linux-x64", elf_payload(183)),
        ("linux-arm64", elf_payload(62)),
        ("win32-x64", pe_payload(0xAA64)),
        ("win32-arm64", pe_payload(0x8664)),
        ("darwin-x64", macho_payload(0x0100000C)),
        ("darwin-arm64", macho_payload(0x01000007)),
        ("darwin-arm64", fat_macho_payload([0x01000007])),
        ("darwin-x64", b"\xcf\xfa\xed\xfe"),
    ),
)
def test_native_component_architecture_rejects_wrong_or_truncated_target(
    tmp_path: Path,
    target: str,
    payload: bytes,
) -> None:
    candidate = tmp_path / "native-component"
    candidate.write_bytes(payload)

    with pytest.raises(build_sgw_module.BuildError, match=f"target architecture {target}"):
        build_sgw_module.validate_native_architecture(candidate, target, "credential_helper")


def test_offline_signing_rejects_wrong_target_architecture(tmp_path: Path) -> None:
    _runtime_path, runtime, _private_key = runtime_fixture(tmp_path)
    wrong_runner = tmp_path / "arm64-runner"
    wrong_runner.write_bytes(elf_payload(183, "wrong-runner"))
    records = runtime["targets"][TARGET]["components"]
    candidate = {
        "schema_version": 1,
        "target": TARGET,
        "runner_launch_admission": runtime["targets"][TARGET]["runner_launch_admission"],
        "components": {name: {"path": record["path"], "sha256": record["sha256"]} for name, record in records.items()},
    }
    candidate["components"]["runner"] = {
        "path": str(wrong_runner),
        "sha256": digest(wrong_runner),
    }
    candidate_path = tmp_path / "signing-candidate.json"
    write_json(candidate_path, candidate)
    module = json.loads(MODULE_MANIFEST.read_text(encoding="utf-8"))

    with pytest.raises(build_sgw_module.BuildError, match="target architecture linux-x64"):
        build_sgw_module.signing_candidates(candidate_path, module, TARGET)


def test_windows_private_acl_uses_bounded_powershell_arguments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    managed_file = tmp_path / "receipt.json"
    managed_file.write_text("{}\n", encoding="utf-8")
    observed: dict[str, object] = {}

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed["argv"] = argv
        observed["kwargs"] = kwargs
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(
        sgw_module,
        "trusted_windows_powershell",
        lambda **_kwargs: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    )
    monkeypatch.setattr(sgw_module.subprocess, "run", fake_run)
    monkeypatch.setenv("DEFENSECLAW_SGW_ACL_OPERATION", "hostile")
    monkeypatch.setenv("DEFENSECLAW_SGW_ACL_SCOPE", "hostile")
    monkeypatch.setenv("DEFENSECLAW_SGW_ACL_ROOT", "C:\\hostile")

    sgw_module.windows_private_acl(
        managed_file,
        operation="apply",
        recursive=False,
        code="install_failed",
    )

    argv = observed["argv"]
    kwargs = observed["kwargs"]
    assert isinstance(argv, list)
    assert argv[-2:] == ["-Command", sgw_module._WINDOWS_PRIVATE_ACL_SCRIPT]
    assert str(managed_file.resolve()) not in argv
    assert isinstance(kwargs, dict)
    assert kwargs["shell"] is False
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["stdout"] is subprocess.DEVNULL
    assert kwargs["stderr"] is subprocess.DEVNULL
    child_env = kwargs["env"]
    assert isinstance(child_env, dict)
    assert child_env["DEFENSECLAW_SGW_ACL_OPERATION"] == "apply"
    assert child_env["DEFENSECLAW_SGW_ACL_SCOPE"] == "single"
    assert child_env["DEFENSECLAW_SGW_ACL_ROOT"] == str(managed_file.resolve())
    assert "$args.Count -ne 0" in sgw_module._WINDOWS_PRIVATE_ACL_SCRIPT
    assert 'GetEnvironmentVariable("DEFENSECLAW_SGW_ACL_ROOT", "Process")' in sgw_module._WINDOWS_PRIVATE_ACL_SCRIPT
    assert "SetAccessRuleProtection($true, $false)" in sgw_module._WINDOWS_PRIVATE_ACL_SCRIPT
    assert 'SecurityIdentifier]::new("S-1-5-18")' in sgw_module._WINDOWS_PRIVATE_ACL_SCRIPT
    source = (ROOT / "scripts" / "sgw_module.py").read_text(encoding="utf-8")
    assert 'shutil.which("powershell.exe")' not in source


def test_windows_private_acl_replaces_only_owner_and_access_sections() -> None:
    script = sgw_module._WINDOWS_PRIVATE_ACL_SCRIPT

    assert "RemoveAccessRuleSpecific" not in script
    assert "$observed.SetSecurityDescriptorSddlForm($replacementSddl, $sections)" in script
    assert "$item.SetAccessControl($observed)" in script
    assert "Get-Acl" not in script
    assert "Set-Acl" not in script
    assert (
        """$sections = [System.Security.AccessControl.AccessControlSections]::Owner -bor `
            [System.Security.AccessControl.AccessControlSections]::Access"""
        in script
    )


def test_windows_private_acl_checks_each_ace_scope_before_unioning_rights() -> None:
    script = sgw_module._WINDOWS_PRIVATE_ACL_SCRIPT
    scope_check = """if ($rule.InheritanceFlags -ne $expectedInheritance -or
            $rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None)"""

    assert "GetAccessRules($true, $true" in script
    assert 'if ($rule.IsInherited) { throw "managed ACL inherits an access rule" }' in script
    assert "$inheritanceBySid" not in script
    assert script.index(scope_check) < script.index("$rights[$sid] = $rights[$sid] -bor $rule.FileSystemRights")


def run_native_windows_powershell(script: str, *arguments: Path) -> subprocess.CompletedProcess[str]:
    powershell = sgw_module.trusted_windows_powershell(code="test_failed")
    child_env = os.environ.copy()
    prefix = "DEFENSECLAW_TEST_POWERSHELL_ARG_"
    for name in [key for key in child_env if key.startswith(prefix)]:
        child_env.pop(name)
    argument_loaders: list[str] = []
    for index, argument in enumerate(arguments):
        name = f"{prefix}{index}"
        child_env[name] = str(argument)
        argument_loaders.append(f'[Environment]::GetEnvironmentVariable("{name}", "Process")')
    wrapped = "$fixtureArgs = @(\n" + "\n".join(f"    {item}" for item in argument_loaders) + "\n)\n& {\n"
    wrapped += script + "\n} @fixtureArgs"
    return subprocess.run(
        [
            powershell,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            wrapped,
        ],
        check=True,
        capture_output=True,
        env=child_env,
        text=True,
        timeout=30,
        shell=False,
    )


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows owner/DACL APIs")
def test_native_windows_acl_apply_recursively_removes_unwanted_aces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    managed = tmp_path / "managed"
    nested = managed / "nested"
    nested.mkdir(parents=True)
    (nested / "receipt.json").write_text("{}\n", encoding="utf-8")
    run_native_windows_powershell(
        r"""
$ErrorActionPreference = "Stop"
$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$systemSid = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-18")
$everyoneSid = [System.Security.Principal.SecurityIdentifier]::new("S-1-1-0")
$root = Get-Item -LiteralPath $args[0] -Force -ErrorAction Stop
$items = @($root) + @(Get-ChildItem -LiteralPath $root.FullName -Force -Recurse -ErrorAction Stop)
foreach ($item in $items) {
    $isDirectory = [bool]$item.PSIsContainer
    $acl = if ($isDirectory) {
        [System.Security.AccessControl.DirectorySecurity]::new()
    } else {
        [System.Security.AccessControl.FileSecurity]::new()
    }
    $inheritance = if ($isDirectory) {
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else {
        [System.Security.AccessControl.InheritanceFlags]::None
    }
    $acl.SetOwner($currentSid)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($currentSid, $systemSid)) {
        [void]$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        ))
    }
    [void]$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        $everyoneSid,
        [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
        $inheritance,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    ))
    $item.SetAccessControl($acl)
}
""",
        managed,
    )
    monkeypatch.setenv("DEFENSECLAW_SGW_ACL_OPERATION", "hostile")
    monkeypatch.setenv("DEFENSECLAW_SGW_ACL_SCOPE", "hostile")
    monkeypatch.setenv("DEFENSECLAW_SGW_ACL_ROOT", "C:\\hostile")

    with pytest.raises(sgw_module.ModuleError, match="private Windows ACL"):
        sgw_module.windows_private_acl(
            managed,
            operation="verify",
            recursive=True,
            code="artifact_invalid",
        )

    sgw_module.windows_private_acl(
        managed,
        operation="apply",
        recursive=True,
        code="artifact_invalid",
    )
    sgw_module.windows_private_acl(
        managed,
        operation="verify",
        recursive=True,
        code="artifact_invalid",
    )


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows owner/DACL APIs")
def test_native_windows_acl_does_not_require_security_module(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    managed = tmp_path / "managed"
    nested = managed / "nested"
    nested.mkdir(parents=True)
    (nested / "receipt.json").write_text("{}\n", encoding="utf-8")
    empty_module_path = tmp_path / "empty-modules"
    empty_module_path.mkdir()
    monkeypatch.setenv("PSModulePath", str(empty_module_path))

    sgw_module.windows_private_acl(
        managed,
        operation="apply",
        recursive=True,
        code="artifact_invalid",
    )
    sgw_module.windows_private_acl(
        managed,
        operation="verify",
        recursive=True,
        code="artifact_invalid",
    )


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows owner/DACL APIs")
def test_native_windows_acl_rejects_split_inheritance_across_aces(tmp_path: Path) -> None:
    managed = tmp_path / "managed"
    managed.mkdir()
    run_native_windows_powershell(
        r"""
$ErrorActionPreference = "Stop"
$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sddl = "O:$($currentSid)D:P" +
    "(A;;FA;;;$currentSid)" +
    "(A;OICI;RC;;;$currentSid)" +
    "(A;OICI;FA;;;SY)"
$item = Get-Item -LiteralPath $args[0] -Force -ErrorAction Stop
$sections = [System.Security.AccessControl.AccessControlSections]::Owner -bor `
    [System.Security.AccessControl.AccessControlSections]::Access
$acl = $item.GetAccessControl()
$acl.SetSecurityDescriptorSddlForm($sddl, $sections)
$item.SetAccessControl($acl)
""",
        managed,
    )

    with pytest.raises(sgw_module.ModuleError, match="private Windows ACL"):
        sgw_module.windows_private_acl(
            managed,
            operation="verify",
            recursive=False,
            code="artifact_invalid",
        )


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows reparse points")
def test_native_windows_acl_rejects_reparse_points_in_recursive_tree(tmp_path: Path) -> None:
    managed = tmp_path / "managed"
    target = tmp_path / "outside"
    managed.mkdir()
    target.mkdir()
    sgw_module.windows_private_acl(
        managed,
        operation="apply",
        recursive=True,
        code="artifact_invalid",
    )
    junction = managed / "junction"
    run_native_windows_powershell(
        "New-Item -ItemType Junction -Path $args[0] -Target $args[1] -ErrorAction Stop | Out-Null",
        junction,
        target,
    )

    try:
        with pytest.raises(sgw_module.ModuleError, match="private Windows ACL"):
            sgw_module.windows_private_acl(
                managed,
                operation="verify",
                recursive=True,
                code="artifact_invalid",
            )
    finally:
        run_native_windows_powershell(
            "Remove-Item -LiteralPath $args[0] -Force -ErrorAction Stop",
            junction,
        )


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows owner/DACL APIs")
def test_native_windows_acl_apply_normalizes_noncanonical_dacl(tmp_path: Path) -> None:
    managed = tmp_path / "managed"
    managed.mkdir()
    group_before = run_native_windows_powershell(
        r"""
$ErrorActionPreference = "Stop"
$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sections = [System.Security.AccessControl.AccessControlSections]::Owner -bor `
    [System.Security.AccessControl.AccessControlSections]::Access
$item = Get-Item -LiteralPath $args[0] -Force -ErrorAction Stop
$acl = $item.GetAccessControl()
$sddl = "O:$($currentSid)D:P" +
    "(A;OICI;FA;;;$currentSid)" +
    "(A;OICI;FA;;;SY)" +
    "(D;OICI;WD;;;WD)"
$acl.SetSecurityDescriptorSddlForm($sddl, $sections)
$item.SetAccessControl($acl)
$observed = $item.GetAccessControl()
if ($observed.AreAccessRulesCanonical) { throw "fixture DACL was canonicalized" }
$observed.GetSecurityDescriptorSddlForm(
    [System.Security.AccessControl.AccessControlSections]::Group
)
""",
        managed,
    ).stdout.strip()

    sgw_module.windows_private_acl(
        managed,
        operation="apply",
        recursive=False,
        code="artifact_invalid",
    )
    sgw_module.windows_private_acl(
        managed,
        operation="verify",
        recursive=False,
        code="artifact_invalid",
    )
    group_after = run_native_windows_powershell(
        r"""
$item = Get-Item -LiteralPath $args[0] -Force -ErrorAction Stop
$acl = $item.GetAccessControl()
if (-not $acl.AreAccessRulesCanonical) { throw "managed DACL remains noncanonical" }
$acl.GetSecurityDescriptorSddlForm(
    [System.Security.AccessControl.AccessControlSections]::Group
)
""",
        managed,
    ).stdout.strip()

    assert group_after == group_before


def test_runtime_json_rejects_duplicate_keys_and_bounded_output(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":1,"schema_version":1}\n', encoding="utf-8")
    with pytest.raises(sgw_module.ModuleError, match="duplicate JSON key"):
        sgw_module.read_json(duplicate, "manifest_invalid")

    returncode, output, overflow = sgw_module.run_bounded_output(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 1024)"],
        timeout=5,
        max_bytes=64,
    )
    assert returncode == 0
    assert output == b"x" * 64
    assert overflow is True


def test_runtime_json_accepts_stable_windows_descriptor_ctime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"schema_version":1}\n', encoding="utf-8")
    real_fstat = sgw_module.os.fstat

    def windows_fstat(descriptor: int) -> SimpleNamespace:
        info = real_fstat(descriptor)
        return SimpleNamespace(
            st_dev=info.st_dev,
            st_ino=info.st_ino,
            st_mode=info.st_mode,
            st_size=info.st_size,
            st_mtime_ns=info.st_mtime_ns,
            st_ctime_ns=info.st_ctime_ns + 1,
        )

    monkeypatch.setattr(sgw_module.os, "fstat", windows_fstat)

    assert sgw_module.read_json(manifest, "manifest_invalid") == {"schema_version": 1}


def test_runtime_json_rejects_descriptor_change_during_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text('{"schema_version":1}\n', encoding="utf-8")
    real_fstat = sgw_module.os.fstat
    calls = 0

    def changing_fstat(descriptor: int) -> SimpleNamespace:
        nonlocal calls
        calls += 1
        info = real_fstat(descriptor)
        return SimpleNamespace(
            st_dev=info.st_dev,
            st_ino=info.st_ino,
            st_mode=info.st_mode,
            st_size=info.st_size,
            st_mtime_ns=info.st_mtime_ns,
            st_ctime_ns=info.st_ctime_ns + calls,
        )

    monkeypatch.setattr(sgw_module.os, "fstat", changing_fstat)

    with pytest.raises(sgw_module.ModuleError, match="JSON input changed while it was read"):
        sgw_module.read_json(manifest, "manifest_invalid")


def test_build_cleanup_excludes_mutable_npm_inventory(tmp_path: Path) -> None:
    node_modules = tmp_path / "node_modules"
    cache = node_modules / ".vite"
    cache.mkdir(parents=True)
    (cache / "state.json").write_text("{}\n", encoding="utf-8")
    hidden_lock = node_modules / ".package-lock.json"
    hidden_lock.write_text("{}\n", encoding="utf-8")

    build_sgw_module.remove_build_caches(tmp_path)

    assert not cache.exists()
    assert not hidden_lock.exists()


def test_built_module_keeps_complete_upstream_attribution(tmp_path: Path) -> None:
    stage = tmp_path / "source"
    package = tmp_path / "package"
    stage.mkdir()
    package.mkdir()

    upstream = ROOT / "third_party" / "s-gw" / "upstream"
    for leaf in ("LICENSE", "NOTICE", "README.md", "TRADEMARKS.md", "package.json", "package-lock.json"):
        shutil.copy2(upstream / leaf, stage / leaf)
    shutil.copytree(upstream / "docs" / "ui", stage / "docs" / "ui")
    (stage / "dist").mkdir()
    (stage / "dist" / "mcp-server.js").write_text("export {};\n", encoding="utf-8")
    (stage / "node_modules").mkdir()
    (stage / "node_modules" / "runtime.js").write_text("export {};\n", encoding="utf-8")

    build_sgw_module.copy_runtime(stage, package)

    required = {
        "docs/ui/THIRD_PARTY_NOTICES.md",
        "docs/ui/vendor/d3-sankey/d3-array.LICENSE.txt",
        "docs/ui/vendor/d3-sankey/d3-path.LICENSE.txt",
        "docs/ui/vendor/d3-sankey/d3-sankey.LICENSE.txt",
        "docs/ui/vendor/d3-sankey/d3-shape.LICENSE.txt",
        "docs/ui/vendor/sankeymatic/LICENSE.txt",
    }
    module = json.loads(MODULE_MANIFEST.read_text(encoding="utf-8"))
    assert required <= set(module["source_selection"]["files"])
    for relative in required:
        assert (package / relative).read_bytes() == (upstream / relative).read_bytes()


def test_runner_alone_cannot_make_a_production_module(tmp_path: Path) -> None:
    module = json.loads(MODULE_MANIFEST.read_text(encoding="utf-8"))
    runtime = json.loads(RUNTIME_MANIFEST.read_text(encoding="utf-8"))
    private_key = configure_signing(runtime)
    runner = tmp_path / "s-gw-core"
    runner.write_bytes(elf_payload(label="runner"))
    destination = runtime["targets"][TARGET]["components"]["runner"]["destination"]
    sign_component(runtime, private_key, "runner", runner, {destination: digest(runner)})
    set_module_signature(runtime, private_key, {"placeholder": "0" * 64})
    path = tmp_path / "runner-only.json"
    write_json(path, runtime)

    with pytest.raises(build_sgw_module.BuildError, match="credential_helper, approval_ui, license_bundle"):
        build_sgw_module.components_for_target(path, module, TARGET, allow_missing=False)
    assert build_sgw_module.components_for_target(path, module, TARGET, allow_missing=True) == {}


@pytest.mark.parametrize(
    "tamper",
    ("forged", "wrong_key", "wrong_target", "wrong_component", "installed_digest", "module_signature"),
)
def test_release_signatures_are_cryptographic_and_context_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    runtime_path, runtime, private_key = runtime_fixture(tmp_path)
    runner = runtime["targets"][TARGET]["components"]["runner"]
    if tamper == "forged":
        runner["signature"] = base64.b64encode(b"\0" * 64).decode("ascii")
    elif tamper == "wrong_key":
        configure_signing(runtime)
    elif tamper == "wrong_target":
        runner["signature"] = signature(
            private_key,
            sgw_module.component_signature_payload(
                "linux-arm64",
                "runner",
                runner["destination"],
                runner["sha256"],
                runner["installed_sha256"],
            ),
        )
    elif tamper == "wrong_component":
        runner["signature"] = signature(
            private_key,
            sgw_module.component_signature_payload(
                TARGET,
                "credential_helper",
                runner["destination"],
                runner["sha256"],
                runner["installed_sha256"],
            ),
        )
    elif tamper == "installed_digest":
        runner["installed_sha256"] = "1" * 64
    else:
        runtime["targets"][TARGET]["module_signature"] = base64.b64encode(b"\0" * 64).decode("ascii")
    write_json(runtime_path, runtime)

    module = json.loads(MODULE_MANIFEST.read_text(encoding="utf-8"))
    with pytest.raises(build_sgw_module.BuildError, match="signature|installed digest"):
        build_sgw_module.components_for_target(runtime_path, module, TARGET, allow_missing=False)

    monkeypatch.setenv("DEFENSECLAW_SGW_RUNNER_MANIFEST", str(runtime_path))
    with pytest.raises(sgw_module.ModuleError, match="signature"):
        sgw_module.component_records(MODULE_MANIFEST, module, TARGET, require_approved=True)


def test_license_bundle_is_required_and_signature_bound(tmp_path: Path) -> None:
    runtime_path, runtime, _private_key = runtime_fixture(tmp_path)
    module = json.loads(MODULE_MANIFEST.read_text(encoding="utf-8"))
    license_record = runtime["targets"][TARGET]["components"]["license_bundle"]
    Path(license_record["path"]).write_text("rewritten licenses\n", encoding="utf-8")

    with pytest.raises(build_sgw_module.BuildError, match="license_bundle digest does not match"):
        build_sgw_module.components_for_target(runtime_path, module, TARGET, allow_missing=False)


def test_ed25519_signature_requires_canonical_padded_base64(tmp_path: Path) -> None:
    _runtime_path, runtime, private_key = runtime_fixture(tmp_path)
    public_key, _fingerprint = sgw_module.component_signing_key(runtime)
    assert public_key is not None
    signed = signature(private_key, b"payload")

    with pytest.raises(ValueError, match="strict base64"):
        sgw_module.verify_ed25519_signature(public_key, signed.rstrip("="), b"payload")


def test_signature_payloads_have_a_fixed_cross_language_contract() -> None:
    module = json.loads(MODULE_MANIFEST.read_text(encoding="utf-8"))
    admission = {
        "schema_version": 1,
        "mode": "linux-sealed-memfd-v1",
        "signature_scope": "installed-runner-bytes",
        "dependency_policy": "system-only-v1",
    }
    admission_sha256 = sgw_module.runner_launch_admission_sha256(TARGET, admission)
    contract_sha256 = sgw_module.runner_contract_sha256()

    assert sgw_module.component_signature_payload(
        TARGET,
        "runner",
        f"dist/native/{TARGET}/s-gw-core",
        "a" * 64,
        "b" * 64,
    ).decode("ascii") == (
        "defenseclaw.s-gw.component-signature.v1\n"
        "schema_version=1\n"
        "target=linux-x64\n"
        "component=runner\n"
        "destination=dist/native/linux-x64/s-gw-core\n"
        f"artifact_sha256={'a' * 64}\n"
        f"installed_sha256={'b' * 64}\n"
    )
    assert sgw_module.runner_launch_admission_payload(TARGET, admission).decode("ascii") == (
        "defenseclaw.s-gw.runner-launch-admission.v1\n"
        "schema_version=1\n"
        "target=linux-x64\n"
        "mode=linux-sealed-memfd-v1\n"
        "signature_scope=installed-runner-bytes\n"
        "dependency_policy=system-only-v1\n"
        "pe_machine=\n"
        "required_mitigations=\n"
        "team_id=\n"
        "signing_id=\n"
        "cdhash=\n"
        "required_cs_flags=\n"
    )
    assert sgw_module.module_signature_payload(
        TARGET,
        module,
        "c" * 64,
        admission_sha256,
        contract_sha256,
    ).decode("ascii") == (
        "defenseclaw.s-gw.module-signature.v1\n"
        "schema_version=1\n"
        "target=linux-x64\n"
        "package_name=@s-gw/s-gw\n"
        "package_version=0.2.0\n"
        "upstream_revision=652b042ef61da6170cb26aa8e4d8e446dc1c9b22\n"
        "upstream_tree=0451e84cbfa65c5050df309c1b045344b75dae10\n"
        f"runner_contract_sha256={contract_sha256}\n"
        f"runner_launch_admission_sha256={admission_sha256}\n"
        f"installed_sha256={'c' * 64}\n"
    )


def test_prepare_signing_rebuilds_without_mutating_release_manifests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_before = MODULE_MANIFEST.read_bytes()
    runtime_before = RUNTIME_MANIFEST.read_bytes()
    candidate = tmp_path / "candidate.json"
    write_json(candidate, {})
    output_dir = tmp_path / "signing"
    calls: list[Path] = []
    inventories: list[dict[str, str]] = []
    admission = {
        "schema_version": 1,
        "mode": "linux-sealed-memfd-v1",
        "signature_scope": "installed-runner-bytes",
        "dependency_policy": "system-only-v1",
    }

    monkeypatch.setattr(build_sgw_module.sync_sgw_vendor, "verify", lambda: None)
    monkeypatch.setattr(build_sgw_module, "signing_candidates", lambda *_args: (admission, {}))
    monkeypatch.setattr(build_sgw_module, "snapshot_signing_candidates", lambda records, _path: records)

    def fake_assemble(
        _args: argparse.Namespace,
        _manifest: dict,
        _records: dict,
        temp_root: Path,
        **_kwargs: object,
    ) -> tuple[Path, dict[str, dict[str, object]], set[str]]:
        calls.append(temp_root)
        package = temp_root / "module" / "package"
        (package / "dist" / "native" / TARGET).mkdir(parents=True)
        (package / "dist" / "console-ui" / "assets").mkdir(parents=True)
        (package / "package.json").write_text('{"name":"@s-gw/s-gw","version":"0.2.0"}\n')
        (package / "dist" / "cli.js").write_text("export {};\n")
        (package / "dist" / "mcp-server.js").write_text("export {};\n")
        (package / "THIRD_PARTY_LICENSES.txt").write_text(LICENSE_BUNDLE)
        runner = f"dist/native/{TARGET}/s-gw-core"
        helper = f"dist/native/{TARGET}/s-gw-secret-service-helper"
        ui_files = [
            "dist/console-ui/assets/app.js",
            "dist/console-ui/capabilities.json",
            "dist/console-ui/index.html",
        ]
        (package / runner).write_bytes(elf_payload(label="runner"))
        (package / helper).write_bytes(elf_payload(label="helper"))
        (package / ui_files[0]).write_text("export {};\n")
        (package / ui_files[1]).write_text('{"schema_version":1,"capabilities":[]}\n')
        (package / ui_files[2]).write_text("<main></main>\n")
        groups = {
            "runner": [runner],
            "credential_helper": [helper],
            "approval_ui": ui_files,
            "license_bundle": ["THIRD_PARTY_LICENSES.txt"],
        }
        components: dict[str, dict[str, object]] = {}
        for index, (name, paths) in enumerate(groups.items(), start=1):
            installed = {relative: digest(package / relative) for relative in paths}
            components[name] = {
                "artifact_sha256": str(index) * 64,
                "installed_sha256": sgw_module.component_inventory_sha256(installed),
                "signature": None,
                "destination": {
                    "runner": f"dist/native/{TARGET}/s-gw-core",
                    "credential_helper": f"dist/native/{TARGET}/s-gw-secret-service-helper",
                    "approval_ui": "dist/console-ui",
                    "license_bundle": "THIRD_PARTY_LICENSES.txt",
                }[name],
                "files": paths,
            }
        inventories.append(build_sgw_module.complete_file_inventory(package))
        return package, components, {runner, helper}

    monkeypatch.setattr(build_sgw_module, "assemble_package", fake_assemble)
    args = argparse.Namespace(
        module_manifest=MODULE_MANIFEST,
        target=TARGET,
        candidate_components=candidate,
        output_dir=output_dir,
        signing_request_output=None,
        skip_tests=False,
        node=None,
        npm=None,
    )
    request_path, archive_path, request_sha256, archive_sha256 = build_sgw_module.prepare_signing(args)

    request = json.loads(request_path.read_text(encoding="utf-8"))
    assert len(calls) == 2
    assert request["request_type"] == "defenseclaw.s-gw.offline-signing-request.v1"
    assert request["module"]["installed_sha256"] == sgw_module.module_inventory_sha256(inventories[0])
    assert request["unsigned_archive"] == {"filename": archive_path.name, "sha256": archive_sha256}
    assert digest(request_path) == request_sha256
    assert archive_path.is_file()
    assert MODULE_MANIFEST.read_bytes() == module_before
    assert RUNTIME_MANIFEST.read_bytes() == runtime_before


def test_go_release_key_is_blank_until_runtime_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = json.loads(RUNTIME_MANIFEST.read_text(encoding="utf-8"))
    assert build_sgw_module.go_release_trust_anchor() == ("", "")
    build_sgw_module.validate_go_release_trust_anchor(runtime)
    configure_signing(runtime)
    with pytest.raises(build_sgw_module.BuildError, match="does not match"):
        build_sgw_module.validate_go_release_trust_anchor(runtime)

    go_key = tmp_path / "sgw_release_key.go"
    go_key.write_text(
        build_sgw_module.go_release_key_source(
            runtime["signature_policy"]["public_key"],
            runtime["signature_policy"]["public_key_sha256"],
        ),
        encoding="ascii",
    )
    monkeypatch.setattr(build_sgw_module, "GO_RELEASE_KEY", go_key)
    build_sgw_module.validate_go_release_trust_anchor(runtime)

    canonical = go_key.read_text(encoding="ascii")
    for tampered in (
        canonical + "\nvar releaseKeyOverride = true\n",
        canonical.replace("package gateway\n", 'package gateway\n\nimport "unsafe"\n', 1),
        canonical.replace('const sgwReleasePublicKeyPEM = "-----', 'const sgwReleasePublicKeyPEM = "\\u002d----', 1),
    ):
        go_key.write_text(tampered, encoding="ascii")
        with pytest.raises(build_sgw_module.BuildError, match="canonical source template"):
            build_sgw_module.go_release_trust_anchor()


def test_probe_is_read_only_and_reports_each_missing_component(tmp_path: Path) -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is not installed")
    home = tmp_path / "home"
    result = run_driver(MODULE_MANIFEST, RUNTIME_MANIFEST, home, node, "probe")

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["state"] == "runner_unavailable"
    assert payload["runner"]["available"] is False
    assert set(payload["components"]) == {"runner", "credential_helper", "approval_ui", "license_bundle"}
    assert all(not item["available"] for item in payload["components"].values())
    assert not home.exists()


def test_builder_inventories_helper_and_every_approval_ui_file(tmp_path: Path) -> None:
    runtime_path, runtime, private_key = runtime_fixture(tmp_path)
    module = json.loads(MODULE_MANIFEST.read_text(encoding="utf-8"))
    package = tmp_path / "staged-package"
    (package / "dist").mkdir(parents=True)
    (package / "package.json").write_text('{"name":"@s-gw/s-gw","version":"0.2.0"}\n', encoding="utf-8")
    (package / "dist" / "cli.js").write_text("export {};\n", encoding="utf-8")
    (package / "dist" / "mcp-server.js").write_text("export {};\n", encoding="utf-8")

    records = build_sgw_module.components_for_target(runtime_path, module, TARGET, allow_missing=False)
    components, executable_paths = build_sgw_module.copy_production_components(package, records)
    set_module_signature(runtime, private_key, build_sgw_module.complete_file_inventory(package))
    write_json(runtime_path, runtime)
    release_records = build_sgw_module.components_for_target(runtime_path, module, TARGET, allow_missing=False)
    metadata = build_sgw_module.module_metadata(
        package,
        module,
        TARGET,
        components,
        release_records,
    )

    assert metadata["production_ready"] is True
    assert metadata["inventory_excludes"] == ["defenseclaw-module.json"]
    assert executable_paths == {
        f"dist/native/{TARGET}/s-gw-core",
        f"dist/native/{TARGET}/s-gw-secret-service-helper",
    }
    assert set(metadata["files"]) >= {
        f"dist/native/{TARGET}/s-gw-core",
        f"dist/native/{TARGET}/s-gw-secret-service-helper",
        "dist/console-ui/index.html",
        "dist/console-ui/capabilities.json",
        "dist/console-ui/assets/app.js",
        "THIRD_PARTY_LICENSES.txt",
    }
    assert components["approval_ui"]["files"] == [
        "dist/console-ui/assets/app.js",
        "dist/console-ui/capabilities.json",
        "dist/console-ui/index.html",
    ]
    assert components["license_bundle"]["files"] == ["THIRD_PARTY_LICENSES.txt"]


def test_builder_rejects_approval_ui_without_enrollment_capability(tmp_path: Path) -> None:
    runtime_path, runtime, private_key = runtime_fixture(tmp_path)
    legacy_ui = tmp_path / "legacy-console-ui"
    (legacy_ui / "assets").mkdir(parents=True)
    (legacy_ui / "index.html").write_text("<main>legacy approval</main>\n", encoding="utf-8")
    (legacy_ui / "assets" / "app.js").write_text("console.log('legacy');\n", encoding="utf-8")
    legacy_archive = tmp_path / "legacy-console-ui.tar.gz"
    with tarfile.open(legacy_archive, "w:gz") as archive:
        archive.add(legacy_ui, arcname="console-ui")
    legacy_files = {
        f"dist/console-ui/{item.relative_to(legacy_ui).as_posix()}": digest(item)
        for item in legacy_ui.rglob("*")
        if item.is_file()
    }
    sign_component(runtime, private_key, "approval_ui", legacy_archive, legacy_files)
    write_json(runtime_path, runtime)

    module = json.loads(MODULE_MANIFEST.read_text(encoding="utf-8"))
    records = build_sgw_module.components_for_target(runtime_path, module, TARGET, allow_missing=False)
    with pytest.raises(build_sgw_module.BuildError, match="required file: capabilities.json"):
        build_sgw_module.copy_production_components(tmp_path / "package", records)


@pytest.mark.skipif(os.name == "nt", reason="fixture uses POSIX private-mode assertions")
def test_install_receipt_and_command_are_bound_to_all_runtime_components(tmp_path: Path) -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is not installed")
    manifest = module_fixture(tmp_path)
    runtime_path, runtime, private_key = runtime_fixture(tmp_path)
    artifact, metadata = package_artifact(tmp_path, runtime_path, runtime, private_key)
    home = tmp_path / "home"

    installed = run_driver(
        manifest,
        runtime_path,
        home,
        node,
        "install",
        "--artifact",
        str(artifact),
        "--sha256",
        digest(artifact),
    )
    assert installed.returncode == 0, installed.stderr
    payload = json.loads(installed.stdout)
    assert payload["state"] == "ready"
    assert all(item["available"] for item in payload["components"].values())

    receipt_path = home / "modules" / "s-gw" / "receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert stat.S_IMODE(receipt_path.stat().st_mode) == 0o600
    assert receipt["components"] == metadata["components"]
    assert receipt["build_toolchain"] == metadata["build_toolchain"]
    assert set(receipt["files"]) == {*metadata["files"], "defenseclaw-module.json"}
    assert receipt["files"]["defenseclaw-module.json"] == digest(
        Path(payload["module"]["path"]) / "defenseclaw-module.json"
    )

    command = run_driver(
        manifest,
        runtime_path,
        home,
        node,
        "command",
        "--entrypoint",
        "mcp",
        "--",
        "--profile",
        "defenseclaw-tokenizer",
    )
    assert command.returncode == 0, command.stderr
    invocation = json.loads(command.stdout)
    assert invocation["argv"][0] == str(Path(node).resolve())
    assert invocation["argv"][1].endswith("/package/dist/mcp-server.js")
    assert invocation["argv"][2:] == ["--profile", "defenseclaw-tokenizer"]
    assert invocation["env"] == {
        "SGW_AGENT_NAME": "DefenseClaw",
        "SGW_DISABLE_UPDATE_CHECK": "1",
        "SGW_EXECUTION_ENGINE": "rust",
    }

    dependency = Path(payload["module"]["path"]) / "node_modules/tiny-runtime/index.js"
    dependency.write_text("export const runtime = false;\n", encoding="utf-8")
    invalid = run_driver(manifest, runtime_path, home, node, "status")
    assert invalid.returncode == 1
    assert json.loads(invalid.stderr)["error"]["code"] == "artifact_invalid"

    old_package_root = Path(receipt["package_root"])
    repaired = run_driver(
        manifest,
        runtime_path,
        home,
        node,
        "install",
        "--artifact",
        str(artifact),
        "--sha256",
        digest(artifact),
    )
    assert repaired.returncode == 0, repaired.stderr
    repaired_payload = json.loads(repaired.stdout)
    assert repaired_payload["state"] == "ready"

    repaired_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    repaired_package_root = Path(repaired_receipt["package_root"])
    assert repaired_package_root != old_package_root
    assert repaired_package_root.parent != old_package_root.parent
    assert repaired_package_root.is_dir()
    assert old_package_root.is_dir()
    assert dependency.read_text(encoding="utf-8") == "export const runtime = false;\n"
    assert (repaired_package_root / "node_modules/tiny-runtime/index.js").read_text(
        encoding="utf-8"
    ) == "export const runtime = true;\n"
    assert repaired_payload["module"]["path"] == str(repaired_package_root)

    repaired_command = run_driver(
        manifest,
        runtime_path,
        home,
        node,
        "command",
        "--entrypoint",
        "mcp",
    )
    assert repaired_command.returncode == 0, repaired_command.stderr
    repaired_invocation = json.loads(repaired_command.stdout)
    assert repaired_invocation["cwd"] == str(repaired_package_root)
    assert repaired_invocation["argv"][1] == str(repaired_package_root / "dist/mcp-server.js")
