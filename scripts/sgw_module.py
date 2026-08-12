#!/usr/bin/env python3
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

"""Validate and resolve the private DefenseClaw s-gw module runtime."""

from __future__ import annotations

import argparse
import base64
import binascii
import ctypes
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_VERSION = 1
NODE_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TARGETS = (
    "darwin-x64",
    "darwin-arm64",
    "linux-x64",
    "linux-arm64",
    "win32-x64",
    "win32-arm64",
)
RUNTIME_MANIFEST_FIELDS = {
    "schema_version",
    "component",
    "license",
    "redistribution_status",
    "required_for_production",
    "signature_policy",
    "runner_contract",
    "targets",
}
MAX_ARCHIVE_FILES = 100_000
MAX_ARCHIVE_FILE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_JSON_BYTES = 1024 * 1024
MODULE_METADATA_FILE = "defenseclaw-module.json"
MAX_NODE_VERSION_OUTPUT_BYTES = 4096
COMPONENT_SIGNATURE_ALGORITHM = "ed25519-sha256-v1"
COMPONENT_SIGNATURE_DOMAIN = "defenseclaw.s-gw.component-signature.v1"
MODULE_SIGNATURE_DOMAIN = "defenseclaw.s-gw.module-signature.v1"
RUNNER_LAUNCH_ADMISSION_DOMAIN = "defenseclaw.s-gw.runner-launch-admission.v1"
RUNNER_CONTRACT_DOMAIN = "defenseclaw.s-gw.runner-contract.v1"
COMPONENT_INVENTORY_DOMAIN = b"DefenseClaw s-gw component inventory\x00v1\x00"
MODULE_INVENTORY_DOMAIN = b"DefenseClaw s-gw module inventory\x00v1\x00"
MAX_SIGNING_KEY_BYTES = 1024
WINDOWS_RUNNER_MITIGATIONS = [
    "block-non-microsoft-binaries",
    "image-load-no-remote",
    "image-load-no-low-label",
]
MACOS_RUNNER_CS_FLAGS = ["valid", "hard", "kill", "runtime"]
RUNNER_CONTRACT = {
    "schema_version": 1,
    "runtime_contract": "defenseclaw.s-gw.native-runtime.v1",
    "protocol": "mcp-stdio-jsonrpc-2.0",
    "mcp_arguments": ["mcp", "--profile", "defenseclaw-tokenizer", "--protocol-version", "1"],
    "server_info": {"name": "s-gw-core", "version": "0.2.0"},
    "tools": ["sgw_prepare_proxy_tokenization"],
    "console_arguments": ["console", "open", "--protocol-version", "1"],
    "console_status": {
        "schema": "defenseclaw.s-gw.console-status.v1",
        "fields": ["schema_version", "status"],
        "statuses": ["opened", "already_open"],
    },
    "console_ui_binding": "runner-verified-signed-inventory-snapshot-v1",
    "console_browser_handoff": "native-os-api-or-absolute-system-launcher-v1",
    "approval_mutations": "native-authenticated-user-presence-only",
    "capabilities": [
        "defenseclaw.native-tokenizer-mcp.v1",
        "defenseclaw.approval-console-session.v1",
        "defenseclaw.pending-enrollment.v1",
    ],
}

_WINDOWS_PRIVATE_ACL_SCRIPT = r"""
$ErrorActionPreference = "Stop"
if ($args.Count -ne 0) { throw "invalid ACL request" }
$operation = [Environment]::GetEnvironmentVariable("DEFENSECLAW_SGW_ACL_OPERATION", "Process")
$scope = [Environment]::GetEnvironmentVariable("DEFENSECLAW_SGW_ACL_SCOPE", "Process")
$rawRoot = [Environment]::GetEnvironmentVariable("DEFENSECLAW_SGW_ACL_ROOT", "Process")
if ($operation -notin @("apply", "verify") -or
    $scope -notin @("single", "recursive") -or
    [string]::IsNullOrEmpty($rawRoot)) {
    throw "invalid ACL request"
}
$recursive = $scope -eq "recursive"
$root = [IO.Path]::GetFullPath($rawRoot)
$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$systemSid = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-18")
$wantedSids = @($currentSid.Value, $systemSid.Value) | Select-Object -Unique
$rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
$items = @($rootItem)
if ($recursive -and $rootItem.PSIsContainer) {
    $items += @(Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction Stop)
}

foreach ($item in $items) {
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "managed path is a reparse point"
    }
    $isDirectory = [bool]$item.PSIsContainer
    $observed = $item.GetAccessControl()
    $expectedInheritance = if ($isDirectory) {
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else {
        [System.Security.AccessControl.InheritanceFlags]::None
    }
    if ($operation -eq "apply") {
        $replacement = if ($isDirectory) {
            [System.Security.AccessControl.DirectorySecurity]::new()
        } else {
            [System.Security.AccessControl.FileSecurity]::new()
        }
        $replacement.SetOwner($currentSid)
        $replacement.SetAccessRuleProtection($true, $false)
        foreach ($sidValue in $wantedSids) {
            $sid = [System.Security.Principal.SecurityIdentifier]::new($sidValue)
            $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                $sid,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                $expectedInheritance,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            [void]$replacement.AddAccessRule($rule)
        }
        $sections = [System.Security.AccessControl.AccessControlSections]::Owner -bor `
            [System.Security.AccessControl.AccessControlSections]::Access
        $replacementSddl = $replacement.GetSecurityDescriptorSddlForm($sections)
        $observed.SetSecurityDescriptorSddlForm($replacementSddl, $sections)
        $item.SetAccessControl($observed)
    } elseif ($operation -ne "verify") {
        throw "invalid ACL operation"
    }

    $observed = $item.GetAccessControl()
    if (-not $observed.AreAccessRulesProtected) { throw "managed ACL inherits access" }
    if ($observed.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $currentSid.Value) {
        throw "managed ACL owner mismatch"
    }
    $rules = @($observed.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
    $rights = @{}
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if ($rule.IsInherited) { throw "managed ACL inherits an access rule" }
        if ($wantedSids -notcontains $sid) {
            throw "managed ACL grants an unexpected identity"
        }
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
            throw "managed ACL contains a deny rule"
        }
        if ($rule.InheritanceFlags -ne $expectedInheritance -or
            $rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None) {
            throw "managed ACL has unexpected inheritance"
        }
        if (-not $rights.ContainsKey($sid)) {
            $rights[$sid] = [System.Security.AccessControl.FileSystemRights]0
        }
        $rights[$sid] = $rights[$sid] -bor $rule.FileSystemRights
    }
    foreach ($sid in $wantedSids) {
        if (-not $rights.ContainsKey($sid) -or
            ($rights[$sid] -band [System.Security.AccessControl.FileSystemRights]::FullControl) -ne `
                [System.Security.AccessControl.FileSystemRights]::FullControl) {
            throw "managed ACL lacks full control"
        }
    }
}
"""


class ModuleError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class DuplicateJSONKeyError(ValueError):
    pass


def emit(payload: dict[str, object], *, stream: Any = sys.stdout) -> None:
    print(json.dumps(payload, separators=(",", ":"), sort_keys=True), file=stream)


def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateJSONKeyError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def json_file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def json_file_state(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (*json_file_identity(metadata), metadata.st_ctime_ns)


def read_json(path: Path, code: str) -> dict[str, Any]:
    descriptor = -1
    try:
        named_before = path.lstat()
        if not stat.S_ISREG(named_before.st_mode):
            raise ValueError("JSON input must be a bounded regular file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > MAX_JSON_BYTES:
            raise ValueError("JSON input must be a bounded regular file")
        chunks: list[bytes] = []
        remaining = MAX_JSON_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        named_after = path.lstat()
        if (
            len(payload) > MAX_JSON_BYTES
            or not stat.S_ISREG(named_after.st_mode)
            # Windows reports creation time for pathname ctime and NTFS change
            # time for descriptor ctime, so compare ctime only within one API.
            or json_file_identity(named_before) != json_file_identity(before)
            or json_file_identity(named_after) != json_file_identity(after)
            or json_file_state(named_before) != json_file_state(named_after)
            or json_file_state(before) != json_file_state(after)
            or len(payload) != after.st_size
        ):
            raise ValueError("JSON input changed while it was read")
        value = json.loads(payload.decode("utf-8", errors="strict"), object_pairs_hook=unique_json_object)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ModuleError(code, f"could not read {path}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(value, dict):
        raise ModuleError(code, f"{path} must contain one JSON object")
    return value


def default_manifest_path() -> Path:
    configured = os.environ.get("DEFENSECLAW_SGW_MODULE_MANIFEST", "").strip()
    if configured:
        return Path(configured).expanduser()
    adjacent = Path(__file__).resolve().with_name("s-gw-module.json")
    if adjacent.is_file():
        return adjacent
    return Path(__file__).resolve().parents[1] / "release" / "s-gw-module.json"


def load_manifest(path: Path) -> dict[str, Any]:
    value = read_json(path, "manifest_invalid")
    if value.get("schema_version") != SCHEMA_VERSION:
        raise ModuleError("manifest_invalid", "unsupported s-gw module manifest schema")
    required_strings = (
        "package_name",
        "package_version",
        "upstream_revision",
        "upstream_tree",
        "minimum_node_version",
        "runner_manifest",
    )
    for field in required_strings:
        if not isinstance(value.get(field), str) or not value[field]:
            raise ModuleError("manifest_invalid", f"s-gw module manifest has invalid {field}")
    if not NODE_VERSION_RE.fullmatch(value["minimum_node_version"]):
        raise ModuleError("manifest_invalid", "s-gw minimum Node version is invalid")
    build_toolchain = value.get("build_toolchain")
    if (
        not isinstance(build_toolchain, dict)
        or set(build_toolchain) != {"node", "npm"}
        or not all(
            isinstance(build_toolchain.get(name), str) and bool(re.fullmatch(r"\d+\.\d+\.\d+", build_toolchain[name]))
            for name in ("node", "npm")
        )
    ):
        raise ModuleError("manifest_invalid", "s-gw build toolchain is invalid")
    for field in ("upstream_revision", "upstream_tree"):
        if not re.fullmatch(r"[0-9a-f]{40}", value[field]):
            raise ModuleError("manifest_invalid", f"s-gw {field} is not a full Git object ID")
    entrypoints = value.get("entrypoints")
    if not isinstance(entrypoints, dict) or set(entrypoints) != {"cli", "mcp"}:
        raise ModuleError("manifest_invalid", "s-gw module entrypoints must be cli and mcp")
    for entrypoint in entrypoints.values():
        safe_relative_path(entrypoint, code="manifest_invalid")
    production_components(value)
    return value


def production_components(manifest: dict[str, Any]) -> tuple[str, ...]:
    raw = manifest.get("production_components")
    if not isinstance(raw, list) or not raw or not all(isinstance(item, str) and item for item in raw):
        raise ModuleError("manifest_invalid", "s-gw module manifest must name its production components")
    names = tuple(raw)
    required = {"runner", "credential_helper", "approval_ui", "license_bundle"}
    if len(set(names)) != len(names) or set(names) != required:
        raise ModuleError(
            "manifest_invalid",
            "s-gw production components must be runner, credential_helper, approval_ui, and license_bundle",
        )
    return names


def component_inventory_sha256(files: dict[str, str]) -> str:
    return installed_inventory_sha256(files, COMPONENT_INVENTORY_DOMAIN)


def module_inventory_sha256(files: dict[str, str]) -> str:
    return installed_inventory_sha256(files, MODULE_INVENTORY_DOMAIN)


def installed_inventory_sha256(files: dict[str, str], domain: bytes) -> str:
    if not files or len(files) > MAX_ARCHIVE_FILES:
        raise ValueError("installed file inventory is empty or too large")
    ordered = sorted(files, key=lambda item: item.encode("utf-8"))
    digest = hashlib.sha256()
    digest.update(domain)
    digest.update(len(ordered).to_bytes(4, "big"))
    for relative in ordered:
        normalized = safe_relative_path(relative, code="artifact_invalid").as_posix()
        file_sha256 = files[relative]
        if normalized != relative or not isinstance(file_sha256, str) or not SHA256_RE.fullmatch(file_sha256):
            raise ValueError("installed file inventory is invalid")
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(bytes.fromhex(file_sha256))
    return digest.hexdigest()


def component_signature_payload(
    target: str,
    component: str,
    destination: str,
    artifact_sha256: str,
    installed_sha256: str,
) -> bytes:
    if target not in TARGETS or component not in {
        "runner",
        "credential_helper",
        "approval_ui",
        "license_bundle",
    }:
        raise ValueError("component signature identity is invalid")
    normalized = safe_relative_path(destination, code="runner_manifest_invalid").as_posix()
    if (
        normalized != destination
        or not SHA256_RE.fullmatch(artifact_sha256)
        or not SHA256_RE.fullmatch(installed_sha256)
    ):
        raise ValueError("component signature statement is invalid")
    return (
        f"{COMPONENT_SIGNATURE_DOMAIN}\n"
        "schema_version=1\n"
        f"target={target}\n"
        f"component={component}\n"
        f"destination={destination}\n"
        f"artifact_sha256={artifact_sha256}\n"
        f"installed_sha256={installed_sha256}\n"
    ).encode("ascii")


def module_signature_payload(
    target: str,
    manifest: dict[str, Any],
    installed_sha256: str,
    runner_launch_admission_sha256: str,
    runner_contract_sha256: str,
) -> bytes:
    if (
        target not in TARGETS
        or not SHA256_RE.fullmatch(installed_sha256)
        or not SHA256_RE.fullmatch(runner_launch_admission_sha256)
        or not SHA256_RE.fullmatch(runner_contract_sha256)
    ):
        raise ValueError("module signature identity is invalid")
    package_name = manifest.get("package_name")
    package_version = manifest.get("package_version")
    revision = manifest.get("upstream_revision")
    tree = manifest.get("upstream_tree")
    if (
        package_name != "@s-gw/s-gw"
        or package_version != "0.2.0"
        or not isinstance(revision, str)
        or not re.fullmatch(r"[0-9a-f]{40}", revision)
        or not isinstance(tree, str)
        or not re.fullmatch(r"[0-9a-f]{40}", tree)
    ):
        raise ValueError("module signature package identity is invalid")
    return (
        f"{MODULE_SIGNATURE_DOMAIN}\n"
        "schema_version=1\n"
        f"target={target}\n"
        f"package_name={package_name}\n"
        f"package_version={package_version}\n"
        f"upstream_revision={revision}\n"
        f"upstream_tree={tree}\n"
        f"runner_contract_sha256={runner_contract_sha256}\n"
        f"runner_launch_admission_sha256={runner_launch_admission_sha256}\n"
        f"installed_sha256={installed_sha256}\n"
    ).encode("ascii")


def runner_contract_payload() -> bytes:
    canonical = json.dumps(RUNNER_CONTRACT, separators=(",", ":"), sort_keys=True, ensure_ascii=True)
    return f"{RUNNER_CONTRACT_DOMAIN}\n{canonical}\n".encode("ascii")


def runner_contract_sha256() -> str:
    return hashlib.sha256(runner_contract_payload()).hexdigest()


def runner_launch_admission_payload(target: str, admission: object) -> bytes:
    validated = validated_runner_launch_admission(target, admission)
    pe_machine = validated.get("pe_machine", "")
    mitigations = ",".join(validated.get("required_mitigations", []))
    team_id = validated.get("team_id", "")
    signing_id = validated.get("signing_id", "")
    cdhash = validated.get("cdhash", "")
    cs_flags = ",".join(validated.get("required_cs_flags", []))
    return (
        f"{RUNNER_LAUNCH_ADMISSION_DOMAIN}\n"
        "schema_version=1\n"
        f"target={target}\n"
        f"mode={validated['mode']}\n"
        f"signature_scope={validated['signature_scope']}\n"
        f"dependency_policy={validated['dependency_policy']}\n"
        f"pe_machine={pe_machine}\n"
        f"required_mitigations={mitigations}\n"
        f"team_id={team_id}\n"
        f"signing_id={signing_id}\n"
        f"cdhash={cdhash}\n"
        f"required_cs_flags={cs_flags}\n"
    ).encode("ascii")


def runner_launch_admission_sha256(target: str, admission: object) -> str:
    return hashlib.sha256(runner_launch_admission_payload(target, admission)).hexdigest()


def validated_runner_launch_admission(target: str, admission: object) -> dict[str, Any]:
    if target not in TARGETS or not isinstance(admission, dict):
        raise ValueError("native runner launch admission is missing")
    common = {
        "schema_version": 1,
        "signature_scope": "installed-runner-bytes",
        "dependency_policy": "system-only-v1",
    }
    for field, expected in common.items():
        if admission.get(field) != expected:
            raise ValueError(f"native runner launch admission has invalid {field}")

    if target.startswith("linux-"):
        expected = {**common, "mode": "linux-sealed-memfd-v1"}
        if admission != expected:
            raise ValueError("Linux runner launch admission is invalid")
        return dict(admission)

    if target.startswith("win32-"):
        expected = {
            **common,
            "mode": "windows-locked-image-v1",
            "pe_machine": "x86_64" if target.endswith("-x64") else "arm64",
            "required_mitigations": WINDOWS_RUNNER_MITIGATIONS,
        }
        if admission != expected:
            raise ValueError("Windows runner launch admission is invalid")
        return dict(admission)

    expected_fields = {
        *common,
        "mode",
        "team_id",
        "signing_id",
        "cdhash",
        "required_cs_flags",
    }
    if set(admission) != expected_fields or admission.get("mode") != "darwin-running-code-v1":
        raise ValueError("macOS runner launch admission is invalid")
    team_id = admission.get("team_id")
    signing_id = admission.get("signing_id")
    cdhash = admission.get("cdhash")
    if not isinstance(team_id, str) or not re.fullmatch(r"[A-Z0-9]{10}", team_id):
        raise ValueError("macOS runner team ID is invalid")
    if not isinstance(signing_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", signing_id):
        raise ValueError("macOS runner signing ID is invalid")
    if not isinstance(cdhash, str) or not re.fullmatch(r"[0-9a-f]{40}", cdhash):
        raise ValueError("macOS runner CDHash is invalid")
    if admission.get("required_cs_flags") != MACOS_RUNNER_CS_FLAGS:
        raise ValueError("macOS runner code-signing flags are invalid")
    return dict(admission)


def component_signing_key(runtime: dict[str, Any]) -> tuple[Any | None, str | None]:
    policy = runtime.get("signature_policy")
    if not isinstance(policy, dict) or set(policy) != {"algorithm", "public_key", "public_key_sha256"}:
        raise ValueError("component signature policy is invalid")
    if policy.get("algorithm") != COMPONENT_SIGNATURE_ALGORITHM:
        raise ValueError("component signature algorithm is invalid")
    public_pem = policy.get("public_key")
    fingerprint = policy.get("public_key_sha256")
    approved = runtime.get("redistribution_status") == "approved"
    if not approved:
        if public_pem is not None or fingerprint is not None:
            raise ValueError("unapproved component signature policy must not carry a trust anchor")
        return None, None
    if (
        not isinstance(public_pem, str)
        or not public_pem
        or len(public_pem.encode("ascii", errors="ignore")) > MAX_SIGNING_KEY_BYTES
        or not isinstance(fingerprint, str)
        or not SHA256_RE.fullmatch(fingerprint)
    ):
        raise ValueError("approved component signature policy lacks its trust anchor")
    try:
        encoded = public_pem.encode("ascii", errors="strict")
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public_key = serialization.load_pem_public_key(encoded)
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("component signing key is not Ed25519")
        canonical = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except ImportError as exc:
        raise RuntimeError("cryptography is required to verify approved s-gw components") from exc
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("component signing key is invalid") from exc
    if encoded != canonical or hashlib.sha256(canonical).hexdigest() != fingerprint:
        raise ValueError("component signing key does not match its reviewed fingerprint")
    return public_key, fingerprint


def validated_runner_contract(runtime: dict[str, Any]) -> dict[str, Any]:
    contract = runtime.get("runner_contract")
    if contract != RUNNER_CONTRACT:
        raise ValueError("native s-gw runner contract is invalid")
    return contract


def verify_component_signature(
    public_key: Any,
    signature: object,
    *,
    target: str,
    component: str,
    destination: str,
    artifact_sha256: str,
    installed_sha256: str,
) -> None:
    payload = component_signature_payload(
        target,
        component,
        destination,
        artifact_sha256,
        installed_sha256,
    )
    verify_ed25519_signature(public_key, signature, payload)


def verify_module_signature(
    public_key: Any,
    signature: object,
    *,
    target: str,
    manifest: dict[str, Any],
    installed_sha256: str,
    runner_launch_admission_sha256: str,
    runner_contract_sha256: str,
) -> None:
    payload = module_signature_payload(
        target,
        manifest,
        installed_sha256,
        runner_launch_admission_sha256,
        runner_contract_sha256,
    )
    verify_ed25519_signature(public_key, signature, payload)


def verify_ed25519_signature(public_key: Any, signature: object, payload: bytes) -> None:
    if not isinstance(signature, str) or not signature:
        raise ValueError("Ed25519 signature is missing")
    try:
        raw_signature = base64.b64decode(signature, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Ed25519 signature is not strict base64") from exc
    if len(raw_signature) != 64 or base64.b64encode(raw_signature).decode("ascii") != signature:
        raise ValueError("signature has an invalid Ed25519 encoding")
    try:
        from cryptography.exceptions import InvalidSignature

        public_key.verify(raw_signature, payload)
    except ImportError as exc:
        raise RuntimeError("cryptography is required to verify approved s-gw components") from exc
    except InvalidSignature as exc:
        raise ValueError("Ed25519 signature verification failed") from exc


def expected_component_contract(target: str) -> dict[str, dict[str, object]]:
    extension = ".exe" if target.startswith("win32-") else ""
    runner_name = f"s-gw-core{extension}"
    if target.startswith("darwin-"):
        helper_name = "s-gw-keychain-helper"
        helper_destination = f"dist/native/{target}/{helper_name}"
        helper_executable = True
    elif target.startswith("linux-"):
        helper_name = "s-gw-secret-service-helper"
        helper_destination = f"dist/native/{target}/{helper_name}"
        helper_executable = True
    else:
        helper_name = "s-gw-credential.ps1"
        helper_destination = "dist/windows/s-gw-credential.ps1"
        helper_executable = False
    return {
        "runner": {
            "filename": runner_name,
            "destination": f"dist/native/{target}/{runner_name}",
            "format": "file",
            "executable": True,
        },
        "credential_helper": {
            "filename": helper_name,
            "destination": helper_destination,
            "format": "file",
            "executable": helper_executable,
        },
        "approval_ui": {
            "filename": "s-gw-console-ui.tar.gz",
            "destination": "dist/console-ui",
            "format": "tar.gz",
            "archive_root": "console-ui",
            "required_files": ["index.html", "capabilities.json"],
            "required_directories": ["assets"],
            "capability_manifest": "capabilities.json",
            "required_capabilities": [
                "defenseclaw.pending-enrollment.v1",
                "defenseclaw.approval-console-session.v1",
            ],
        },
        "license_bundle": {
            "filename": "THIRD_PARTY_LICENSES.txt",
            "destination": "THIRD_PARTY_LICENSES.txt",
            "format": "file",
            "executable": False,
        },
    }


def safe_relative_path(value: object, *, code: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ModuleError(code, f"unsafe module-relative path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ModuleError(code, f"unsafe module-relative path: {value!r}")
    return path


def parse_version(value: str, *, code: str) -> tuple[int, int, int]:
    match = NODE_VERSION_RE.fullmatch(value.strip())
    if not match:
        raise ModuleError(code, f"invalid Node.js version: {value!r}")
    return tuple(int(part) for part in match.groups())


def run_bounded_output(command: list[str], *, timeout: int, max_bytes: int) -> tuple[int, bytes, bool]:
    read_descriptor, write_descriptor = os.pipe()
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=write_descriptor,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
    except OSError:
        os.close(read_descriptor)
        os.close(write_descriptor)
        raise
    os.close(write_descriptor)
    try:
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise
        try:
            os.set_blocking(read_descriptor, False)
        except AttributeError:
            pass
        try:
            output = os.read(read_descriptor, max_bytes + 1)
        except BlockingIOError:
            output = b""
        return process.returncode, output[:max_bytes], len(output) > max_bytes
    finally:
        os.close(read_descriptor)


def native_target() -> str:
    system = platform.system().lower()
    if system == "darwin":
        os_name = "darwin"
    elif system == "linux":
        os_name = "linux"
    elif system == "windows":
        os_name = "win32"
    else:
        raise ModuleError("platform_unsupported", f"unsupported operating system: {platform.system()}")
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64", "x64"}:
        arch = "x64"
    elif machine in {"arm64", "aarch64"}:
        arch = "arm64"
    else:
        raise ModuleError("platform_unsupported", f"unsupported architecture: {platform.machine()}")
    target = f"{os_name}-{arch}"
    if target not in TARGETS:
        raise ModuleError("platform_unsupported", f"unsupported s-gw target: {target}")
    return target


def resolve_node(explicit: str | None, minimum: str) -> dict[str, object]:
    candidate = explicit or os.environ.get("DEFENSECLAW_SGW_NODE", "").strip() or shutil.which("node")
    if not candidate:
        return {"path": None, "version": None, "minimum": minimum, "available": False, "supported": False}
    node = Path(candidate).expanduser()
    if not node.is_absolute():
        found = shutil.which(os.fspath(node))
        if not found:
            return {"path": None, "version": None, "minimum": minimum, "available": False, "supported": False}
        node = Path(found)
    try:
        resolved = node.resolve(strict=True)
        returncode, raw_version, overflow = run_bounded_output(
            [os.fspath(resolved), "--version"],
            timeout=5,
            max_bytes=MAX_NODE_VERSION_OUTPUT_BYTES,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"path": os.fspath(node), "version": None, "minimum": minimum, "available": False, "supported": False}
    try:
        version = raw_version.decode("ascii", errors="strict").strip() if returncode == 0 and not overflow else ""
    except UnicodeDecodeError:
        version = ""
    try:
        supported = parse_version(version, code="node_unsupported") >= parse_version(minimum, code="manifest_invalid")
    except ModuleError:
        supported = False
    return {
        "path": os.fspath(resolved),
        "version": version.removeprefix("v") or None,
        "minimum": minimum,
        "available": returncode == 0 and bool(version),
        "supported": supported,
    }


def runner_manifest_path(module_path: Path, manifest: dict[str, Any]) -> Path:
    configured = os.environ.get("DEFENSECLAW_SGW_RUNNER_MANIFEST", "").strip()
    if configured:
        return Path(configured).expanduser()
    adjacent = module_path.with_name(Path(manifest["runner_manifest"]).name)
    if adjacent.is_file():
        return adjacent
    candidate = Path(manifest["runner_manifest"])
    if candidate.is_absolute():
        return candidate
    source_root = Path(__file__).resolve().parents[1]
    return source_root / candidate


def runtime_manifest(module_path: Path, manifest: dict[str, Any], target: str) -> tuple[dict[str, Any], dict[str, Any]]:
    path = runner_manifest_path(module_path, manifest)
    runtime = read_json(path, "runner_manifest_invalid")
    if runtime.get("schema_version") != SCHEMA_VERSION:
        raise ModuleError("runner_manifest_invalid", "unsupported s-gw runner manifest schema")
    targets = runtime.get("targets")
    record = targets.get(target) if isinstance(targets, dict) else None
    if not isinstance(record, dict):
        raise ModuleError("runner_manifest_invalid", f"runtime manifest lacks target {target}")
    return runtime, record


def component_records(
    module_path: Path,
    manifest: dict[str, Any],
    target: str,
    *,
    require_approved: bool,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    runtime, target_record = runtime_manifest(module_path, manifest, target)
    targets = runtime.get("targets")
    if (
        set(runtime) != RUNTIME_MANIFEST_FIELDS
        or runtime.get("component") != "s-gw production runtime"
        or runtime.get("license") != "LicenseRef-s-gw-Core"
        or runtime.get("redistribution_status") not in {"approved", "not_approved"}
        or runtime.get("required_for_production") is not True
        or not isinstance(targets, dict)
        or set(targets) != set(TARGETS)
    ):
        raise ModuleError("runner_manifest_invalid", "s-gw runtime manifest has an invalid production contract")
    approved = runtime.get("redistribution_status") == "approved"
    try:
        signing_key, fingerprint = component_signing_key(runtime)
        validated_runner_contract(runtime)
    except (RuntimeError, ValueError) as exc:
        raise ModuleError("runner_manifest_invalid", str(exc)) from exc
    if set(target_record) != {
        "components",
        "runner_launch_admission",
        "module_installed_sha256",
        "module_signature",
    }:
        raise ModuleError("runner_manifest_invalid", f"runtime target metadata is invalid for {target}")
    launch_admission = target_record.get("runner_launch_admission")
    launch_admission_sha256: str | None = None
    if approved:
        if launch_admission is not None:
            try:
                launch_admission = validated_runner_launch_admission(target, launch_admission)
                launch_admission_sha256 = runner_launch_admission_sha256(target, launch_admission)
            except ValueError as exc:
                raise ModuleError(
                    "runner_manifest_invalid",
                    f"runtime runner launch admission is invalid for {target}",
                ) from exc
    elif launch_admission is not None:
        raise ModuleError(
            "runner_manifest_invalid",
            f"unapproved runtime target carries runner launch admission for {target}",
        )
    module_installed_sha256 = target_record.get("module_installed_sha256")
    module_signature = target_record.get("module_signature")
    if module_installed_sha256 is not None and (
        not isinstance(module_installed_sha256, str) or not SHA256_RE.fullmatch(module_installed_sha256)
    ):
        raise ModuleError("runner_manifest_invalid", f"runtime module installed digest is invalid for {target}")
    if not approved and (module_installed_sha256 is not None or module_signature is not None):
        raise ModuleError("runner_manifest_invalid", f"unapproved runtime target carries signed metadata for {target}")
    module_available = (
        approved
        and launch_admission is not None
        and isinstance(launch_admission_sha256, str)
        and isinstance(module_installed_sha256, str)
        and bool(SHA256_RE.fullmatch(module_installed_sha256))
        and isinstance(module_signature, str)
        and bool(module_signature)
    )
    if module_available:
        assert signing_key is not None
        try:
            verify_module_signature(
                signing_key,
                module_signature,
                target=target,
                manifest=manifest,
                installed_sha256=module_installed_sha256,
                runner_launch_admission_sha256=launch_admission_sha256,
                runner_contract_sha256=runner_contract_sha256(),
            )
        except (RuntimeError, ValueError) as exc:
            raise ModuleError("runner_manifest_invalid", f"runtime module signature is invalid for {target}") from exc
    records = target_record.get("components")
    names = production_components(manifest)
    if not isinstance(records, dict) or set(records) != set(names):
        raise ModuleError("runner_manifest_invalid", f"runtime manifest has an incomplete component set for {target}")
    parsed: dict[str, dict[str, Any]] = {}
    missing: list[str] = []
    if not module_available:
        missing.append("module_signature")
    if approved and launch_admission is None:
        missing.append("runner_launch_admission")
    for name in names:
        item = records[name]
        if not isinstance(item, dict):
            raise ModuleError("runner_manifest_invalid", f"runtime component {name} must be an object")
        expected = expected_component_contract(target)[name]
        if set(item) != {*expected, "path", "sha256", "installed_sha256", "signature"}:
            raise ModuleError(
                "runner_manifest_invalid",
                f"runtime component {name} has unexpected fields for {target}",
            )
        for field, value in expected.items():
            if item.get(field) != value:
                raise ModuleError(
                    "runner_manifest_invalid",
                    f"runtime component {name} has invalid {field} for {target}",
                )
        source_path = item.get("path")
        if source_path is not None and (not isinstance(source_path, str) or not source_path):
            raise ModuleError("runner_manifest_invalid", f"runtime component {name} has an invalid source path")
        safe_relative_path(item.get("destination"), code="runner_manifest_invalid")
        if item.get("format") not in {"file", "tar.gz"}:
            raise ModuleError("runner_manifest_invalid", f"runtime component {name} has an invalid format")
        installed_sha256 = item.get("installed_sha256")
        signature = item.get("signature")
        if installed_sha256 is not None and (
            not isinstance(installed_sha256, str) or not SHA256_RE.fullmatch(installed_sha256)
        ):
            raise ModuleError("runner_manifest_invalid", f"runtime component {name} has an invalid installed digest")
        if not approved and (installed_sha256 is not None or signature is not None):
            raise ModuleError(
                "runner_manifest_invalid",
                f"unapproved runtime component {name} carries signed release metadata",
            )
        available = (
            approved
            and isinstance(item.get("filename"), str)
            and bool(item["filename"])
            and isinstance(item.get("sha256"), str)
            and bool(SHA256_RE.fullmatch(item["sha256"]))
            and isinstance(installed_sha256, str)
            and bool(SHA256_RE.fullmatch(installed_sha256))
            and isinstance(signature, str)
            and bool(signature)
        )
        if not available:
            missing.append(name)
        else:
            assert signing_key is not None
            try:
                verify_component_signature(
                    signing_key,
                    signature,
                    target=target,
                    component=name,
                    destination=str(item["destination"]),
                    artifact_sha256=str(item["sha256"]),
                    installed_sha256=installed_sha256,
                )
            except (RuntimeError, ValueError) as exc:
                raise ModuleError(
                    "runner_manifest_invalid",
                    f"runtime component {name} signature is invalid",
                ) from exc
        parsed[name] = {
            **item,
            "_public_key_sha256": fingerprint,
            "_module_installed_sha256": module_installed_sha256,
            "_module_signature": module_signature,
            "_runner_launch_admission": launch_admission,
            "_runner_launch_admission_sha256": launch_admission_sha256,
        }
    if require_approved and missing:
        joined = ", ".join(missing)
        raise ModuleError(
            "runner_unavailable",
            f"approved s-gw runtime components are unavailable for {target}: {joined}",
        )
    return runtime, parsed


def runtime_probe(
    module_path: Path,
    manifest: dict[str, Any],
    target: str,
) -> tuple[dict[str, object], dict[str, object]]:
    runtime, records = component_records(module_path, manifest, target, require_approved=False)
    approved = runtime.get("redistribution_status") == "approved"
    components: dict[str, object] = {}
    all_available = approved
    for name, item in records.items():
        available = (
            approved
            and isinstance(item.get("sha256"), str)
            and bool(SHA256_RE.fullmatch(item["sha256"]))
            and isinstance(item.get("installed_sha256"), str)
            and bool(SHA256_RE.fullmatch(item["installed_sha256"]))
            and isinstance(item.get("signature"), str)
            and bool(item["signature"])
            and isinstance(item.get("_module_installed_sha256"), str)
            and bool(SHA256_RE.fullmatch(item["_module_installed_sha256"]))
            and isinstance(item.get("_module_signature"), str)
            and bool(item["_module_signature"])
            and isinstance(item.get("_runner_launch_admission"), dict)
            and isinstance(item.get("_runner_launch_admission_sha256"), str)
            and bool(SHA256_RE.fullmatch(item["_runner_launch_admission_sha256"]))
        )
        all_available = all_available and available
        components[name] = {
            "required": True,
            "available": available,
            "redistribution_status": runtime.get("redistribution_status"),
        }
    runner = {
        "target": target,
        "required": bool(runtime.get("required_for_production", True)),
        "available": all_available,
        "redistribution_status": runtime.get("redistribution_status"),
    }
    return runner, components


def approved_component_records(module_path: Path, manifest: dict[str, Any], target: str) -> dict[str, dict[str, Any]]:
    _runtime, records = component_records(module_path, manifest, target, require_approved=True)
    return records


def module_home(home: Path, manifest: dict[str, Any]) -> Path:
    install = manifest.get("install")
    if not isinstance(install, dict):
        raise ModuleError("manifest_invalid", "s-gw module install contract is invalid")
    relative = safe_relative_path(install.get("module_directory"), code="manifest_invalid")
    return home.joinpath(*relative.parts)


def receipt_path(home: Path, manifest: dict[str, Any]) -> Path:
    install = manifest.get("install")
    assert isinstance(install, dict)
    relative = safe_relative_path(install.get("receipt"), code="manifest_invalid")
    return home.joinpath(*relative.parts)


def ensure_private_receipt(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ModuleError("not_installed", f"s-gw receipt is unavailable: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ModuleError("receipt_invalid", "s-gw receipt must be a regular file")
    if os.name == "nt":
        windows_private_acl(path, operation="verify", recursive=False, code="receipt_invalid")
        return
    if metadata.st_uid != os.geteuid():
        raise ModuleError("receipt_invalid", "s-gw receipt is not owned by the current user")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ModuleError("receipt_invalid", "s-gw receipt is accessible by another user")


def checked_installed_path(value: object, root: Path, *, code: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ModuleError(code, "s-gw receipt contains an invalid path")
    try:
        resolved = Path(value).resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise ModuleError(code, "s-gw receipt path escapes the managed module directory") from exc
    return resolved


def artifact_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ModuleError("artifact_invalid", f"could not read s-gw module artifact: {exc}") from exc
    return digest.hexdigest()


def package_file_inventory(package_root: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    total = 0
    if os.name == "nt":
        windows_private_acl(package_root, operation="verify", recursive=True, code="artifact_invalid")
    check_private_item(package_root, package_root)
    for item in sorted(package_root.rglob("*"), key=lambda path: path.relative_to(package_root).as_posix()):
        relative = item.relative_to(package_root).as_posix()
        if item.is_symlink() or (not item.is_dir() and not item.is_file()):
            raise ModuleError("artifact_invalid", f"s-gw module contains an unsafe entry: {relative}")
        check_private_item(item, package_root)
        if item.is_dir():
            continue
        size = item.stat().st_size
        if size > MAX_ARCHIVE_FILE_BYTES:
            raise ModuleError("artifact_invalid", f"s-gw module contains an oversized file: {relative}")
        total += size
        if len(files) >= MAX_ARCHIVE_FILES or total > MAX_ARCHIVE_TOTAL_BYTES:
            raise ModuleError("artifact_invalid", "s-gw module exceeds its file inventory limits")
        files[relative] = artifact_sha256(item)
    if not files:
        raise ModuleError("artifact_invalid", "s-gw module file inventory is empty")
    return files


def check_private_item(item: Path, package_root: Path) -> None:
    if os.name == "nt":
        return
    try:
        metadata = item.lstat()
    except OSError as exc:
        raise ModuleError("artifact_invalid", f"could not inspect s-gw module path: {item}") from exc
    if metadata.st_uid != os.geteuid():
        raise ModuleError("artifact_invalid", "s-gw module is not owned by the current user")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        relative = item.relative_to(package_root).as_posix() if item != package_root else "."
        raise ModuleError("artifact_invalid", f"s-gw module path is accessible by another user: {relative}")


def extract_module_artifact(artifact: Path, destination: Path) -> Path:
    try:
        archive = tarfile.open(artifact, mode="r:gz")
    except (OSError, tarfile.TarError) as exc:
        raise ModuleError("artifact_invalid", f"could not open s-gw module artifact: {exc}") from exc
    names: set[str] = set()
    total = 0
    with archive:
        members = archive.getmembers()
        if not members or len(members) > MAX_ARCHIVE_FILES:
            raise ModuleError("artifact_invalid", "s-gw module artifact has an invalid file count")
        for member in members:
            if "\\" in member.name or "\x00" in member.name:
                raise ModuleError("artifact_invalid", f"unsafe s-gw module artifact path: {member.name!r}")
            pure = PurePosixPath(member.name)
            if (
                pure.is_absolute()
                or not pure.parts
                or pure.parts[0] != "package"
                or any(part in {"", ".", ".."} for part in pure.parts)
            ):
                raise ModuleError("artifact_invalid", f"unsafe s-gw module artifact path: {member.name!r}")
            normalized = pure.as_posix()
            if normalized in names:
                raise ModuleError("artifact_invalid", f"duplicate s-gw module artifact path: {normalized}")
            names.add(normalized)
            if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                raise ModuleError("artifact_invalid", f"unsupported s-gw module artifact entry: {normalized}")
            if member.size < 0 or member.size > MAX_ARCHIVE_FILE_BYTES:
                raise ModuleError("artifact_invalid", f"oversized s-gw module artifact entry: {normalized}")
            total += member.size
            if total > MAX_ARCHIVE_TOTAL_BYTES:
                raise ModuleError("artifact_invalid", "s-gw module artifact exceeds its expanded-size limit")

        for member in members:
            pure = PurePosixPath(member.name)
            output = destination.joinpath(*pure.parts)
            if member.isdir():
                output.mkdir(parents=True, exist_ok=True, mode=0o700)
                if os.name != "nt":
                    output.chmod(0o700)
                continue
            output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            source = archive.extractfile(member)
            if source is None:
                raise ModuleError("artifact_invalid", f"could not read s-gw module entry: {member.name}")
            try:
                with output.open("xb") as target_file:
                    shutil.copyfileobj(source, target_file, length=1024 * 1024)
                    target_file.flush()
                    os.fsync(target_file.fileno())
            finally:
                source.close()
            if output.stat().st_size != member.size:
                raise ModuleError("artifact_invalid", f"short s-gw module entry: {member.name}")
            if os.name != "nt":
                output.chmod(0o700 if member.mode & 0o111 else 0o600)
    package_root = destination / "package"
    if package_root.is_symlink() or not package_root.is_dir():
        raise ModuleError("artifact_invalid", "s-gw module artifact lacks its package root")
    return package_root


def verified_module_metadata(
    package_root: Path,
    manifest: dict[str, Any],
    target: str,
    approved_components: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, str]]:
    metadata = read_json(package_root / MODULE_METADATA_FILE, "artifact_invalid")
    expected_metadata_fields = {
        "schema_version",
        "package_name",
        "package_version",
        "upstream_revision",
        "upstream_tree",
        "minimum_node_version",
        "build_toolchain",
        "target",
        "production_ready",
        "inventory_excludes",
        "signature_policy",
        "runner_contract",
        "runner_contract_sha256",
        "runner_launch_admission",
        "runner_launch_admission_sha256",
        "module_installed_sha256",
        "module_signature",
        "components",
        "runner",
        "files",
    }
    if set(metadata) != expected_metadata_fields:
        raise ModuleError("artifact_invalid", "s-gw module metadata has unexpected fields")
    expected = {
        "schema_version": SCHEMA_VERSION,
        "package_name": manifest["package_name"],
        "package_version": manifest["package_version"],
        "upstream_revision": manifest["upstream_revision"],
        "upstream_tree": manifest["upstream_tree"],
        "minimum_node_version": manifest["minimum_node_version"],
        "build_toolchain": manifest["build_toolchain"],
        "target": target,
        "production_ready": True,
    }
    for field, value in expected.items():
        if metadata.get(field) != value:
            raise ModuleError("artifact_invalid", f"s-gw module metadata has invalid {field}")
    if metadata.get("inventory_excludes") != [MODULE_METADATA_FILE]:
        raise ModuleError("artifact_invalid", "s-gw module metadata has an invalid inventory exclusion")
    release_proof = approved_components["runner"]
    expected_signature_policy = {
        "algorithm": COMPONENT_SIGNATURE_ALGORITHM,
        "public_key_sha256": release_proof.get("_public_key_sha256"),
    }
    if metadata.get("signature_policy") != expected_signature_policy:
        raise ModuleError("artifact_invalid", "s-gw module signing policy does not match the reviewed release")
    if metadata.get("runner_contract") != RUNNER_CONTRACT:
        raise ModuleError("artifact_invalid", "s-gw native runner contract is invalid")
    if metadata.get("runner_contract_sha256") != runner_contract_sha256():
        raise ModuleError("artifact_invalid", "s-gw native runner contract digest is invalid")
    if metadata.get("runner_launch_admission") != release_proof.get("_runner_launch_admission") or metadata.get(
        "runner_launch_admission_sha256"
    ) != release_proof.get("_runner_launch_admission_sha256"):
        raise ModuleError("artifact_invalid", "s-gw runner launch admission does not match the reviewed release")
    try:
        observed_admission_sha256 = runner_launch_admission_sha256(
            target,
            metadata.get("runner_launch_admission"),
        )
    except ValueError as exc:
        raise ModuleError("artifact_invalid", "s-gw runner launch admission is invalid") from exc
    if observed_admission_sha256 != metadata.get("runner_launch_admission_sha256"):
        raise ModuleError("artifact_invalid", "s-gw runner launch admission digest is invalid")
    files = metadata.get("files")
    if not isinstance(files, dict) or not files:
        raise ModuleError("artifact_invalid", "s-gw module metadata lacks its file inventory")
    required = {
        "package.json",
        manifest["entrypoints"]["cli"],
        manifest["entrypoints"]["mcp"],
    }
    if not required.issubset(files):
        raise ModuleError("artifact_invalid", "s-gw module file inventory is incomplete")
    for relative, digest in files.items():
        safe_relative_path(relative, code="artifact_invalid")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ModuleError("artifact_invalid", f"invalid s-gw module digest for {relative}")
    try:
        module_installed_sha256 = module_inventory_sha256(files)
    except ValueError as exc:
        raise ModuleError("artifact_invalid", "s-gw installed module inventory is invalid") from exc
    if (
        metadata.get("module_installed_sha256") != module_installed_sha256
        or module_installed_sha256 != release_proof.get("_module_installed_sha256")
        or metadata.get("module_signature") != release_proof.get("_module_signature")
    ):
        raise ModuleError("artifact_invalid", "s-gw installed module inventory is not signed by the reviewed release")
    full_inventory = package_file_inventory(package_root)
    metadata_digest = full_inventory.pop(MODULE_METADATA_FILE, None)
    if metadata_digest is None or files != full_inventory:
        raise ModuleError("artifact_invalid", "s-gw module file inventory does not match the package")
    full_inventory[MODULE_METADATA_FILE] = metadata_digest
    full_inventory = dict(sorted(full_inventory.items()))

    components = metadata.get("components")
    if not isinstance(components, dict) or set(components) != set(production_components(manifest)):
        raise ModuleError("artifact_invalid", "s-gw module metadata lacks its production components")
    for name, approved in approved_components.items():
        component = components.get(name)
        if not isinstance(component, dict):
            raise ModuleError("artifact_invalid", f"s-gw module metadata lacks {name}")
        if set(component) != {"artifact_sha256", "installed_sha256", "signature", "destination", "files"}:
            raise ModuleError("artifact_invalid", f"s-gw module {name} metadata has unexpected fields")
        if (
            component.get("artifact_sha256") != approved["sha256"]
            or component.get("installed_sha256") != approved["installed_sha256"]
            or component.get("signature") != approved["signature"]
            or component.get("destination") != approved["destination"]
        ):
            raise ModuleError("artifact_invalid", f"s-gw module {name} does not match approved release metadata")
        component_files = checked_component_files(component.get("files"), files, code="artifact_invalid")
        try:
            installed_sha256 = component_inventory_sha256({relative: files[relative] for relative in component_files})
        except ValueError as exc:
            raise ModuleError("artifact_invalid", f"s-gw module {name} installed inventory is invalid") from exc
        if installed_sha256 != component.get("installed_sha256"):
            raise ModuleError("artifact_invalid", f"s-gw module {name} installed digest is invalid")
        destination = safe_relative_path(approved["destination"], code="runner_manifest_invalid")
        if approved["format"] == "file":
            if component_files != {destination.as_posix()}:
                raise ModuleError("artifact_invalid", f"s-gw module {name} file inventory is invalid")
            if files[destination.as_posix()] != approved["sha256"]:
                raise ModuleError("artifact_invalid", f"s-gw module {name} digest is invalid")
            installed_component = package_root.joinpath(*destination.parts)
            if os.name != "nt" and approved.get("executable") is True:
                if stat.S_IMODE(installed_component.stat().st_mode) & 0o100 == 0:
                    raise ModuleError("artifact_invalid", f"s-gw module {name} is not executable")
        else:
            verify_directory_component(package_root, destination, component_files, approved)

    runner = metadata.get("runner")
    runner_component = components["runner"]
    assert isinstance(runner_component, dict)
    runner_files = runner_component["files"]
    if (
        not isinstance(runner, dict)
        or set(runner) != {"path", "sha256", "signature"}
        or not isinstance(runner_files, list)
        or len(runner_files) != 1
    ):
        raise ModuleError("artifact_invalid", "s-gw module metadata lacks its runner")
    runner_path = safe_relative_path(runner.get("path"), code="artifact_invalid")
    runner_digest = runner.get("sha256")
    if (
        runner_path.as_posix() != runner_files[0]
        or runner_digest != files.get(runner_path.as_posix())
        or runner.get("signature") != runner_component.get("signature")
    ):
        raise ModuleError("artifact_invalid", "s-gw module runner compatibility metadata is invalid")
    package = read_json(package_root / "package.json", "artifact_invalid")
    if package.get("name") != manifest["package_name"] or package.get("version") != manifest["package_version"]:
        raise ModuleError("artifact_invalid", "s-gw module package identity is invalid")
    return metadata, full_inventory


def checked_component_files(value: object, files: dict[str, Any], *, code: str) -> set[str]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
        raise ModuleError(code, "s-gw component has an invalid file inventory")
    result: set[str] = set()
    for relative in value:
        normalized = safe_relative_path(relative, code=code).as_posix()
        if normalized in result or normalized not in files:
            raise ModuleError(code, "s-gw component file inventory is incomplete or duplicated")
        result.add(normalized)
    return result


def verify_directory_component(
    package_root: Path,
    destination: PurePosixPath,
    component_files: set[str],
    approved: dict[str, Any],
) -> None:
    root = package_root.joinpath(*destination.parts)
    if root.is_symlink() or not root.is_dir():
        raise ModuleError("artifact_invalid", "s-gw approval UI directory is missing")
    actual: set[str] = set()
    for item in root.rglob("*"):
        if item.is_symlink() or (not item.is_dir() and not item.is_file()):
            raise ModuleError("artifact_invalid", "s-gw approval UI contains an unsafe entry")
        if item.is_file():
            actual.add(item.relative_to(package_root).as_posix())
    if actual != component_files:
        raise ModuleError("artifact_invalid", "s-gw approval UI file inventory is incomplete")
    for raw in approved.get("required_files", []):
        relative = safe_relative_path(raw, code="runner_manifest_invalid")
        item = root.joinpath(*relative.parts)
        if not item.is_file() or item.stat().st_size == 0:
            raise ModuleError("artifact_invalid", f"s-gw approval UI lacks required file: {relative}")
    for raw in approved.get("required_directories", []):
        relative = safe_relative_path(raw, code="runner_manifest_invalid")
        item = root.joinpath(*relative.parts)
        if not item.is_dir() or not any(candidate.is_file() for candidate in item.rglob("*")):
            raise ModuleError("artifact_invalid", f"s-gw approval UI lacks required assets: {relative}")
    capability_path = safe_relative_path(approved.get("capability_manifest"), code="runner_manifest_invalid")
    capability_manifest = read_json(root.joinpath(*capability_path.parts), "artifact_invalid")
    if set(capability_manifest) != {"schema_version", "capabilities"} or capability_manifest.get("schema_version") != 1:
        raise ModuleError("artifact_invalid", "s-gw approval UI capability manifest is invalid")
    capabilities = capability_manifest.get("capabilities")
    required = approved.get("required_capabilities")
    if (
        not isinstance(capabilities, list)
        or not capabilities
        or not all(isinstance(item, str) and item for item in capabilities)
        or len(capabilities) != len(set(capabilities))
        or not isinstance(required, list)
        or not set(required).issubset(capabilities)
    ):
        raise ModuleError("artifact_invalid", "s-gw approval UI lacks its required enrollment capability")


def private_tree(root: Path) -> None:
    for item in sorted(root.rglob("*"), reverse=True):
        if item.is_symlink():
            raise ModuleError("artifact_invalid", "s-gw module contains a symbolic link")
        if os.name == "nt":
            continue
        item.chmod(0o700 if item.is_dir() or item.stat().st_mode & 0o111 else 0o600)
    if os.name == "nt":
        windows_private_acl(root, operation="apply", recursive=True, code="artifact_invalid")
        return
    root.chmod(0o700)


def write_receipt(path: Path, receipt: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise ModuleError("install_failed", "s-gw receipt directory is unsafe")
    if os.name == "nt":
        windows_private_acl(path.parent, operation="apply", recursive=False, code="install_failed")
    else:
        path.parent.chmod(0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    payload = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")
    try:
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise ModuleError("install_failed", "s-gw receipt write did not progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if os.name == "nt":
            windows_private_acl(temporary, operation="apply", recursive=False, code="install_failed")
        os.replace(temporary, path)
        if os.name != "nt":
            path.chmod(0o600)
        sync_directory(path.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def sync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def windows_private_acl(
    path: Path,
    *,
    operation: str,
    recursive: bool,
    code: str,
) -> None:
    if operation not in {"apply", "verify"}:
        raise ValueError(f"unsupported Windows ACL operation: {operation}")
    powershell = trusted_windows_powershell(code=code)
    try:
        resolved = path.resolve(strict=True)
        child_env = os.environ.copy()
        child_env.update(
            {
                "DEFENSECLAW_SGW_ACL_OPERATION": operation,
                "DEFENSECLAW_SGW_ACL_SCOPE": "recursive" if recursive else "single",
                "DEFENSECLAW_SGW_ACL_ROOT": os.fspath(resolved),
            }
        )
        result = subprocess.run(
            [
                powershell,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                _WINDOWS_PRIVATE_ACL_SCRIPT,
            ],
            check=False,
            env=child_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=300 if recursive else 30,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ModuleError(code, "could not validate the private Windows ACL for the managed s-gw runtime") from exc
    if result.returncode != 0:
        raise ModuleError(code, "managed s-gw runtime does not have a private Windows ACL")


def trusted_windows_powershell(*, code: str) -> str:
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_windows_directory = kernel32.GetWindowsDirectoryW
        get_windows_directory.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
        get_windows_directory.restype = ctypes.c_uint
        buffer = ctypes.create_unicode_buffer(32_768)
        length = get_windows_directory(buffer, len(buffer))
    except (AttributeError, OSError) as exc:
        raise ModuleError(code, "could not resolve the trusted Windows PowerShell path") from exc
    if length == 0 or length >= len(buffer):
        raise ModuleError(code, "could not resolve the trusted Windows PowerShell path")
    windows_root = Path(buffer.value)
    candidate = windows_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not windows_root.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts[1:]):
        raise ModuleError(code, "trusted Windows PowerShell path is unsafe")

    current = Path(candidate.anchor)
    try:
        chain = candidate.parts[1:]
        for index, part in enumerate(chain):
            current = current / part
            metadata = current.lstat()
            attributes = getattr(metadata, "st_file_attributes", 0)
            reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            if current.is_symlink() or attributes & reparse_flag:
                raise ModuleError(code, "trusted Windows PowerShell path contains a reparse point")
            is_last = index == len(chain) - 1
            if (is_last and not stat.S_ISREG(metadata.st_mode)) or (not is_last and not stat.S_ISDIR(metadata.st_mode)):
                raise ModuleError(code, "trusted Windows PowerShell path has an invalid entry")
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ModuleError(code, "trusted Windows PowerShell is unavailable") from exc
    if os.path.normcase(os.fspath(resolved)) != os.path.normcase(os.fspath(candidate)):
        raise ModuleError(code, "trusted Windows PowerShell path changed during validation")
    return os.fspath(resolved)


def ensure_private_managed_root(home: Path, managed_root: Path) -> None:
    try:
        relative = managed_root.relative_to(home)
    except ValueError as exc:
        raise ModuleError("install_failed", "managed s-gw module path escapes DefenseClaw home") from exc
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    home_metadata = home.lstat()
    if stat.S_ISLNK(home_metadata.st_mode) or not stat.S_ISDIR(home_metadata.st_mode):
        raise ModuleError("install_failed", "DefenseClaw home is unsafe")
    if os.name == "nt":
        windows_private_acl(home, operation="apply", recursive=False, code="install_failed")
    else:
        if home_metadata.st_uid != os.geteuid():
            raise ModuleError("install_failed", "DefenseClaw home has the wrong owner")
        home.chmod(0o700)
    current = home
    for part in relative.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=0o700)
            metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ModuleError("install_failed", f"managed s-gw directory is unsafe: {current}")
        if os.name == "nt":
            windows_private_acl(current, operation="apply", recursive=False, code="install_failed")
        else:
            if metadata.st_uid != os.geteuid():
                raise ModuleError("install_failed", f"managed s-gw directory has the wrong owner: {current}")
            current.chmod(0o700)


def verify_private_managed_root(home: Path, managed_root: Path) -> None:
    try:
        relative = managed_root.relative_to(home)
    except ValueError as exc:
        raise ModuleError("module_invalid", "managed s-gw module path escapes DefenseClaw home") from exc
    for current in (home, *(home.joinpath(*relative.parts[:index]) for index in range(1, len(relative.parts) + 1))):
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise ModuleError("module_invalid", f"managed s-gw directory is unavailable: {current}") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ModuleError("module_invalid", f"managed s-gw directory is unsafe: {current}")
        if os.name == "nt":
            windows_private_acl(current, operation="verify", recursive=False, code="module_invalid")
        elif metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ModuleError("module_invalid", f"managed s-gw directory is not private: {current}")


def verify_private_directory(path: Path, *, code: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ModuleError(code, f"managed s-gw directory is unavailable: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ModuleError(code, f"managed s-gw directory is unsafe: {path}")
    if os.name == "nt":
        windows_private_acl(path, operation="verify", recursive=False, code=code)
        return
    if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ModuleError(code, f"managed s-gw directory is not private: {path}")


def install_module_generation(package_root: Path, managed_root: Path, module_id: str) -> Path:
    try:
        version_root = Path(tempfile.mkdtemp(prefix=f"{module_id}-g", dir=managed_root))
    except OSError as exc:
        raise ModuleError("install_failed", "could not create a fresh s-gw module generation") from exc
    destination = version_root / "package"
    try:
        if os.name != "nt":
            version_root.chmod(0o700)
        os.replace(package_root, destination)
        if os.name == "nt":
            windows_private_acl(version_root, operation="apply", recursive=True, code="install_failed")
        sync_directory(version_root)
        sync_directory(managed_root)
    except Exception:
        shutil.rmtree(version_root, ignore_errors=True)
        raise
    return destination


def install_module(
    module_path: Path,
    manifest: dict[str, Any],
    home: Path,
    node_arg: str | None,
    target: str,
    artifact: Path,
    expected_sha256: str,
) -> dict[str, object]:
    if not SHA256_RE.fullmatch(expected_sha256):
        raise ModuleError("artifact_invalid", "expected s-gw module SHA-256 must be lowercase hexadecimal")
    node = resolve_node(node_arg, manifest["minimum_node_version"])
    if not node["available"]:
        raise ModuleError("node_missing", "Node.js is required to install the s-gw module")
    if not node["supported"]:
        raise ModuleError("node_unsupported", f"Node.js {manifest['minimum_node_version']} or newer is required")
    approved_components = approved_component_records(module_path, manifest, target)
    if artifact.is_symlink() or not artifact.is_file():
        raise ModuleError("artifact_invalid", "s-gw module artifact must be a regular file")
    actual_sha256 = artifact_sha256(artifact)
    if actual_sha256 != expected_sha256:
        raise ModuleError("artifact_invalid", "s-gw module artifact digest does not match the authenticated release")

    with tempfile.TemporaryDirectory(prefix="defenseclaw-sgw-install-") as temporary:
        extracted = Path(temporary) / "extracted"
        extracted.mkdir(mode=0o700)
        package_root = extract_module_artifact(artifact, extracted)
        private_tree(package_root)
        metadata, full_inventory = verified_module_metadata(package_root, manifest, target, approved_components)

        managed_root = module_home(home, manifest)
        ensure_private_managed_root(home, managed_root)
        module_id = f"{manifest['package_version']}-{manifest['upstream_revision'][:12]}-{target}"
        destination = install_module_generation(package_root, managed_root, module_id)
        # An older generation may still be running or locked, so retirement is a separate lifecycle step.
        components = metadata["components"]
        runner = metadata["runner"]
        assert isinstance(components, dict) and isinstance(runner, dict)
        receipt = {
            "schema_version": SCHEMA_VERSION,
            "package_name": manifest["package_name"],
            "package_version": manifest["package_version"],
            "upstream_revision": manifest["upstream_revision"],
            "upstream_tree": manifest["upstream_tree"],
            "target": target,
            "archive_sha256": actual_sha256,
            "package_root": os.fspath(destination.resolve(strict=True)),
            "node_path": node["path"],
            "node_version": node["version"],
            "build_toolchain": metadata["build_toolchain"],
            "signature_policy": metadata["signature_policy"],
            "runner_contract": metadata["runner_contract"],
            "runner_contract_sha256": metadata["runner_contract_sha256"],
            "runner_launch_admission": metadata["runner_launch_admission"],
            "runner_launch_admission_sha256": metadata["runner_launch_admission_sha256"],
            "module_installed_sha256": metadata["module_installed_sha256"],
            "module_signature": metadata["module_signature"],
            "components": components,
            "runner": {"path": runner["path"], "sha256": runner["sha256"]},
            "files": full_inventory,
            "installed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        write_receipt(receipt_path(home, manifest), receipt)
    return status(module_path, manifest, home, str(node["path"]), target)


def base_result(
    manifest: dict[str, Any],
    node: dict[str, object],
    runner: dict[str, object],
    components: dict[str, object],
) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "node": node,
        "runner": runner,
        "components": components,
        "module": {
            "installed": False,
            "version": manifest["package_version"],
            "revision": manifest["upstream_revision"],
            "path": None,
        },
    }


def probe(module_path: Path, manifest: dict[str, Any], node_arg: str | None, target: str) -> dict[str, object]:
    node = resolve_node(node_arg, manifest["minimum_node_version"])
    runner, components = runtime_probe(module_path, manifest, target)
    result = base_result(manifest, node, runner, components)
    if not node["available"]:
        state = "node_missing"
    elif not node["supported"]:
        state = "node_unsupported"
    elif runner["required"] and not runner["available"]:
        state = "runner_unavailable"
    else:
        state = "ready_to_install"
    result.update({"state": state, "ready": state == "ready_to_install"})
    return result


def status(
    module_path: Path,
    manifest: dict[str, Any],
    home: Path,
    node_arg: str | None,
    target: str,
) -> dict[str, object]:
    path = receipt_path(home, manifest)
    try:
        ensure_private_receipt(path)
        receipt = read_json(path, "receipt_invalid")
    except ModuleError as exc:
        result = probe(module_path, manifest, node_arg, target)
        result.update({"state": exc.code, "ready": False})
        return result
    if receipt.get("schema_version") != SCHEMA_VERSION:
        raise ModuleError("receipt_invalid", "unsupported s-gw receipt schema")
    expected_receipt_fields = {
        "schema_version",
        "package_name",
        "package_version",
        "upstream_revision",
        "upstream_tree",
        "target",
        "archive_sha256",
        "package_root",
        "node_path",
        "node_version",
        "build_toolchain",
        "signature_policy",
        "runner_contract",
        "runner_contract_sha256",
        "runner_launch_admission",
        "runner_launch_admission_sha256",
        "module_installed_sha256",
        "module_signature",
        "components",
        "runner",
        "files",
        "installed_at",
    }
    if set(receipt) != expected_receipt_fields:
        raise ModuleError("receipt_invalid", "s-gw receipt has unexpected fields")
    identity_fields = {
        "package_name": manifest["package_name"],
        "package_version": manifest["package_version"],
        "upstream_revision": manifest["upstream_revision"],
        "upstream_tree": manifest["upstream_tree"],
        "target": target,
    }
    for field, expected in identity_fields.items():
        if receipt.get(field) != expected:
            raise ModuleError("module_invalid", f"installed s-gw {field} does not match the reviewed module")

    managed_root = module_home(home, manifest)
    verify_private_managed_root(home, managed_root)
    package_root = checked_installed_path(receipt.get("package_root"), managed_root, code="module_invalid")
    if package_root.is_symlink() or not package_root.is_dir():
        raise ModuleError("module_invalid", "installed s-gw package root is not a regular directory")
    verify_private_directory(package_root.parent, code="module_invalid")
    approved_components = approved_component_records(module_path, manifest, target)
    metadata, full_inventory = verified_module_metadata(package_root, manifest, target, approved_components)
    signed_receipt_fields = (
        "build_toolchain",
        "signature_policy",
        "runner_contract",
        "runner_contract_sha256",
        "runner_launch_admission",
        "runner_launch_admission_sha256",
        "module_installed_sha256",
        "module_signature",
    )
    if (
        receipt.get("files") != full_inventory
        or receipt.get("components") != metadata.get("components")
        or any(receipt.get(field) != metadata.get(field) for field in signed_receipt_fields)
    ):
        raise ModuleError("module_invalid", "installed s-gw receipt does not match the module inventory")
    runner_receipt = receipt.get("runner")
    module_runner = metadata.get("runner")
    if not isinstance(runner_receipt, dict) or not isinstance(module_runner, dict):
        raise ModuleError("runner_unavailable", "installed s-gw runner receipt is missing")
    expected_runner = {"path": module_runner.get("path"), "sha256": module_runner.get("sha256")}
    if runner_receipt != expected_runner:
        raise ModuleError("runner_unavailable", "installed s-gw runner receipt is invalid")

    chosen_node = node_arg or receipt.get("node_path")
    node = resolve_node(chosen_node if isinstance(chosen_node, str) else None, manifest["minimum_node_version"])
    runner = {
        "target": target,
        "required": True,
        "available": True,
        "redistribution_status": "approved",
    }
    component_status = {
        name: {"required": True, "available": True, "redistribution_status": "approved"}
        for name in production_components(manifest)
    }
    result = base_result(manifest, node, runner, component_status)
    module = result["module"]
    assert isinstance(module, dict)
    module.update({"installed": True, "path": os.fspath(package_root)})
    if not node["available"]:
        state = "node_missing"
    elif not node["supported"]:
        state = "node_unsupported"
    else:
        state = "ready"
    result.update({"state": state, "ready": state == "ready"})
    return result


def command_payload(
    current: dict[str, object],
    manifest: dict[str, Any],
    entrypoint: str,
    arguments: list[str],
) -> dict[str, object]:
    if not current.get("ready"):
        raise ModuleError(str(current.get("state", "module_unavailable")), "s-gw module is not ready")
    module = current["module"]
    node = current["node"]
    assert isinstance(module, dict) and isinstance(node, dict)
    package_root = Path(str(module["path"]))
    relative = safe_relative_path(manifest["entrypoints"][entrypoint], code="manifest_invalid")
    executable = package_root.joinpath(*relative.parts).resolve(strict=True)
    return {
        "schema_version": SCHEMA_VERSION,
        "argv": [str(node["path"]), os.fspath(executable), *arguments],
        "cwd": os.fspath(package_root),
        "env": {
            "SGW_AGENT_NAME": "DefenseClaw",
            "SGW_DISABLE_UPDATE_CHECK": "1",
            "SGW_EXECUTION_ENGINE": "rust",
        },
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=default_manifest_path())
    parser.add_argument(
        "--home",
        type=Path,
        default=Path(os.environ.get("DEFENSECLAW_HOME", "~/.defenseclaw")).expanduser(),
    )
    parser.add_argument("--node")
    parser.add_argument("--target", choices=TARGETS, default=None)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("probe")
    subparsers.add_parser("status")
    install_parser = subparsers.add_parser("install")
    install_parser.add_argument("--artifact", required=True, type=Path)
    install_parser.add_argument("--sha256", required=True)
    command_parser = subparsers.add_parser("command")
    command_parser.add_argument("--entrypoint", choices=("cli", "mcp"), required=True)
    command_parser.add_argument("arguments", nargs=argparse.REMAINDER)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(sys.argv[1:] if argv is None else argv)
        manifest_path = args.manifest.expanduser().resolve(strict=True)
        manifest = load_manifest(manifest_path)
        target = args.target or native_target()
        home = args.home.expanduser().resolve()
        if args.command == "probe":
            payload = probe(manifest_path, manifest, args.node, target)
        elif args.command == "install":
            payload = install_module(
                manifest_path,
                manifest,
                home,
                args.node,
                target,
                args.artifact.expanduser().resolve(strict=True),
                args.sha256,
            )
        else:
            current = status(manifest_path, manifest, home, args.node, target)
            if args.command == "status":
                payload = current
            else:
                command_args = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
                payload = command_payload(current, manifest, args.entrypoint, command_args)
        emit(payload)
        return 0
    except ModuleError as exc:
        emit(
            {
                "schema_version": SCHEMA_VERSION,
                "state": "error",
                "error": {"code": exc.code, "message": str(exc)},
            },
            stream=sys.stderr,
        )
        return 1
    except (OSError, ValueError) as exc:
        emit(
            {
                "schema_version": SCHEMA_VERSION,
                "state": "error",
                "error": {"code": "runtime_error", "message": str(exc)},
            },
            stream=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
