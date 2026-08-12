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

"""Build the pinned s-gw runtime as a deterministic DefenseClaw module."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

if __package__:
    from scripts import sgw_module, sync_sgw_vendor
else:
    import sgw_module  # type: ignore[no-redef]
    import sync_sgw_vendor  # type: ignore[no-redef]


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODULE_MANIFEST = ROOT / "release" / "s-gw-module.json"
TARGETS = (
    "darwin-x64",
    "darwin-arm64",
    "linux-x64",
    "linux-arm64",
    "win32-x64",
    "win32-arm64",
)
MAX_COMPONENT_FILES = 20_000
MAX_COMPONENT_FILE_BYTES = 64 * 1024 * 1024
MAX_COMPONENT_TOTAL_BYTES = 256 * 1024 * 1024
MAX_MODULE_FILES = 100_000
MAX_MODULE_FILE_BYTES = 256 * 1024 * 1024
MAX_MODULE_TOTAL_BYTES = 1024 * 1024 * 1024
MODULE_METADATA_FILE = "defenseclaw-module.json"
GO_RELEASE_KEY = ROOT / "internal" / "gateway" / "sgw_release_key.go"
MAX_GO_RELEASE_KEY_BYTES = 64 * 1024
GO_RELEASE_KEY_HEADER = (
    "// Copyright 2026 Cisco Systems, Inc. and its affiliates\n"
    "//\n"
    '// Licensed under the Apache License, Version 2.0 (the "License");\n'
    "// you may not use this file except in compliance with the License.\n"
    "// You may obtain a copy of the License at\n"
    "//\n"
    "//     http://www.apache.org/licenses/LICENSE-2.0\n"
    "//\n"
    "// Unless required by applicable law or agreed to in writing, software\n"
    '// distributed under the License is distributed on an "AS IS" BASIS,\n'
    "// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n"
    "// See the License for the specific language governing permissions and\n"
    "// limitations under the License.\n"
    "//\n"
    "// SPDX-License-Identifier: Apache-2.0\n"
    "\n"
    "package gateway\n"
    "\n"
)


class BuildError(RuntimeError):
    pass


def go_release_trust_anchor(path: Path | None = None) -> tuple[str, str]:
    path = GO_RELEASE_KEY if path is None else path
    try:
        metadata = path.lstat()
        if path.is_symlink() or not path.is_file() or metadata.st_size > MAX_GO_RELEASE_KEY_BYTES:
            raise ValueError("Go release key source must be a bounded regular file")
        source = path.read_text(encoding="ascii", errors="strict")
    except (OSError, UnicodeError, ValueError) as exc:
        raise BuildError(f"could not read the committed Go s-gw release key: {exc}") from exc

    values: dict[str, str] = {}
    for name in ("sgwReleasePublicKeyPEM", "sgwReleasePublicKeySHA256"):
        matches = re.findall(rf'^const {name} = ("(?:[^"\\]|\\.)*")$', source, flags=re.MULTILINE)
        if len(matches) != 1:
            raise BuildError(f"committed Go s-gw release key must define exactly one {name}")
        try:
            value = json.loads(matches[0])
        except json.JSONDecodeError as exc:
            raise BuildError(f"committed Go s-gw release key has invalid {name}") from exc
        if not isinstance(value, str):
            raise BuildError(f"committed Go s-gw release key has invalid {name}")
        values[name] = value
    public_key = values["sgwReleasePublicKeyPEM"]
    fingerprint = values["sgwReleasePublicKeySHA256"]
    if source != go_release_key_source(public_key, fingerprint):
        raise BuildError("committed Go s-gw release key must use the canonical source template")
    return public_key, fingerprint


def go_release_key_source(public_key: str, fingerprint: str) -> str:
    return (
        GO_RELEASE_KEY_HEADER
        + f"const sgwReleasePublicKeyPEM = {json.dumps(public_key)}\n"
        + f"const sgwReleasePublicKeySHA256 = {json.dumps(fingerprint)}\n"
    )


def validate_go_release_trust_anchor(runtime: dict[str, Any]) -> None:
    go_pem, go_fingerprint = go_release_trust_anchor()
    approved = runtime.get("redistribution_status") == "approved"
    policy = runtime.get("signature_policy")
    if not isinstance(policy, dict):
        raise BuildError("s-gw runtime signature policy is invalid")
    if not approved:
        if go_pem or go_fingerprint:
            raise BuildError("Go s-gw release key must remain blank while redistribution is not approved")
        return
    try:
        sgw_module.component_signing_key(runtime)
    except (RuntimeError, ValueError) as exc:
        raise BuildError(str(exc)) from exc
    if go_pem != policy.get("public_key") or go_fingerprint != policy.get("public_key_sha256"):
        raise BuildError("committed Go s-gw release key does not match the approved runtime trust anchor")


def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise BuildError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = sgw_module.read_json(path, "build_input_invalid")
    except sgw_module.ModuleError as exc:
        raise BuildError(f"could not read {path}: {exc}") from exc
    return value


def run(command: list[str], *, cwd: Path) -> None:
    try:
        result = subprocess.run(command, cwd=cwd, check=False)
    except OSError as exc:
        raise BuildError(f"could not run {command[0]}: {exc}") from exc
    if result.returncode != 0:
        raise BuildError(f"command exited {result.returncode}: {' '.join(command)}")


def safe_repo_path(value: object, *, label: str) -> Path:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise BuildError(f"invalid repository-relative {label}: {value!r}")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise BuildError(f"invalid repository-relative {label}: {value!r}")
    candidate = ROOT.joinpath(*pure.parts)
    try:
        candidate.resolve().relative_to(ROOT.resolve())
    except (OSError, ValueError) as exc:
        raise BuildError(f"{label} escapes the repository") from exc
    return candidate


def patch_queue(manifest: dict[str, Any]) -> list[Path]:
    raw = manifest.get("patches")
    if not isinstance(raw, list) or not raw or not all(isinstance(item, str) for item in raw):
        raise BuildError("s-gw module manifest must contain a non-empty patch queue")
    patches = [safe_repo_path(item, label="patch path") for item in raw]
    for patch in patches:
        if patch.is_symlink() or not patch.is_file() or patch.stat().st_size == 0:
            raise BuildError(f"s-gw patch is missing or unsafe: {patch}")
    series_path = patches[0].parent / "series"
    try:
        series = [line.strip() for line in series_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except OSError as exc:
        raise BuildError(f"could not read s-gw patch series: {exc}") from exc
    if series != [patch.name for patch in patches]:
        raise BuildError("s-gw patch series does not match the reviewed module manifest")
    return patches


def component_names(manifest: dict[str, Any]) -> tuple[str, ...]:
    raw = manifest.get("production_components")
    if not isinstance(raw, list) or not raw or not all(isinstance(item, str) and item for item in raw):
        raise BuildError("s-gw module manifest must name its production components")
    names = tuple(raw)
    required = {"runner", "credential_helper", "approval_ui", "license_bundle"}
    if len(set(names)) != len(names) or set(names) != required:
        raise BuildError(
            "s-gw production components must be runner, credential_helper, approval_ui, and license_bundle"
        )
    return names


def components_for_target(
    path: Path,
    module_manifest: dict[str, Any],
    target: str,
    *,
    allow_missing: bool,
) -> dict[str, dict[str, Any]]:
    manifest = read_json(path)
    targets = manifest.get("targets")
    if (
        set(manifest) != sgw_module.RUNTIME_MANIFEST_FIELDS
        or manifest.get("schema_version") != 1
        or manifest.get("component") != "s-gw production runtime"
        or manifest.get("license") != "LicenseRef-s-gw-Core"
        or manifest.get("redistribution_status") not in {"approved", "not_approved"}
        or manifest.get("required_for_production") is not True
        or not isinstance(targets, dict)
        or set(targets) != set(TARGETS)
    ):
        raise BuildError("s-gw runtime manifest has an invalid production contract")
    record = targets.get(target) if isinstance(targets, dict) else None
    if not isinstance(record, dict):
        raise BuildError(f"s-gw runtime manifest lacks target {target}")
    if set(record) != {
        "components",
        "runner_launch_admission",
        "module_installed_sha256",
        "module_signature",
    }:
        raise BuildError(f"s-gw runtime target metadata is invalid for {target}")
    records = record.get("components")
    names = component_names(module_manifest)
    if not isinstance(records, dict) or set(records) != set(names):
        raise BuildError(f"s-gw runtime manifest has an incomplete component set for {target}")

    approved = manifest.get("redistribution_status") == "approved"
    try:
        signing_key, fingerprint = sgw_module.component_signing_key(manifest)
        sgw_module.validated_runner_contract(manifest)
    except (RuntimeError, ValueError) as exc:
        raise BuildError(str(exc)) from exc
    launch_admission = record.get("runner_launch_admission")
    launch_admission_sha256: str | None = None
    if approved:
        if launch_admission is not None:
            try:
                launch_admission = sgw_module.validated_runner_launch_admission(target, launch_admission)
                launch_admission_sha256 = sgw_module.runner_launch_admission_sha256(target, launch_admission)
            except ValueError as exc:
                raise BuildError(f"s-gw runner launch admission is invalid for {target}") from exc
    elif launch_admission is not None:
        raise BuildError(f"unapproved s-gw target carries runner launch admission for {target}")
    module_installed_sha256 = record.get("module_installed_sha256")
    module_signature = record.get("module_signature")
    if module_installed_sha256 is not None and (
        not isinstance(module_installed_sha256, str) or not sgw_module.SHA256_RE.fullmatch(module_installed_sha256)
    ):
        raise BuildError(f"s-gw module installed digest is invalid for {target}")
    if not approved and (module_installed_sha256 is not None or module_signature is not None):
        raise BuildError(f"unapproved s-gw target carries signed release metadata for {target}")
    module_available = (
        approved
        and launch_admission is not None
        and isinstance(launch_admission_sha256, str)
        and isinstance(module_installed_sha256, str)
        and bool(sgw_module.SHA256_RE.fullmatch(module_installed_sha256))
        and isinstance(module_signature, str)
        and bool(module_signature)
    )
    if module_available:
        assert signing_key is not None
        try:
            sgw_module.verify_module_signature(
                signing_key,
                module_signature,
                target=target,
                manifest=module_manifest,
                installed_sha256=module_installed_sha256,
                runner_launch_admission_sha256=launch_admission_sha256,
                runner_contract_sha256=sgw_module.runner_contract_sha256(),
            )
        except (RuntimeError, ValueError) as exc:
            raise BuildError(f"s-gw module signature is invalid for {target}") from exc
    resolved: dict[str, dict[str, Any]] = {}
    missing: list[str] = []
    if not module_available:
        missing.append("module_signature")
    if approved and launch_admission is None:
        missing.append("runner_launch_admission")
    for name in names:
        item = records[name]
        if not isinstance(item, dict):
            raise BuildError(f"s-gw {name} metadata must be an object for {target}")
        expected = expected_component_contract(target)[name]
        if set(item) != {*expected, "path", "sha256", "installed_sha256", "signature"}:
            raise BuildError(f"s-gw {name} metadata has unexpected fields for {target}")
        for field, value in expected.items():
            if item.get(field) != value:
                raise BuildError(f"s-gw {name} has invalid {field} for {target}")
        destination = safe_component_path(item.get("destination"), label=f"{name} destination")
        component_format = item.get("format")
        if component_format not in {"file", "tar.gz"}:
            raise BuildError(f"s-gw {name} has an unsupported format for {target}")
        if component_format == "tar.gz":
            archive_root = safe_component_path(item.get("archive_root"), label=f"{name} archive root")
            if len(archive_root.parts) != 1:
                raise BuildError(f"s-gw {name} archive root must be one path component")
        installed_sha256 = item.get("installed_sha256")
        signature = item.get("signature")
        if installed_sha256 is not None and (
            not isinstance(installed_sha256, str) or not sgw_module.SHA256_RE.fullmatch(installed_sha256)
        ):
            raise BuildError(f"s-gw {name} installed digest is invalid for {target}")
        if not approved and (installed_sha256 is not None or signature is not None):
            raise BuildError(f"unapproved s-gw {name} carries signed release metadata for {target}")
        available = (
            approved
            and isinstance(item.get("filename"), str)
            and bool(item["filename"])
            and isinstance(item.get("path"), str)
            and bool(item["path"])
            and isinstance(item.get("sha256"), str)
            and len(item["sha256"]) == 64
            and all(character in "0123456789abcdef" for character in item["sha256"])
            and isinstance(installed_sha256, str)
            and bool(sgw_module.SHA256_RE.fullmatch(installed_sha256))
            and isinstance(signature, str)
            and bool(signature)
        )
        if not available:
            missing.append(name)
            continue
        source = Path(item["path"])
        if not source.is_absolute():
            source = safe_repo_path(item["path"], label=f"{name} source")
        if source.is_symlink() or not source.is_file():
            raise BuildError(f"approved s-gw {name} is missing or unsafe: {source}")
        if source.stat().st_size == 0:
            raise BuildError(f"approved s-gw {name} is empty: {source}")
        digest = file_digest(source)
        if digest != item["sha256"]:
            raise BuildError(f"approved s-gw {name} digest does not match for {target}")
        if component_format == "file":
            expected_installed = sgw_module.component_inventory_sha256({destination.as_posix(): digest})
            if installed_sha256 != expected_installed:
                raise BuildError(f"approved s-gw {name} installed digest does not match for {target}")
        assert signing_key is not None
        try:
            sgw_module.verify_component_signature(
                signing_key,
                signature,
                target=target,
                component=name,
                destination=destination.as_posix(),
                artifact_sha256=digest,
                installed_sha256=installed_sha256,
            )
        except (RuntimeError, ValueError) as exc:
            raise BuildError(f"approved s-gw {name} signature is invalid for {target}") from exc
        if name == "runner":
            validate_native_architecture(source, target, name)
        elif name == "credential_helper" and target.startswith(("darwin-", "linux-")):
            validate_native_architecture(source, target, name)
        resolved[name] = {
            **item,
            "destination": destination.as_posix(),
            "source": source,
            "_public_key_sha256": fingerprint,
            "_module_installed_sha256": module_installed_sha256,
            "_module_signature": module_signature,
            "_runner_launch_admission": launch_admission,
            "_runner_launch_admission_sha256": launch_admission_sha256,
        }

    if missing:
        if allow_missing:
            return {}
        joined = ", ".join(missing)
        raise BuildError(
            f"production s-gw module is blocked: approved {target} runtime components are unavailable: {joined}"
        )
    return resolved


def signing_candidates(
    path: Path,
    module_manifest: dict[str, Any],
    target: str,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    candidate = read_json(path)
    if set(candidate) != {"schema_version", "target", "runner_launch_admission", "components"}:
        raise BuildError("s-gw signing candidate request has unexpected fields")
    if candidate.get("schema_version") != 1 or candidate.get("target") != target:
        raise BuildError("s-gw signing candidate request has an invalid target contract")
    try:
        admission = sgw_module.validated_runner_launch_admission(
            target,
            candidate.get("runner_launch_admission"),
        )
    except ValueError as exc:
        raise BuildError(f"s-gw signing candidate has invalid runner launch admission for {target}") from exc
    components = candidate.get("components")
    names = component_names(module_manifest)
    if not isinstance(components, dict) or set(components) != set(names):
        raise BuildError("s-gw signing candidate request has an incomplete component set")

    records: dict[str, dict[str, Any]] = {}
    base = path.parent.resolve(strict=True)
    for name in names:
        value = components[name]
        if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
            raise BuildError(f"s-gw signing candidate {name} has unexpected fields")
        raw_path = value.get("path")
        expected_sha256 = value.get("sha256")
        if not isinstance(raw_path, str) or not raw_path or "\x00" in raw_path:
            raise BuildError(f"s-gw signing candidate {name} has an invalid path")
        if not isinstance(expected_sha256, str) or not sgw_module.SHA256_RE.fullmatch(expected_sha256):
            raise BuildError(f"s-gw signing candidate {name} has an invalid SHA-256")
        source = Path(raw_path).expanduser()
        if not source.is_absolute():
            source = base / source
        try:
            metadata = source.lstat()
            resolved = source.resolve(strict=True)
        except OSError as exc:
            raise BuildError(f"s-gw signing candidate {name} is unavailable") from exc
        if source.is_symlink() or not source.is_file() or metadata.st_size <= 0:
            raise BuildError(f"s-gw signing candidate {name} is not a non-empty regular file")
        if metadata.st_size > MAX_COMPONENT_FILE_BYTES:
            raise BuildError(f"s-gw signing candidate {name} is too large")
        if file_digest(resolved) != expected_sha256:
            raise BuildError(f"s-gw signing candidate {name} digest does not match")
        if name == "runner":
            validate_native_architecture(resolved, target, name)
        elif name == "credential_helper" and target.startswith(("darwin-", "linux-")):
            validate_native_architecture(resolved, target, name)
        records[name] = {
            **expected_component_contract(target)[name],
            "path": os.fspath(resolved),
            "sha256": expected_sha256,
            "installed_sha256": None,
            "signature": None,
            "source": resolved,
        }
    return admission, records


def snapshot_signing_candidates(
    records: dict[str, dict[str, Any]],
    destination: Path,
) -> dict[str, dict[str, Any]]:
    destination.mkdir(mode=0o700)
    snapshots: dict[str, dict[str, Any]] = {}
    for name, record in records.items():
        source = record["source"]
        assert isinstance(source, Path)
        output = destination / str(record["filename"])
        if output.exists():
            output = destination / f"{name}-{record['filename']}"
        with source.open("rb") as candidate, output.open("xb") as snapshot:
            shutil.copyfileobj(candidate, snapshot, length=1024 * 1024)
        if file_digest(output) != record["sha256"]:
            raise BuildError(f"s-gw signing candidate {name} changed while it was snapshotted")
        if record.get("executable") is True:
            output.chmod(0o700)
        snapshots[name] = {**record, "path": os.fspath(output), "source": output}
    return snapshots


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


def safe_component_path(value: object, *, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise BuildError(f"invalid {label}: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise BuildError(f"invalid {label}: {value!r}")
    return path


def validate_native_architecture(path: Path, target: str, component: str) -> None:
    try:
        with path.open("rb") as source:
            if target.startswith("linux-"):
                valid = valid_elf_architecture(source, target)
            elif target.startswith("darwin-"):
                valid = valid_macho_architecture(source, path.stat().st_size, target)
            elif target.startswith("win32-"):
                valid = valid_pe_architecture(source, path.stat().st_size, target)
            else:
                valid = False
    except OSError as exc:
        raise BuildError(f"could not inspect approved {component} architecture: {path}") from exc
    if not valid:
        raise BuildError(f"approved {component} does not match target architecture {target}: {path}")


def valid_elf_architecture(source: Any, target: str) -> bool:
    header = source.read(20)
    expected = {"linux-x64": 62, "linux-arm64": 183}.get(target)
    if expected is None or len(header) != 20:
        return False
    if header[:4] != b"\x7fELF" or header[4] != 2 or header[5] != 1:
        return False
    return int.from_bytes(header[18:20], "little") == expected


def valid_pe_architecture(source: Any, file_size: int, target: str) -> bool:
    header = source.read(64)
    expected = {"win32-x64": 0x8664, "win32-arm64": 0xAA64}.get(target)
    if expected is None or len(header) != 64 or header[:2] != b"MZ":
        return False
    pe_offset = int.from_bytes(header[60:64], "little")
    if pe_offset < 64 or pe_offset > file_size - 6:
        return False
    source.seek(pe_offset)
    identity = source.read(6)
    if len(identity) != 6 or identity[:4] != b"PE\0\0":
        return False
    return int.from_bytes(identity[4:6], "little") == expected


def valid_macho_architecture(source: Any, file_size: int, target: str) -> bool:
    expected = {"darwin-x64": 0x01000007, "darwin-arm64": 0x0100000C}.get(target)
    header = source.read(8)
    if expected is None or len(header) != 8:
        return False
    thin = macho_cpu_type(header)
    if thin is not None:
        return thin == expected

    fat_formats = {
        b"\xca\xfe\xba\xbe": ("big", 20),
        b"\xbe\xba\xfe\xca": ("little", 20),
        b"\xca\xfe\xba\xbf": ("big", 32),
        b"\xbf\xba\xfe\xca": ("little", 32),
    }
    fat = fat_formats.get(header[:4])
    if fat is None:
        return False
    byte_order, record_size = fat
    count = int.from_bytes(header[4:8], byte_order)
    if count < 1 or count > 64 or 8 + count * record_size > file_size:
        return False
    records = source.read(count * record_size)
    if len(records) != count * record_size:
        return False

    matched = False
    for index in range(count):
        record = records[index * record_size : (index + 1) * record_size]
        cpu_type = int.from_bytes(record[:4], byte_order)
        if record_size == 20:
            offset = int.from_bytes(record[8:12], byte_order)
            size = int.from_bytes(record[12:16], byte_order)
        else:
            offset = int.from_bytes(record[8:16], byte_order)
            size = int.from_bytes(record[16:24], byte_order)
        if offset < 8 + count * record_size or size < 8 or offset > file_size - size:
            return False
        if cpu_type == expected:
            source.seek(offset)
            slice_header = source.read(8)
            if len(slice_header) != 8 or macho_cpu_type(slice_header) != expected:
                return False
            matched = True
    return matched


def macho_cpu_type(header: bytes) -> int | None:
    if len(header) < 8:
        return None
    byte_order = {
        b"\xcf\xfa\xed\xfe": "little",
        b"\xfe\xed\xfa\xcf": "big",
    }.get(header[:4])
    if byte_order is None:
        return None
    return int.from_bytes(header[4:8], byte_order)


def build_toolchain(manifest: dict[str, Any]) -> tuple[str, str]:
    toolchain = manifest.get("build_toolchain")
    if (
        not isinstance(toolchain, dict)
        or set(toolchain) != {"node", "npm"}
        or not all(
            isinstance(toolchain.get(name), str) and bool(sgw_module.NODE_VERSION_RE.fullmatch(toolchain[name]))
            for name in ("node", "npm")
        )
    ):
        raise BuildError("s-gw module manifest has an invalid build toolchain")
    return toolchain["node"], toolchain["npm"]


def node_command(explicit: str | None, minimum_major: int, exact_version: str | None = None) -> Path:
    candidate = explicit or shutil.which("node")
    if not candidate:
        raise BuildError(f"Node.js {minimum_major}+ is required to build the s-gw module")
    node = Path(candidate).resolve(strict=True)
    try:
        returncode, output, overflow = sgw_module.run_bounded_output(
            [os.fspath(node), "--version"],
            timeout=5,
            max_bytes=4096,
        )
        version = output.decode("ascii", errors="strict").strip().removeprefix("v")
    except (OSError, UnicodeDecodeError, subprocess.TimeoutExpired) as exc:
        raise BuildError("could not read the Node.js build version") from exc
    if returncode != 0 or overflow:
        raise BuildError("could not read the Node.js build version")
    try:
        major = int(version.split(".", 1)[0])
    except (ValueError, IndexError):
        major = 0
    if major < minimum_major:
        raise BuildError(f"Node.js {minimum_major}+ is required; found {version or 'an unreadable version'}")
    if exact_version is not None and version != exact_version:
        raise BuildError(f"production s-gw build requires Node.js {exact_version}; found {version}")
    return node


def npm_command(explicit: str | None, node: Path, exact_version: str | None = None) -> Path:
    candidate = explicit or shutil.which("npm")
    if not candidate:
        raise BuildError("npm is required to build the s-gw module")
    npm = Path(candidate).absolute()
    if exact_version is not None and npm.parent.resolve() != node.parent.resolve():
        raise BuildError("Node.js and npm must come from the same pinned toolchain")
    try:
        returncode, output, overflow = sgw_module.run_bounded_output(
            [os.fspath(npm), "--version"],
            timeout=5,
            max_bytes=4096,
        )
        version = output.decode("ascii", errors="strict").strip()
    except (OSError, UnicodeDecodeError, subprocess.TimeoutExpired) as exc:
        raise BuildError("could not read the npm build version") from exc
    if returncode != 0 or overflow or not sgw_module.NODE_VERSION_RE.fullmatch(version):
        raise BuildError("could not read the npm build version")
    if exact_version is not None and version != exact_version:
        raise BuildError(f"production s-gw build requires npm {exact_version}; found {version}")
    return npm


def apply_patches(stage: Path, patches: list[Path]) -> None:
    for patch in patches:
        run(["git", "apply", "--check", os.fspath(patch)], cwd=stage)
        run(["git", "apply", os.fspath(patch)], cwd=stage)


def copy_runtime(stage: Path, package_root: Path) -> None:
    for leaf in ("LICENSE", "NOTICE", "README.md", "TRADEMARKS.md", "package.json", "package-lock.json"):
        source = stage / leaf
        if source.is_symlink() or not source.is_file():
            raise BuildError(f"patched s-gw source lacks {leaf}")
        shutil.copy2(source, package_root / leaf)
    notices = stage / "docs" / "ui"
    if notices.is_symlink() or not notices.is_dir():
        raise BuildError("patched s-gw source lacks third-party attribution files")
    shutil.copytree(notices, package_root / "docs" / "ui")
    shutil.copytree(stage / "dist", package_root / "dist")
    shutil.copytree(stage / "node_modules", package_root / "node_modules")
    bin_dir = package_root / "node_modules" / ".bin"
    if bin_dir.exists():
        shutil.rmtree(bin_dir)
    reject_links(package_root)


def remove_build_caches(stage: Path) -> None:
    for name in (".vite", ".vite-temp"):
        cache = stage / "node_modules" / name
        if cache.exists():
            if cache.is_symlink() or not cache.is_dir():
                raise BuildError(f"s-gw build cache path is unsafe: {cache}")
            shutil.rmtree(cache)
    hidden_lock = stage / "node_modules" / ".package-lock.json"
    if hidden_lock.exists() or hidden_lock.is_symlink():
        if hidden_lock.is_symlink() or not hidden_lock.is_file():
            raise BuildError("s-gw npm runtime lock path is unsafe")
        hidden_lock.unlink()


def reject_links(root: Path) -> None:
    for item in root.rglob("*"):
        if item.is_symlink():
            raise BuildError(f"s-gw module contains a symbolic link: {item.relative_to(root)}")
        if not item.is_dir() and not item.is_file():
            raise BuildError(f"s-gw module contains a non-regular entry: {item.relative_to(root)}")


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def complete_file_inventory(package_root: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    total = 0
    for item in sorted(package_root.rglob("*"), key=lambda path: path.relative_to(package_root).as_posix()):
        relative = item.relative_to(package_root).as_posix()
        if item.is_symlink() or (not item.is_dir() and not item.is_file()):
            raise BuildError(f"s-gw module contains an unsafe entry: {relative}")
        if item.is_dir():
            continue
        size = item.stat().st_size
        if size > MAX_MODULE_FILE_BYTES:
            raise BuildError(f"s-gw module contains an oversized file: {relative}")
        total += size
        if len(files) >= MAX_MODULE_FILES or total > MAX_MODULE_TOTAL_BYTES:
            raise BuildError("s-gw module exceeds its file inventory limits")
        files[relative] = file_digest(item)
    if not files:
        raise BuildError("s-gw module file inventory is empty")
    return files


def copy_production_components(
    package_root: Path,
    records: dict[str, dict[str, Any]],
) -> tuple[dict[str, dict[str, object]], set[str]]:
    return copy_components(package_root, records, verify_signed_inventory=True)


def copy_signing_candidates(
    package_root: Path,
    records: dict[str, dict[str, Any]],
) -> tuple[dict[str, dict[str, object]], set[str]]:
    return copy_components(package_root, records, verify_signed_inventory=False)


def copy_components(
    package_root: Path,
    records: dict[str, dict[str, Any]],
    *,
    verify_signed_inventory: bool,
) -> tuple[dict[str, dict[str, object]], set[str]]:
    metadata: dict[str, dict[str, object]] = {}
    executable_paths: set[str] = set()
    for name, record in records.items():
        destination = safe_component_path(record["destination"], label=f"{name} destination")
        source = record["source"]
        assert isinstance(source, Path)
        if record["format"] == "file":
            output = package_root.joinpath(*destination.parts)
            output.parent.mkdir(parents=True, exist_ok=True)
            if output.exists():
                raise BuildError(f"s-gw runtime component would replace an existing file: {destination}")
            shutil.copy2(source, output)
            if record.get("executable") is True:
                output.chmod(0o755)
                executable_paths.add(destination.as_posix())
            files = [destination.as_posix()]
        else:
            files = extract_component_archive(source, package_root, destination, record)
        installed_files = {
            relative: file_digest(package_root.joinpath(*PurePosixPath(relative).parts)) for relative in files
        }
        installed_sha256 = sgw_module.component_inventory_sha256(installed_files)
        if verify_signed_inventory and installed_sha256 != record.get("installed_sha256"):
            raise BuildError(f"s-gw {name} installed inventory does not match its signed digest")
        metadata[name] = {
            "artifact_sha256": record["sha256"],
            "installed_sha256": installed_sha256,
            "signature": record.get("signature"),
            "destination": destination.as_posix(),
            "files": files,
        }
    return metadata, executable_paths


def extract_component_archive(
    source: Path,
    package_root: Path,
    destination: PurePosixPath,
    record: dict[str, Any],
) -> list[str]:
    archive_root = safe_component_path(record.get("archive_root"), label="component archive root")
    required_files = required_component_entries(record.get("required_files"), "required_files")
    required_directories = required_component_entries(record.get("required_directories"), "required_directories")
    output_root = package_root.joinpath(*destination.parts)
    if output_root.exists():
        raise BuildError(f"s-gw component archive would replace an existing path: {destination}")

    try:
        archive = tarfile.open(source, mode="r:gz")
    except (OSError, tarfile.TarError) as exc:
        raise BuildError(f"could not open approved s-gw component archive: {exc}") from exc
    entries: list[tuple[tarfile.TarInfo, PurePosixPath]] = []
    names: set[str] = set()
    total = 0
    with archive:
        members = archive.getmembers()
        if not members or len(members) > MAX_COMPONENT_FILES:
            raise BuildError("approved s-gw component archive has an invalid file count")
        for member in members:
            if "\\" in member.name or "\x00" in member.name:
                raise BuildError(f"unsafe s-gw component archive path: {member.name!r}")
            member_path = PurePosixPath(member.name)
            if (
                member_path.is_absolute()
                or not member_path.parts
                or member_path.parts[0] != archive_root.as_posix()
                or any(part in {"", ".", ".."} for part in member_path.parts)
            ):
                raise BuildError(f"unsafe s-gw component archive path: {member.name!r}")
            relative = PurePosixPath(*member_path.parts[1:])
            if not relative.parts:
                if not member.isdir():
                    raise BuildError("s-gw component archive root must be a directory")
                continue
            normalized = relative.as_posix()
            if normalized in names:
                raise BuildError(f"duplicate s-gw component archive path: {normalized}")
            names.add(normalized)
            if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                raise BuildError(f"unsupported s-gw component archive entry: {normalized}")
            if member.size < 0 or member.size > MAX_COMPONENT_FILE_BYTES:
                raise BuildError(f"oversized s-gw component archive entry: {normalized}")
            total += member.size
            if total > MAX_COMPONENT_TOTAL_BYTES:
                raise BuildError("approved s-gw component archive exceeds its expanded-size limit")
            entries.append((member, relative))

        output_root.mkdir(parents=True)
        files: list[str] = []
        for member, relative in entries:
            output = output_root.joinpath(*relative.parts)
            if member.isdir():
                output.mkdir(parents=True, exist_ok=True)
                continue
            output.parent.mkdir(parents=True, exist_ok=True)
            extracted = archive.extractfile(member)
            if extracted is None:
                raise BuildError(f"could not read s-gw component archive entry: {member.name}")
            try:
                with output.open("xb") as target_file:
                    shutil.copyfileobj(extracted, target_file, length=1024 * 1024)
            finally:
                extracted.close()
            if output.stat().st_size != member.size:
                raise BuildError(f"short s-gw component archive entry: {member.name}")
            files.append(destination.joinpath(relative).as_posix())

    for required in required_files:
        item = output_root.joinpath(*required.parts)
        if not item.is_file() or item.stat().st_size == 0:
            raise BuildError(f"s-gw approval UI lacks required file: {required}")
    for required in required_directories:
        item = output_root.joinpath(*required.parts)
        if not item.is_dir() or not any(candidate.is_file() for candidate in item.rglob("*")):
            raise BuildError(f"s-gw approval UI lacks required assets: {required}")
    validate_approval_ui_capabilities(output_root, record)
    return sorted(files)


def validate_approval_ui_capabilities(output_root: Path, record: dict[str, Any]) -> None:
    relative = safe_component_path(record.get("capability_manifest"), label="capability manifest")
    manifest_path = output_root.joinpath(*relative.parts)
    manifest = read_json(manifest_path)
    if set(manifest) != {"schema_version", "capabilities"} or manifest.get("schema_version") != 1:
        raise BuildError("s-gw approval UI capability manifest has an invalid contract")
    capabilities = manifest.get("capabilities")
    required = record.get("required_capabilities")
    if (
        not isinstance(capabilities, list)
        or not capabilities
        or not all(isinstance(item, str) and item for item in capabilities)
        or len(capabilities) != len(set(capabilities))
        or not isinstance(required, list)
        or not set(required).issubset(capabilities)
    ):
        raise BuildError("s-gw approval UI lacks its required enrollment capability")


def required_component_entries(value: object, label: str) -> tuple[PurePosixPath, ...]:
    if not isinstance(value, list) or not value:
        raise BuildError(f"s-gw component archive must define {label}")
    return tuple(safe_component_path(item, label=label) for item in value)


def module_metadata(
    package_root: Path,
    manifest: dict[str, Any],
    target: str,
    components: dict[str, dict[str, object]],
    release_records: dict[str, dict[str, Any]],
) -> dict[str, object]:
    entrypoints = manifest["entrypoints"]
    critical = ["package.json", str(entrypoints["cli"]), str(entrypoints["mcp"])]
    for component in components.values():
        files = component.get("files")
        if not isinstance(files, list) or not files:
            raise BuildError("s-gw production component lacks its installed file inventory")
        critical.extend(str(relative) for relative in files)
    for relative in dict.fromkeys(critical):
        item = package_root.joinpath(*PurePosixPath(relative).parts)
        if item.is_symlink() or not item.is_file() or item.stat().st_size == 0:
            raise BuildError(f"s-gw module lacks required runtime file: {relative}")
    files = complete_file_inventory(package_root)
    module_installed_sha256 = sgw_module.module_inventory_sha256(files)
    public_key_sha256: object = None
    module_signature: object = None
    launch_admission: object = None
    launch_admission_sha256: object = None
    runner: dict[str, object] = {"path": None, "sha256": None, "signature": None}
    if components:
        release_proof = release_records["runner"]
        if module_installed_sha256 != release_proof.get("_module_installed_sha256"):
            raise BuildError("s-gw installed module inventory does not match its signed digest")
        public_key_sha256 = release_proof.get("_public_key_sha256")
        module_signature = release_proof.get("_module_signature")
        launch_admission = release_proof.get("_runner_launch_admission")
        launch_admission_sha256 = release_proof.get("_runner_launch_admission_sha256")
        runner_component = components["runner"]
        runner_files = runner_component["files"]
        assert isinstance(runner_files, list) and len(runner_files) == 1
        runner_path = runner_files[0]
        runner = {
            "path": runner_path,
            "sha256": files[runner_path],
            "signature": runner_component["signature"],
        }
    return {
        "schema_version": 1,
        "package_name": manifest["package_name"],
        "package_version": manifest["package_version"],
        "upstream_revision": manifest["upstream_revision"],
        "upstream_tree": manifest["upstream_tree"],
        "minimum_node_version": manifest["minimum_node_version"],
        "build_toolchain": manifest["build_toolchain"],
        "target": target,
        "production_ready": set(components) == set(component_names(manifest)),
        "inventory_excludes": [MODULE_METADATA_FILE],
        "signature_policy": {
            "algorithm": sgw_module.COMPONENT_SIGNATURE_ALGORITHM,
            "public_key_sha256": public_key_sha256,
        },
        "runner_contract": sgw_module.RUNNER_CONTRACT,
        "runner_contract_sha256": sgw_module.runner_contract_sha256(),
        "runner_launch_admission": launch_admission,
        "runner_launch_admission_sha256": launch_admission_sha256,
        "module_installed_sha256": module_installed_sha256,
        "module_signature": module_signature,
        "components": components,
        "runner": runner,
        "files": files,
    }


def normalized_mode(path: Path, executable_paths: set[str], relative: str) -> int:
    if relative in executable_paths:
        return 0o755
    return 0o755 if path.is_dir() else 0o644


def write_deterministic_archive(package_root: Path, output: Path, executable_paths: set[str]) -> str:
    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    with tmp.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                root_info = tarfile.TarInfo("package")
                root_info.type = tarfile.DIRTYPE
                root_info.mode = 0o755
                root_info.mtime = root_info.uid = root_info.gid = 0
                root_info.uname = root_info.gname = ""
                archive.addfile(root_info)
                items = sorted(
                    package_root.rglob("*"),
                    key=lambda item: item.relative_to(package_root).as_posix().encode(),
                )
                for item in items:
                    relative = item.relative_to(package_root).as_posix()
                    arcname = f"package/{relative}"
                    info = tarfile.TarInfo(arcname)
                    info.mtime = info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mode = normalized_mode(item, executable_paths, relative)
                    if item.is_dir():
                        info.type = tarfile.DIRTYPE
                        archive.addfile(info)
                    else:
                        info.size = item.stat().st_size
                        with item.open("rb") as source:
                            archive.addfile(info, source)
        raw.flush()
        os.fsync(raw.fileno())
    os.replace(tmp, output)
    digest = file_digest(output)
    checksum = output.with_suffix(output.suffix + ".sha256")
    checksum.write_text(f"{digest}  {output.name}\n", encoding="ascii")
    return digest


def copy_new_file(source: Path, destination: Path) -> None:
    created = False
    try:
        with destination.open("xb") as output:
            created = True
            with source.open("rb") as source_file:
                shutil.copyfileobj(source_file, output, length=1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        if created:
            destination.unlink(missing_ok=True)
        raise


def assemble_package(
    args: argparse.Namespace,
    manifest: dict[str, Any],
    component_records: dict[str, dict[str, Any]],
    temp_root: Path,
    *,
    signing_candidate: bool,
    skip_tests: bool,
) -> tuple[Path, dict[str, dict[str, object]], set[str]]:
    pinned_node, pinned_npm = build_toolchain(manifest)
    minimum_major = int(str(manifest["minimum_node_version"]).split(".", 1)[0])
    production_build = bool(component_records) or signing_candidate
    node = node_command(args.node, minimum_major, pinned_node if production_build else None)
    npm = npm_command(args.npm, node, pinned_npm if production_build else None)
    source = safe_repo_path(manifest["source_path"], label="source path")
    patches = patch_queue(manifest)
    stage = temp_root / "source"
    shutil.copytree(source, stage)
    apply_patches(stage, patches)
    package = read_json(stage / "package.json")
    if package.get("name") != manifest["package_name"] or package.get("version") != manifest["package_version"]:
        raise BuildError("patched s-gw package identity does not match the module manifest")

    build_env = os.environ.copy()
    build_env["PATH"] = f"{node.parent}{os.pathsep}{build_env.get('PATH', '')}"
    commands = [
        [os.fspath(npm), "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
        [os.fspath(stage / "node_modules" / ".bin" / executable_name("tsc")), "-p", "tsconfig.json"],
    ]
    if not skip_tests:
        commands.append(
            [
                os.fspath(stage / "node_modules" / ".bin" / executable_name("vitest")),
                "run",
                "tests/defenseclaw-runtime.test.ts",
                "tests/mcp-e2e.test.ts",
            ]
        )
    commands.append(
        [
            os.fspath(npm),
            "prune",
            "--omit=dev",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ]
    )
    for command in commands:
        result = subprocess.run(command, cwd=stage, env=build_env, check=False)
        if result.returncode != 0:
            raise BuildError(f"command exited {result.returncode}: {' '.join(command)}")
    remove_build_caches(stage)

    package_root = temp_root / "module" / "package"
    package_root.mkdir(parents=True)
    copy_runtime(stage, package_root)
    if signing_candidate:
        components, executable_paths = copy_signing_candidates(package_root, component_records)
    else:
        components, executable_paths = copy_production_components(package_root, component_records)
    return package_root, components, executable_paths


def signing_request_document(
    package_root: Path,
    manifest: dict[str, Any],
    target: str,
    admission: dict[str, Any],
    components: dict[str, dict[str, object]],
    archive_name: str,
    archive_sha256: str,
) -> dict[str, object]:
    files = complete_file_inventory(package_root)
    admission_sha256 = sgw_module.runner_launch_admission_sha256(target, admission)
    contract_sha256 = sgw_module.runner_contract_sha256()
    component_requests: dict[str, dict[str, object]] = {}
    for name in component_names(manifest):
        component = components[name]
        artifact_sha256 = component.get("artifact_sha256")
        installed_sha256 = component.get("installed_sha256")
        destination = component.get("destination")
        installed_files = component.get("files")
        if (
            not isinstance(artifact_sha256, str)
            or not isinstance(installed_sha256, str)
            or not isinstance(destination, str)
            or not isinstance(installed_files, list)
        ):
            raise BuildError(f"s-gw signing candidate {name} inventory is invalid")
        payload = sgw_module.component_signature_payload(
            target,
            name,
            destination,
            artifact_sha256,
            installed_sha256,
        )
        component_requests[name] = {
            "artifact_sha256": artifact_sha256,
            "installed_sha256": installed_sha256,
            "destination": destination,
            "files": installed_files,
            "signature_payload": payload.decode("ascii"),
            "signature_payload_sha256": hashlib.sha256(payload).hexdigest(),
        }
    module_installed_sha256 = sgw_module.module_inventory_sha256(files)
    module_payload = sgw_module.module_signature_payload(
        target,
        manifest,
        module_installed_sha256,
        admission_sha256,
        contract_sha256,
    )
    return {
        "schema_version": 1,
        "request_type": "defenseclaw.s-gw.offline-signing-request.v1",
        "target": target,
        "package": {
            "name": manifest["package_name"],
            "version": manifest["package_version"],
            "upstream_revision": manifest["upstream_revision"],
            "upstream_tree": manifest["upstream_tree"],
        },
        "build_toolchain": manifest["build_toolchain"],
        "signature_policy": {"algorithm": sgw_module.COMPONENT_SIGNATURE_ALGORITHM},
        "runner_contract": sgw_module.RUNNER_CONTRACT,
        "runner_contract_sha256": contract_sha256,
        "runner_launch_admission": admission,
        "runner_launch_admission_sha256": admission_sha256,
        "components": component_requests,
        "module": {
            "installed_sha256": module_installed_sha256,
            "file_count": len(files),
            "signature_payload": module_payload.decode("ascii"),
            "signature_payload_sha256": hashlib.sha256(module_payload).hexdigest(),
        },
        "unsigned_archive": {"filename": archive_name, "sha256": archive_sha256},
    }


def prepare_signing(args: argparse.Namespace) -> tuple[Path, Path, str, str]:
    sync_sgw_vendor.verify()
    manifest = read_json(args.module_manifest.resolve(strict=True))
    if manifest.get("schema_version") != 1:
        raise BuildError("unsupported s-gw module manifest schema")
    build_toolchain(manifest)
    if args.candidate_components is None:
        raise BuildError("--prepare-signing requires --candidate-components")
    candidate_path = args.candidate_components.resolve(strict=True)
    admission, records = signing_candidates(candidate_path, manifest, args.target)

    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    candidate_name = f"defenseclaw-s-gw-signing-candidate-{manifest['package_version']}-{args.target}.tar.gz"
    request_name = f"defenseclaw-s-gw-signing-request-{manifest['package_version']}-{args.target}.json"
    candidate_output = output_dir / candidate_name
    request_output = args.signing_request_output.resolve() if args.signing_request_output else output_dir / request_name
    checksum_output = candidate_output.with_suffix(candidate_output.suffix + ".sha256")
    for output in (candidate_output, checksum_output, request_output):
        if output.exists() or output.is_symlink():
            raise BuildError(f"refusing to replace existing signing output: {output}")

    with tempfile.TemporaryDirectory(prefix="defenseclaw-sgw-signing-") as temporary:
        temp_root = Path(temporary)
        snapshots = snapshot_signing_candidates(records, temp_root / "candidates")
        first_root = temp_root / "first"
        package_root, components, executable_paths = assemble_package(
            args,
            manifest,
            snapshots,
            first_root,
            signing_candidate=True,
            skip_tests=args.skip_tests,
        )
        second_package, second_components, _second_executables = assemble_package(
            args,
            manifest,
            snapshots,
            temp_root / "second",
            signing_candidate=True,
            skip_tests=True,
        )
        first_inventory = complete_file_inventory(package_root)
        second_inventory = complete_file_inventory(second_package)
        if first_inventory != second_inventory or components != second_components:
            raise BuildError("s-gw signing candidate rebuild is not reproducible")

        temporary_archive = temp_root / candidate_name
        archive_sha256 = write_deterministic_archive(package_root, temporary_archive, executable_paths)
        request = signing_request_document(
            package_root,
            manifest,
            args.target,
            admission,
            components,
            candidate_name,
            archive_sha256,
        )
        request_bytes = (json.dumps(request, indent=2, sort_keys=True) + "\n").encode("utf-8")
        if len(request_bytes) > sgw_module.MAX_JSON_BYTES:
            raise BuildError("s-gw signing request exceeds its size limit")
        temporary_request = temp_root / request_name
        temporary_request.write_bytes(request_bytes)
        temporary_checksum = temporary_archive.with_suffix(temporary_archive.suffix + ".sha256")
        request_sha256 = hashlib.sha256(request_bytes).hexdigest()
        request_output.parent.mkdir(parents=True, exist_ok=True)
        published: list[Path] = []
        try:
            copy_new_file(temporary_archive, candidate_output)
            published.append(candidate_output)
            copy_new_file(temporary_checksum, checksum_output)
            published.append(checksum_output)
            copy_new_file(temporary_request, request_output)
            published.append(request_output)
        except OSError:
            for output in published:
                output.unlink(missing_ok=True)
            raise
    return request_output, candidate_output, request_sha256, archive_sha256


def build(args: argparse.Namespace) -> tuple[Path, str]:
    sync_sgw_vendor.verify()
    manifest = read_json(args.module_manifest.resolve(strict=True))
    if manifest.get("schema_version") != 1:
        raise BuildError("unsupported s-gw module manifest schema")
    build_toolchain(manifest)
    runner_manifest = args.runner_manifest or safe_repo_path(manifest["runner_manifest"], label="runner manifest")
    component_records = components_for_target(
        runner_manifest.resolve(strict=True),
        manifest,
        args.target,
        allow_missing=args.allow_missing_runner,
    )
    runtime = read_json(runner_manifest.resolve(strict=True))
    validate_go_release_trust_anchor(runtime)
    output_dir = args.output_dir.resolve()

    with tempfile.TemporaryDirectory(prefix="defenseclaw-sgw-build-") as temp:
        package_root, components, executable_paths = assemble_package(
            args,
            manifest,
            component_records,
            Path(temp),
            signing_candidate=False,
            skip_tests=args.skip_tests,
        )
        metadata = module_metadata(package_root, manifest, args.target, components, component_records)
        if args.verify_reproducible:
            second_package, second_components, _second_executables = assemble_package(
                args,
                manifest,
                component_records,
                Path(temp) / "rebuild",
                signing_candidate=False,
                skip_tests=True,
            )
            second_metadata = module_metadata(
                second_package,
                manifest,
                args.target,
                second_components,
                component_records,
            )
            if (
                metadata["module_installed_sha256"] != second_metadata["module_installed_sha256"]
                or metadata["files"] != second_metadata["files"]
                or components != second_components
            ):
                raise BuildError("s-gw module rebuild is not reproducible")
        (package_root / MODULE_METADATA_FILE).write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        suffix = "-source-only" if not components else ""
        filename = str(manifest["artifact"]["filename_template"]).format(target=args.target)
        if suffix:
            filename = filename.removesuffix(".tar.gz") + f"{suffix}.tar.gz"
        output = output_dir / filename
        digest = write_deterministic_archive(package_root, output, executable_paths)
    return output, digest


def audit_dependencies(args: argparse.Namespace) -> None:
    sync_sgw_vendor.verify()
    manifest = read_json(args.module_manifest.resolve(strict=True))
    if manifest.get("schema_version") != 1:
        raise BuildError("unsupported s-gw module manifest schema")
    build_toolchain(manifest)
    minimum_major = int(str(manifest["minimum_node_version"]).split(".", 1)[0])
    node = node_command(args.node, minimum_major)
    npm = npm_command(args.npm, node)
    source = safe_repo_path(manifest["source_path"], label="source path")
    patches = patch_queue(manifest)

    with tempfile.TemporaryDirectory(prefix="defenseclaw-sgw-audit-") as temporary:
        stage = Path(temporary) / "source"
        shutil.copytree(source, stage)
        apply_patches(stage, patches)
        package = read_json(stage / "package.json")
        if package.get("name") != manifest["package_name"] or package.get("version") != manifest["package_version"]:
            raise BuildError("patched s-gw package identity does not match the module manifest")
        run(
            [
                os.fspath(npm),
                "audit",
                "--omit=dev",
                "--audit-level=high",
                "--package-lock-only",
            ],
            cwd=stage,
        )


def check_production_components(args: argparse.Namespace) -> tuple[str, ...]:
    sync_sgw_vendor.verify()
    manifest = read_json(args.module_manifest.resolve(strict=True))
    if manifest.get("schema_version") != 1:
        raise BuildError("unsupported s-gw module manifest schema")
    runner_manifest = args.runner_manifest or safe_repo_path(manifest["runner_manifest"], label="runner manifest")
    runtime = read_json(runner_manifest.resolve(strict=True))
    validate_go_release_trust_anchor(runtime)
    targets = TARGETS if args.target == "all" else (args.target,)
    for target in targets:
        records = components_for_target(
            runner_manifest.resolve(strict=True),
            manifest,
            target,
            allow_missing=False,
        )
        with tempfile.TemporaryDirectory(prefix=f"defenseclaw-sgw-{target}-components-") as temporary:
            copy_production_components(Path(temporary), records)
    return targets


def executable_name(name: str) -> str:
    return f"{name}.cmd" if os.name == "nt" else name


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module-manifest", type=Path, default=DEFAULT_MODULE_MANIFEST)
    parser.add_argument("--runner-manifest", type=Path)
    parser.add_argument("--target", required=True, choices=(*TARGETS, "all"))
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist" / "sgw")
    parser.add_argument("--node")
    parser.add_argument("--npm")
    parser.add_argument(
        "--allow-missing-runner",
        "--allow-incomplete-components",
        dest="allow_missing_runner",
        action="store_true",
        help="build a non-production source-only archive when approved runtime components are unavailable",
    )
    parser.add_argument("--skip-tests", action="store_true")
    parser.add_argument("--audit-dependencies", action="store_true")
    parser.add_argument("--check-production-components", action="store_true")
    parser.add_argument("--verify-reproducible", action="store_true")
    parser.add_argument("--prepare-signing", action="store_true")
    parser.add_argument("--candidate-components", type=Path)
    parser.add_argument("--signing-request-output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.audit_dependencies:
            if (
                args.target == "all"
                or args.prepare_signing
                or args.check_production_components
                or args.allow_missing_runner
                or args.skip_tests
                or args.verify_reproducible
                or args.candidate_components is not None
                or args.signing_request_output is not None
            ):
                raise BuildError("--audit-dependencies cannot be combined with build or signing modes")
            audit_dependencies(args)
            print(json.dumps({"schema_version": 1, "dependencies_audited": True}, sort_keys=True))
            return 0
        if args.prepare_signing:
            if args.target == "all" or args.check_production_components or args.allow_missing_runner:
                raise BuildError("--prepare-signing requires one target and cannot use production/source-only modes")
            request, candidate, request_sha256, candidate_sha256 = prepare_signing(args)
            print(
                json.dumps(
                    {
                        "schema_version": 1,
                        "signing_request": os.fspath(request),
                        "signing_request_sha256": request_sha256,
                        "unsigned_candidate": os.fspath(candidate),
                        "unsigned_candidate_sha256": candidate_sha256,
                    },
                    sort_keys=True,
                )
            )
            return 0
        if args.candidate_components is not None or args.signing_request_output is not None:
            raise BuildError("signing candidate options require --prepare-signing")
        if args.check_production_components:
            targets = check_production_components(args)
            print(json.dumps({"schema_version": 1, "production_components_ready": True, "targets": targets}))
            return 0
        if args.target == "all":
            raise BuildError("--target all is only valid with --check-production-components")
        output, digest = build(args)
    except (BuildError, sync_sgw_vendor.VendorError, OSError, ValueError, KeyError) as exc:
        print(f"s-gw module build failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"schema_version": 1, "artifact": os.fspath(output), "sha256": digest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
