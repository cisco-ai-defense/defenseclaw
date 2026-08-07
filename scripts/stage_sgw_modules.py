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

"""Stage authenticated s-gw modules for DefenseClaw wheels."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import unicodedata
import urllib.parse
import zipfile
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any

if __package__:
    from scripts import build_sgw_module, sgw_module
else:
    import build_sgw_module  # type: ignore[no-redef]
    import sgw_module  # type: ignore[no-redef]


ROOT = Path(__file__).resolve().parents[1]
TARGETS = sgw_module.TARGETS
BASE_ASSETS = {
    "sgw_module.py": Path("scripts/sgw_module.py"),
    "s-gw-module.json": Path("release/s-gw-module.json"),
}
RUNTIME_ASSET_NAME = "s-gw-runners.json"
RESOURCE_TEMPLATE = "_data/sgw/modules/{target}/s-gw-module.tar.gz"
MAX_DRIVER_BYTES = 2 * 1024 * 1024
MAX_JSON_BYTES = 1024 * 1024
MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024
MAX_SGW_SBOM_BYTES = 256 * 1024 * 1024
MAX_PACKAGE_LOCK_BYTES = 32 * 1024 * 1024
MAX_SOURCE_LICENSE_BYTES = 4 * 1024 * 1024
MAX_CORE_LICENSE_BYTES = 1024 * 1024
MAX_WHEEL_NOTICE_BYTES = 5 * 1024 * 1024
EXPECTED_WHEEL_METADATA = (
    b"Wheel-Version: 1.0\nGenerator: setuptools (82.0.1)\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n"
)
EXPECTED_ENTRY_POINTS = (
    b"[console_scripts]\n"
    b"defenseclaw = defenseclaw.main:main\n"
    b"defenseclaw-observability = defenseclaw.observability.local_stack:main\n"
)
SGW_CORE_LICENSE = "LicenseRef-s-gw-Core"
SGW_MIXED_LICENSE = f"Apache-2.0 AND {SGW_CORE_LICENSE}"
SGW_CORE_LICENSE_BEGIN = f"----- BEGIN {SGW_CORE_LICENSE} -----"
SGW_CORE_LICENSE_END = f"----- END {SGW_CORE_LICENSE} -----"
WHEEL_LICENSE_FILES = ["LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt"]
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
DOS_DEVICE_RE = re.compile(
    r"^(?:CON|PRN|AUX|NUL|CLOCK\$|COM[1-9¹²³]|LPT[1-9¹²³])$",
    re.IGNORECASE,
)
DOS_SHORT_NAME_RE = re.compile(r"^[A-Z0-9_]{1,6}~[1-9][0-9]*(?:\.[A-Z0-9_]{0,3})?$", re.IGNORECASE)
WINDOWS_FORBIDDEN_RE = re.compile(r'[<>"|?*]')
CONTROL_CHARACTER_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class DeliveryError(RuntimeError):
    pass


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0 or metadata.st_size > MAX_ARTIFACT_BYTES:
            raise DeliveryError(f"s-gw module artifact has an invalid size: {path}")
        read_bytes = 0
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            read_bytes += len(chunk)
            if read_bytes > metadata.st_size:
                raise DeliveryError(f"s-gw module artifact changed while hashing: {path}")
            digest.update(chunk)
    if read_bytes != metadata.st_size:
        raise DeliveryError(f"s-gw module artifact changed while hashing: {path}")
    return digest.hexdigest()


def absolute_path(root: Path, value: Path) -> Path:
    candidate = value if value.is_absolute() else root / value
    return Path(os.path.abspath(candidate))


def regular_metadata(path: Path, *, label: str, max_bytes: int) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise DeliveryError(f"{label} is unavailable: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise DeliveryError(f"{label} must be a regular file: {path}")
    if metadata.st_size <= 0 or metadata.st_size > max_bytes:
        raise DeliveryError(f"{label} has an invalid size: {path}")
    return metadata


def regular_file(path: Path, *, label: str, max_bytes: int) -> bytes:
    metadata = regular_metadata(path, label=label, max_bytes=max_bytes)
    try:
        with path.open("rb") as source:
            payload = source.read(max_bytes + 1)
    except OSError as exc:
        raise DeliveryError(f"could not read {label}: {path}") from exc
    if len(payload) != metadata.st_size:
        raise DeliveryError(f"{label} changed while it was read: {path}")
    return payload


def parse_json(payload: bytes, *, label: str) -> dict[str, Any]:
    if len(payload) > MAX_JSON_BYTES:
        raise DeliveryError(f"{label} is too large")
    try:
        value = json.loads(payload, object_pairs_hook=sgw_module.unique_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError, sgw_module.DuplicateJSONKeyError) as exc:
        raise DeliveryError(f"{label} is malformed") from exc
    if not isinstance(value, dict):
        raise DeliveryError(f"{label} must contain one JSON object")
    return value


def sanitized_runtime_manifest(payload: bytes) -> bytes:
    runtime = parse_json(payload, label="s-gw runtime manifest")
    targets = runtime.get("targets")
    if not isinstance(targets, dict) or set(targets) != set(TARGETS):
        raise DeliveryError("s-gw runtime manifest has an invalid target set")
    for target in TARGETS:
        record = targets.get(target)
        components = record.get("components") if isinstance(record, dict) else None
        if not isinstance(components, dict):
            raise DeliveryError(f"s-gw runtime manifest lacks components for {target}")
        for component in components.values():
            if not isinstance(component, dict) or "path" not in component:
                raise DeliveryError(f"s-gw runtime manifest has invalid component metadata for {target}")
            component["path"] = None
    return (json.dumps(runtime, indent=2, sort_keys=True) + "\n").encode("utf-8")


def module_filename(manifest: dict[str, Any], target: str) -> str:
    artifact = manifest.get("artifact")
    if not isinstance(artifact, dict):
        raise DeliveryError("s-gw module manifest lacks its artifact contract")
    if artifact.get("resource_template") != RESOURCE_TEMPLATE or artifact.get("checksum_manifest") != "checksums.txt":
        raise DeliveryError("s-gw module resource contract is incompatible with the CLI")
    template = artifact.get("filename_template")
    if not isinstance(template, str) or not template:
        raise DeliveryError("s-gw module artifact filename template is invalid")
    try:
        filename = template.format(target=target)
    except (KeyError, ValueError) as exc:
        raise DeliveryError("s-gw module artifact filename template is invalid") from exc
    pure = PurePosixPath(filename)
    if len(pure.parts) != 1 or pure.name != filename or not filename.endswith(".tar.gz"):
        raise DeliveryError("s-gw module artifact filename is unsafe")
    return filename


def module_control(
    module_payload: bytes,
    runtime_payload: bytes,
    target: str,
    *,
    require_approved: bool,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    with tempfile.TemporaryDirectory(prefix="defenseclaw-sgw-control-") as temp:
        control = Path(temp)
        module_path = control / "s-gw-module.json"
        runtime_path = control / RUNTIME_ASSET_NAME
        module_path.write_bytes(module_payload)
        runtime_path.write_bytes(runtime_payload)
        try:
            manifest = sgw_module.load_manifest(module_path)
            _runtime, records = sgw_module.component_records(
                module_path,
                manifest,
                target,
                require_approved=require_approved,
            )
        except sgw_module.ModuleError as exc:
            raise DeliveryError(f"s-gw production contract is invalid for {target}: {exc}") from exc
    return manifest, records


def expected_artifacts(artifact_dir: Path, manifest: dict[str, Any]) -> dict[str, tuple[Path, Path]]:
    result: dict[str, tuple[Path, Path]] = {}
    for target in TARGETS:
        artifact = artifact_dir / module_filename(manifest, target)
        result[target] = (artifact, artifact.with_suffix(artifact.suffix + ".sha256"))
    return result


def available_artifacts(expected: dict[str, tuple[Path, Path]]) -> set[str]:
    available: set[str] = set()
    for target, (artifact, checksum) in expected.items():
        if artifact.exists() or artifact.is_symlink() or checksum.exists() or checksum.is_symlink():
            available.add(target)
    return available


def validated_checksum(path: Path, artifact: Path) -> str:
    payload = regular_file(path, label="s-gw module checksum", max_bytes=1024)
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise DeliveryError(f"s-gw module checksum is not ASCII: {path}") from exc
    parts = text.strip().split()
    if len(parts) != 2 or parts[1].lstrip("*") != artifact.name:
        raise DeliveryError(f"s-gw module checksum has an invalid record: {path}")
    expected = parts[0].lower()
    if not sgw_module.SHA256_RE.fullmatch(expected):
        raise DeliveryError(f"s-gw module checksum is invalid: {path}")
    actual = file_digest(artifact)
    if actual != expected:
        raise DeliveryError(f"s-gw module checksum does not match: {artifact}")
    return actual


def validate_module_archive(
    artifact: Path,
    manifest: dict[str, Any],
    target: str,
    records: dict[str, dict[str, Any]],
) -> None:
    with tempfile.TemporaryDirectory(prefix=f"defenseclaw-sgw-verify-{target}-") as temp:
        destination = Path(temp) / "extracted"
        destination.mkdir(mode=0o700)
        try:
            package_root = sgw_module.extract_module_artifact(artifact, destination)
            sgw_module.private_tree(package_root)
            sgw_module.verified_module_metadata(package_root, manifest, target, records)
        except sgw_module.ModuleError as exc:
            raise DeliveryError(f"s-gw module artifact is invalid for {target}: {exc}") from exc


def validate_artifact_set(
    artifact_dir: Path,
    module_payload: bytes,
    runtime_payload: bytes,
) -> tuple[dict[str, str], dict[str, Any]]:
    manifest = parse_json(module_payload, label="s-gw module manifest")
    runtime = parse_json(runtime_payload, label="s-gw runtime manifest")
    expected = expected_artifacts(artifact_dir, manifest)
    digests: dict[str, str] = {}
    controls: dict[str, tuple[dict[str, Any], dict[str, dict[str, Any]]]] = {}
    for target, (artifact, checksum) in expected.items():
        regular_metadata(artifact, label=f"{target} s-gw module", max_bytes=MAX_ARTIFACT_BYTES)
        digests[target] = validated_checksum(checksum, artifact)
        controls[target] = module_control(
            module_payload,
            runtime_payload,
            target,
            require_approved=True,
        )
    for target, (artifact, _checksum) in expected.items():
        reviewed_manifest, records = controls[target]
        validate_module_archive(artifact, reviewed_manifest, target, records)
    return digests, runtime


def verify_component_sources(
    runtime_path: Path,
    manifest: dict[str, Any],
) -> None:
    for target in TARGETS:
        try:
            build_sgw_module.components_for_target(
                runtime_path,
                manifest,
                target,
                allow_missing=False,
            )
        except build_sgw_module.BuildError as exc:
            raise DeliveryError(f"approved s-gw component source is invalid for {target}: {exc}") from exc


def checksum_manifest(digests: dict[str, str]) -> bytes:
    lines = [f"{digests[target]}  modules/{target}/s-gw-module.tar.gz" for target in TARGETS]
    return ("\n".join(lines) + "\n").encode("ascii")


def copy_zip_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    output: Path,
    *,
    max_bytes: int,
) -> None:
    if info.file_size <= 0 or info.file_size > max_bytes:
        raise DeliveryError(f"wheel contains an invalid s-gw member size: {info.filename}")
    copied = 0
    try:
        with archive.open(info, "r") as source, output.open("xb") as target_file:
            while True:
                chunk = source.read(min(1024 * 1024, max_bytes + 1 - copied))
                if not chunk:
                    break
                copied += len(chunk)
                if copied > max_bytes:
                    raise DeliveryError(f"wheel contains an oversized s-gw member: {info.filename}")
                target_file.write(chunk)
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise DeliveryError(f"could not extract wheel s-gw member: {info.filename}") from exc
    if copied != info.file_size:
        raise DeliveryError(f"wheel s-gw member changed size during extraction: {info.filename}")


def populate_destination(
    destination: Path,
    root: Path,
    module_payload: bytes,
    runtime_payload: bytes,
    artifact_dir: Path,
    digests: dict[str, str],
) -> None:
    destination.mkdir(mode=0o700)
    for name, relative in BASE_ASSETS.items():
        source = root / relative
        payload = (
            module_payload
            if name == "s-gw-module.json"
            else regular_file(
                source,
                label=f"s-gw runtime asset {name}",
                max_bytes=MAX_DRIVER_BYTES,
            )
        )
        (destination / name).write_bytes(payload)
    (destination / RUNTIME_ASSET_NAME).write_bytes(runtime_payload)
    if not digests:
        return
    manifest = parse_json(module_payload, label="s-gw module manifest")
    modules = destination / "modules"
    modules.mkdir()
    for target in TARGETS:
        target_dir = modules / target
        target_dir.mkdir()
        source = artifact_dir / module_filename(manifest, target)
        artifact = target_dir / "s-gw-module.tar.gz"
        shutil.copyfile(source, artifact)
        if file_digest(artifact) != digests[target]:
            raise DeliveryError(f"staged s-gw module differs from its authenticated source: {target}")
        sidecar = artifact.with_suffix(artifact.suffix + ".sha256")
        sidecar.write_text(f"{digests[target]}  {artifact.name}\n", encoding="ascii")
    (destination / "checksums.txt").write_bytes(checksum_manifest(digests))


def replace_directory(staged: Path, destination: Path) -> None:
    if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
        raise DeliveryError(f"s-gw staging destination is unsafe: {destination}")
    backup = destination.with_name(f".{destination.name}.{os.getpid()}.old")
    if backup.exists() or backup.is_symlink():
        raise DeliveryError(f"s-gw staging backup already exists: {backup}")
    moved_old = False
    try:
        if destination.exists():
            os.replace(destination, backup)
            moved_old = True
        os.replace(staged, destination)
    except OSError as exc:
        if moved_old and not destination.exists():
            os.replace(backup, destination)
        raise DeliveryError(f"could not publish staged s-gw runtime assets: {exc}") from exc
    if moved_old:
        shutil.rmtree(backup)


def stage(args: argparse.Namespace) -> dict[str, object]:
    root = args.root.resolve(strict=True)
    destination = absolute_path(root, args.destination)
    artifact_dir = absolute_path(root, args.artifact_dir)
    runtime_path = absolute_path(root, args.runtime_manifest)
    module_path = root / BASE_ASSETS["s-gw-module.json"]
    module_payload = regular_file(module_path, label="s-gw module manifest", max_bytes=MAX_JSON_BYTES)
    source_runtime_payload = regular_file(runtime_path, label="s-gw runtime manifest", max_bytes=MAX_JSON_BYTES)
    runtime_payload = sanitized_runtime_manifest(source_runtime_payload)
    manifest = parse_json(module_payload, label="s-gw module manifest")
    parse_json(runtime_payload, label="s-gw runtime manifest")
    driver_payload = regular_file(
        root / BASE_ASSETS["sgw_module.py"],
        label="s-gw runtime driver",
        max_bytes=MAX_DRIVER_BYTES,
    )
    if not driver_payload:
        raise DeliveryError("s-gw runtime driver is empty")
    for target in TARGETS:
        module_control(
            module_payload,
            runtime_payload,
            target,
            require_approved=False,
        )
    expected = expected_artifacts(artifact_dir, manifest)
    present = available_artifacts(expected)
    if present and present != set(TARGETS):
        missing = sorted(set(TARGETS) - present)
        raise DeliveryError(f"s-gw module artifact set is partial; missing targets: {', '.join(missing)}")
    if args.require_all and not present:
        raise DeliveryError("all six authenticated s-gw module artifacts are required")

    digests: dict[str, str] = {}
    if present:
        if artifact_dir.is_symlink() or not artifact_dir.is_dir():
            raise DeliveryError(f"s-gw module artifact directory is unsafe: {artifact_dir}")
        verify_component_sources(runtime_path, manifest)
        digests, _runtime = validate_artifact_set(
            artifact_dir,
            module_payload,
            runtime_payload,
        )

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.stage-", dir=destination.parent))
    payload_root = temporary / "payload"
    try:
        populate_destination(
            payload_root,
            root,
            module_payload,
            runtime_payload,
            artifact_dir,
            digests,
        )
        replace_directory(payload_root, destination)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return {
        "schema_version": 1,
        "destination": os.fspath(destination),
        "production_modules": bool(digests),
        "targets": digests,
    }


def verify_wheel(args: argparse.Namespace) -> dict[str, object]:
    wheel = args.wheel.resolve(strict=True)
    prefix = "defenseclaw/_data/sgw/"
    expected = {f"{prefix}{name}" for name in (*BASE_ASSETS, RUNTIME_ASSET_NAME, "checksums.txt")}
    for target in TARGETS:
        base = f"{prefix}modules/{target}/s-gw-module.tar.gz"
        expected.update({base, f"{base}.sha256"})
    try:
        with zipfile.ZipFile(wheel) as archive:
            infos = _validated_wheel_archive_members(archive)
            names = [info.filename for info in infos]
            observed = {
                name
                for name in names
                if [part.casefold() for part in name.split("/")[:3]] == ["defenseclaw", "_data", "sgw"]
            }
            if observed != expected:
                missing = sorted(expected - observed)
                unexpected = sorted(observed - expected)
                raise DeliveryError(f"wheel s-gw inventory mismatch: missing={missing}, unexpected={unexpected}")
            with tempfile.TemporaryDirectory(prefix="defenseclaw-sgw-wheel-") as temp:
                staged = Path(temp) / "sgw"
                for name in sorted(expected):
                    info = archive.getinfo(name)
                    if not _wheel_member_is_regular(info):
                        raise DeliveryError(f"wheel contains an unsafe s-gw member: {name}")
                    relative = PurePosixPath(name.removeprefix(prefix))
                    output = staged.joinpath(*relative.parts)
                    output.parent.mkdir(parents=True, exist_ok=True)
                    if name.endswith(".tar.gz"):
                        max_bytes = MAX_ARTIFACT_BYTES
                    elif name.endswith((".json", ".sha256")) or name.endswith("checksums.txt"):
                        max_bytes = MAX_JSON_BYTES
                    else:
                        max_bytes = MAX_DRIVER_BYTES
                    copy_zip_member(archive, info, output, max_bytes=max_bytes)
                module_payload = regular_file(
                    staged / "s-gw-module.json",
                    label="wheel s-gw module manifest",
                    max_bytes=MAX_JSON_BYTES,
                )
                runtime_payload = regular_file(
                    staged / RUNTIME_ASSET_NAME,
                    label="wheel s-gw runtime manifest",
                    max_bytes=MAX_JSON_BYTES,
                )
                if runtime_payload != sanitized_runtime_manifest(runtime_payload):
                    raise DeliveryError("wheel s-gw runtime manifest leaks build-source metadata")
                artifact_dir = Path(temp) / "artifacts"
                artifact_dir.mkdir()
                manifest = parse_json(module_payload, label="wheel s-gw module manifest")
                for target in TARGETS:
                    source = staged / "modules" / target / "s-gw-module.tar.gz"
                    destination = artifact_dir / module_filename(manifest, target)
                    source_digest = validated_checksum(
                        source.with_suffix(source.suffix + ".sha256"),
                        source,
                    )
                    shutil.copyfile(source, destination)
                    destination.with_suffix(destination.suffix + ".sha256").write_text(
                        f"{source_digest}  {destination.name}\n",
                        encoding="ascii",
                    )
                digests, _runtime = validate_artifact_set(
                    artifact_dir,
                    module_payload,
                    runtime_payload,
                )
                if (staged / "checksums.txt").read_bytes() != checksum_manifest(digests):
                    raise DeliveryError("wheel s-gw checksum manifest is invalid")
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        raise DeliveryError(f"could not verify s-gw wheel delivery: {exc}") from exc
    return {"schema_version": 1, "wheel": os.fspath(wheel), "targets": digests}


def staged_wheel_license_contract(staged_root: Path) -> tuple[str, str | None]:
    try:
        root_info = staged_root.lstat()
    except OSError as exc:
        raise DeliveryError(f"staged s-gw wheel assets are unavailable: {staged_root}") from exc
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise DeliveryError(f"staged s-gw wheel assets must be a regular directory: {staged_root}")

    observed: set[str] = set()
    for path in staged_root.rglob("*"):
        relative = path.relative_to(staged_root).as_posix()
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
            raise DeliveryError(f"staged s-gw wheel assets contain an unsafe entry: {relative}")
        if stat.S_ISREG(metadata.st_mode):
            observed.add(relative)

    base_files = {*BASE_ASSETS, RUNTIME_ASSET_NAME}
    production_files = {*base_files, "checksums.txt"}
    for target in TARGETS:
        artifact = f"modules/{target}/s-gw-module.tar.gz"
        production_files.update({artifact, f"{artifact}.sha256"})
    if observed not in (base_files, production_files):
        missing = sorted(production_files - observed)
        unexpected = sorted(observed - production_files)
        raise DeliveryError(f"staged s-gw wheel license inventory mismatch: missing={missing}, unexpected={unexpected}")

    module_payload = regular_file(
        staged_root / "s-gw-module.json",
        label="staged s-gw module manifest",
        max_bytes=MAX_JSON_BYTES,
    )
    runtime_payload = regular_file(
        staged_root / RUNTIME_ASSET_NAME,
        label="staged s-gw runtime manifest",
        max_bytes=MAX_JSON_BYTES,
    )
    regular_file(
        staged_root / "sgw_module.py",
        label="staged s-gw runtime driver",
        max_bytes=MAX_DRIVER_BYTES,
    )
    if runtime_payload != sanitized_runtime_manifest(runtime_payload):
        raise DeliveryError("staged s-gw runtime manifest leaks build-source metadata")
    for target in TARGETS:
        module_control(
            module_payload,
            runtime_payload,
            target,
            require_approved=False,
        )
    if observed == base_files:
        return "Apache-2.0", None

    digests: dict[str, str] = {}
    core_terms: str | None = None
    for target in TARGETS:
        artifact = staged_root / "modules" / target / "s-gw-module.tar.gz"
        digests[target] = validated_checksum(
            artifact.with_suffix(artifact.suffix + ".sha256"),
            artifact,
        )
        reviewed_manifest, records = module_control(
            module_payload,
            runtime_payload,
            target,
            require_approved=True,
        )
        with tempfile.TemporaryDirectory(prefix=f"defenseclaw-sgw-license-{target}-") as temp:
            destination = Path(temp) / "expanded"
            destination.mkdir(mode=0o700)
            try:
                package_root = sgw_module.extract_module_artifact(artifact, destination)
                sgw_module.private_tree(package_root)
                metadata, _inventory = sgw_module.verified_module_metadata(
                    package_root,
                    reviewed_manifest,
                    target,
                    records,
                )
            except sgw_module.ModuleError as exc:
                raise DeliveryError(f"{target} s-gw module is invalid for wheel licensing: {exc}") from exc
            target_terms = _core_license_from_module(package_root, metadata, target)
        if core_terms is None:
            core_terms = target_terms
        elif core_terms != target_terms:
            raise DeliveryError("authenticated s-gw Core license terms differ across target modules")

    checksums = regular_file(
        staged_root / "checksums.txt",
        label="staged s-gw checksum manifest",
        max_bytes=MAX_JSON_BYTES,
    )
    if checksums != checksum_manifest(digests):
        raise DeliveryError("staged s-gw checksum manifest is invalid")
    if core_terms is None:
        raise DeliveryError("authenticated s-gw Core license terms are absent from the module set")
    return SGW_MIXED_LICENSE, core_terms


def production_notice(base_notice: bytes, core_terms: str) -> bytes:
    if not base_notice or not base_notice.endswith(b"\n") or b"\r" in base_notice or b"\0" in base_notice:
        raise DeliveryError("the source NOTICE must contain canonical LF text")
    if len(base_notice) > MAX_SOURCE_LICENSE_BYTES:
        raise DeliveryError("the source NOTICE has an invalid size")
    try:
        base_notice.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise DeliveryError("the source NOTICE must be UTF-8") from exc
    if SGW_CORE_LICENSE_BEGIN.encode() in base_notice or SGW_CORE_LICENSE_END.encode() in base_notice:
        raise DeliveryError("the source NOTICE already carries s-gw Core license terms")
    terms = validated_core_license_text(core_terms)
    payload = (
        base_notice
        + b"\n"
        + SGW_CORE_LICENSE_BEGIN.encode("ascii")
        + b"\n"
        + terms.encode("utf-8")
        + b"\n"
        + SGW_CORE_LICENSE_END.encode("ascii")
        + b"\n"
    )
    if len(payload) > MAX_WHEEL_NOTICE_BYTES:
        raise DeliveryError("the production wheel NOTICE has an invalid size")
    return payload


def materialize_wheel_license_metadata(args: argparse.Namespace) -> dict[str, Any]:
    staged_root = absolute_path(Path.cwd(), args.staged_root)
    output = absolute_path(Path.cwd(), args.output)
    base_notice_path = absolute_path(Path.cwd(), args.base_notice)
    if output.name != "NOTICE":
        raise DeliveryError("the wheel NOTICE file name is invalid")
    base_notice = regular_file(
        base_notice_path,
        label="source NOTICE",
        max_bytes=MAX_SOURCE_LICENSE_BYTES,
    )
    current_notice = regular_file(
        output,
        label="wheel NOTICE",
        max_bytes=MAX_WHEEL_NOTICE_BYTES,
    )
    expression, core_terms = staged_wheel_license_contract(staged_root)
    if core_terms is None:
        if current_notice != base_notice:
            raise DeliveryError("source-only wheel NOTICE differs from the source NOTICE")
        return {
            "schema_version": 1,
            "production_modules": False,
            "license_expression": expression,
            "license_file": None,
            "license_sha256": None,
        }

    payload = production_notice(base_notice, core_terms)
    if current_notice == payload:
        return {
            "schema_version": 1,
            "production_modules": True,
            "license_expression": expression,
            "license_file": output.name,
            "license_sha256": hashlib.sha256(payload).hexdigest(),
        }
    if current_notice != base_notice:
        raise DeliveryError("production wheel NOTICE is neither the source nor approved final payload")
    if getattr(args, "validate_only", False):
        raise DeliveryError("prepared wheel NOTICE does not match the requested s-gw module mode")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.",
        suffix=".tmp",
        dir=output.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as target:
            target.write(payload)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, output)
    except OSError as exc:
        raise DeliveryError(f"could not write the production wheel NOTICE: {output}") from exc
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "schema_version": 1,
        "production_modules": True,
        "license_expression": expression,
        "license_file": output.name,
        "license_sha256": hashlib.sha256(payload).hexdigest(),
    }


def _spdx_id(kind: str, identity: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9.-]+", "-", identity).strip("-.")[:72] or "item"
    suffix = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
    return f"SPDXRef-{kind}-{slug}-{suffix}"


def _stream_digests(source: Any) -> tuple[str, str]:
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()  # noqa: S324 - SPDX package verification codes require SHA-1.
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        sha256.update(chunk)
        sha1.update(chunk)
    return sha256.hexdigest(), sha1.hexdigest()


def _path_digests(path: Path, *, label: str, max_bytes: int) -> tuple[str, str]:
    metadata = regular_metadata(path, label=label, max_bytes=max_bytes)
    try:
        with path.open("rb") as source:
            opened = os.fstat(source.fileno())
            result = _stream_digests(source)
            after = os.fstat(source.fileno())
    except OSError as exc:
        raise DeliveryError(f"could not hash {label}: {path}") from exc
    if (
        opened.st_dev != metadata.st_dev
        or opened.st_ino != metadata.st_ino
        or opened.st_size != metadata.st_size
        or opened.st_mtime_ns != metadata.st_mtime_ns
        or after.st_size != opened.st_size
        or after.st_mtime_ns != opened.st_mtime_ns
    ):
        raise DeliveryError(f"{label} changed while it was hashed: {path}")
    return result


def _strict_json_file(path: Path, *, label: str, max_bytes: int) -> dict[str, Any]:
    payload = regular_file(path, label=label, max_bytes=max_bytes)
    try:
        result = json.loads(payload, object_pairs_hook=sgw_module.unique_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError, sgw_module.DuplicateJSONKeyError) as exc:
        raise DeliveryError(f"{label} is malformed") from exc
    if not isinstance(result, dict):
        raise DeliveryError(f"{label} must contain one JSON object")
    return result


def _spdx_license(value: object) -> tuple[str, str | None]:
    if value is None:
        return "NOASSERTION", None
    if not isinstance(value, str) or not value.strip():
        raise DeliveryError("s-gw npm package carries malformed license metadata")
    raw = value.strip()
    if raw.upper() == "UNLICENSED":
        return "NOASSERTION", raw
    aliases = {
        "Apache 2.0": "Apache-2.0",
        "Apache License 2.0": "Apache-2.0",
        "BSD": "BSD-3-Clause",
        "MIT License": "MIT",
    }
    normalized = aliases.get(raw, raw)
    if re.fullmatch(r"[A-Za-z0-9.+-]+(?:\s+(?:AND|OR|WITH)\s+[A-Za-z0-9.+-]+)*", normalized):
        return normalized, None
    return "NOASSERTION", raw


class SgwSpdxDocument:
    def __init__(self, *, version: str, commit: str, created: str, wheel_sha256: str):
        self.version = version
        self.commit = commit
        self.created = created
        self.wheel_sha256 = wheel_sha256
        self.packages: dict[str, dict[str, Any]] = {}
        self.files: dict[str, dict[str, Any]] = {}
        self.file_sha1: dict[str, str] = {}
        self.package_files: dict[str, set[str]] = {}
        self.relationships: set[tuple[str, str, str]] = set()
        self.described: list[str] = []
        self.core_license_text: str | None = None

    def add_file(self, logical_name: str, sha256: str, sha1: str) -> str:
        if not logical_name.startswith("./sgw/") or not SHA256_RE.fullmatch(sha256):
            raise DeliveryError(f"invalid s-gw SPDX file identity: {logical_name}")
        file_id = _spdx_id("File", logical_name)
        record = {
            "SPDXID": file_id,
            "fileName": logical_name,
            "checksums": [
                {"algorithm": "SHA1", "checksumValue": sha1},
                {"algorithm": "SHA256", "checksumValue": sha256},
            ],
            "licenseConcluded": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
        previous = self.files.get(file_id)
        if previous is not None and previous != record:
            raise DeliveryError(f"conflicting s-gw SPDX file identity: {logical_name}")
        self.files[file_id] = record
        self.file_sha1[file_id] = sha1
        return file_id

    def add_package(
        self,
        identity: str,
        *,
        name: str,
        version: str | None,
        purpose: str,
        license_declared: str,
        comment: str,
        checksum: str | None = None,
        package_file_name: str | None = None,
        purl: str | None = None,
        license_comment: str | None = None,
        files_analyzed: bool = True,
    ) -> str:
        package_id = _spdx_id("Package", identity)
        record: dict[str, Any] = {
            "SPDXID": package_id,
            "name": name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": files_analyzed,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": license_declared,
            "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": purpose,
            "comment": comment,
        }
        if version:
            record["versionInfo"] = version
        if checksum:
            if not SHA256_RE.fullmatch(checksum):
                raise DeliveryError(f"invalid s-gw SPDX package checksum: {name}")
            record["checksums"] = [{"algorithm": "SHA256", "checksumValue": checksum}]
        if package_file_name:
            record["packageFileName"] = package_file_name
        if purl:
            record["externalRefs"] = [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": purl,
                }
            ]
        if license_comment:
            record["licenseComments"] = license_comment
        previous = self.packages.get(package_id)
        if previous is not None and previous != record:
            raise DeliveryError(f"conflicting s-gw SPDX package identity: {name}")
        self.packages[package_id] = record
        self.package_files.setdefault(package_id, set())
        return package_id

    def relate(self, source: str, relationship: str, target: str) -> None:
        self.relationships.add((source, relationship, target))

    def contains_file(self, package_id: str, file_id: str) -> None:
        self.package_files.setdefault(package_id, set()).add(file_id)
        self.relate(package_id, "CONTAINS", file_id)

    def render(self) -> dict[str, Any]:
        if self.core_license_text is None:
            raise DeliveryError("authenticated s-gw Core license terms are absent from the module set")
        for package_id, package in self.packages.items():
            hashes = sorted(self.file_sha1[file_id] for file_id in self.package_files.get(package_id, set()))
            if package["filesAnalyzed"] and not hashes:
                raise DeliveryError(f"s-gw SPDX package has no analyzed files: {package['name']}")
            if hashes:
                verification = hashlib.sha1("".join(hashes).encode("ascii")).hexdigest()  # noqa: S324
                package["packageVerificationCode"] = {"packageVerificationCodeValue": verification}
        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"DefenseClaw s-gw runtime modules {self.version}",
            "documentNamespace": (
                "https://github.com/cisco-ai-defense/defenseclaw/"
                f"spdx/sgw/{urllib.parse.quote(self.version, safe='-._~')}/{self.wheel_sha256}"
            ),
            "comment": f"DefenseClaw source commit: {self.commit}",
            "creationInfo": {
                "created": self.created,
                "creators": [
                    "Organization: Cisco Systems, Inc.",
                    "Tool: DefenseClaw s-gw SBOM generator",
                ],
                "licenseListVersion": "3.25",
            },
            "documentDescribes": sorted(self.described),
            "hasExtractedLicensingInfos": [
                {
                    "licenseId": SGW_CORE_LICENSE,
                    "name": "s-gw Core runtime license",
                    "extractedText": self.core_license_text,
                }
            ],
            "packages": sorted(self.packages.values(), key=lambda item: item["SPDXID"]),
            "files": sorted(self.files.values(), key=lambda item: item["fileName"].encode("utf-8")),
            "relationships": [
                {
                    "spdxElementId": source,
                    "relationshipType": relationship,
                    "relatedSpdxElement": target,
                }
                for source, relationship, target in sorted(self.relationships)
            ],
        }


def _wheel_version(archive: zipfile.ZipFile) -> str:
    metadata = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
    if len(metadata) != 1:
        raise DeliveryError("DefenseClaw wheel must contain exactly one distribution metadata file")
    info = archive.getinfo(metadata[0])
    if not _wheel_member_is_regular(info) or info.file_size <= 0 or info.file_size > MAX_JSON_BYTES:
        raise DeliveryError("DefenseClaw wheel distribution metadata has an invalid size")
    document = BytesParser(policy=policy.default).parsebytes(archive.read(info))
    if (document.get("Name") or "").strip().lower() != "defenseclaw":
        raise DeliveryError("DefenseClaw wheel distribution identity is invalid")
    version = (document.get("Version") or "").strip()
    if not version:
        raise DeliveryError("DefenseClaw wheel distribution version is missing")
    return version


def _validated_wheel_member_identity(raw_name: str) -> tuple[str, bool]:
    if not raw_name:
        raise DeliveryError("DefenseClaw wheel contains a non-canonical wheel member path: empty name")
    if "\\" in raw_name or raw_name.startswith("/") or ":" in raw_name:
        raise DeliveryError(f"DefenseClaw wheel contains a non-canonical wheel member path: {raw_name}")
    if CONTROL_CHARACTER_RE.search(raw_name):
        raise DeliveryError(f"DefenseClaw wheel contains a non-canonical wheel member path: {raw_name}")
    if unicodedata.normalize("NFC", raw_name) != raw_name:
        raise DeliveryError(f"DefenseClaw wheel contains a non-canonical wheel member path: {raw_name}")

    is_directory = raw_name.endswith("/")
    identity = raw_name[:-1] if is_directory else raw_name
    if not identity or "//" in identity:
        raise DeliveryError(f"DefenseClaw wheel contains a non-canonical wheel member path: {raw_name}")
    for component in identity.split("/"):
        if not component or component in {".", ".."}:
            raise DeliveryError(f"DefenseClaw wheel contains a non-canonical wheel member path: {raw_name}")
        if WINDOWS_FORBIDDEN_RE.search(component) or component.endswith((".", " ")):
            raise DeliveryError(f"DefenseClaw wheel contains a non-canonical wheel member path: {raw_name}")
        stem = component.split(".", 1)[0].rstrip(" .")
        if DOS_DEVICE_RE.fullmatch(stem) or DOS_SHORT_NAME_RE.fullmatch(component):
            raise DeliveryError(f"DefenseClaw wheel contains a non-canonical wheel member path: {raw_name}")
    return identity, is_directory


def _wheel_member_is_regular(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    file_type = stat.S_IFMT(mode)
    unsafe_dos_attributes = 0x10 | 0x400
    return not info.is_dir() and not (info.external_attr & unsafe_dos_attributes) and file_type in {0, stat.S_IFREG}


def _validated_wheel_archive_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    infos = archive.infolist()
    if not infos or len(infos) > sgw_module.MAX_ARCHIVE_FILES:
        raise DeliveryError("DefenseClaw wheel has an invalid member count")

    names = [info.filename for info in infos]
    if len(names) != len(set(names)):
        raise DeliveryError("wheel contains duplicate members")

    identities: dict[str, str] = {}
    prefix_spellings: dict[tuple[str, ...], tuple[str, ...]] = {}
    file_paths: set[tuple[str, ...]] = set()
    parent_paths: set[tuple[str, ...]] = set()
    total = 0
    for info in infos:
        if info.orig_filename != info.filename:
            raise DeliveryError(f"DefenseClaw wheel contains a non-canonical wheel member path: {info.orig_filename}")
        identity, is_directory = _validated_wheel_member_identity(info.filename)
        folded = unicodedata.normalize("NFC", identity).casefold()
        prior = identities.get(folded)
        if prior is not None:
            raise DeliveryError(f"DefenseClaw wheel contains case-insensitive member aliases: {prior}, {info.filename}")
        identities[folded] = info.filename

        exact_parts = tuple(identity.split("/"))
        folded_parts = tuple(unicodedata.normalize("NFC", part).casefold() for part in exact_parts)
        for depth in range(1, len(folded_parts) + 1):
            prefix = folded_parts[:depth]
            spelling = exact_parts[:depth]
            prior_spelling = prefix_spellings.get(prefix)
            if prior_spelling is not None and prior_spelling != spelling:
                raise DeliveryError(
                    "DefenseClaw wheel contains case-insensitive hierarchy aliases: "
                    f"{'/'.join(prior_spelling)}, {'/'.join(spelling)}"
                )
            prefix_spellings[prefix] = spelling
            if depth < len(folded_parts):
                if prefix in file_paths:
                    raise DeliveryError(
                        f"DefenseClaw wheel contains a regular-file member used as a directory: {'/'.join(spelling)}"
                    )
                parent_paths.add(prefix)
        if not is_directory:
            if folded_parts in parent_paths:
                raise DeliveryError(
                    f"DefenseClaw wheel contains a regular-file member used as a directory: {info.filename}"
                )
            file_paths.add(folded_parts)

        mode = info.external_attr >> 16
        file_type = stat.S_IFMT(mode)
        if is_directory:
            if info.external_attr & 0x400 or info.file_size != 0 or file_type not in {0, stat.S_IFDIR}:
                raise DeliveryError(f"DefenseClaw wheel contains an unsafe member type: {info.filename}")
            continue
        if not _wheel_member_is_regular(info):
            raise DeliveryError(f"DefenseClaw wheel contains an unsafe member type: {info.filename}")
        if info.flag_bits & 0x1:
            raise DeliveryError(f"DefenseClaw wheel contains an encrypted member: {info.filename}")
        if info.file_size < 0 or info.file_size > sgw_module.MAX_ARCHIVE_FILE_BYTES:
            raise DeliveryError(f"DefenseClaw wheel member has an invalid size: {info.filename}")
        total += info.file_size
        if total > sgw_module.MAX_ARCHIVE_TOTAL_BYTES:
            raise DeliveryError("DefenseClaw wheel expands beyond the allowed size")
    return infos


def _wheel_member_sha256(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    with archive.open(info, "r") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            total += len(chunk)
            if total > info.file_size:
                raise DeliveryError(f"DefenseClaw wheel member changed while it was read: {info.filename}")
            digest.update(chunk)
    if total != info.file_size:
        raise DeliveryError(f"DefenseClaw wheel member changed while it was read: {info.filename}")
    encoded = base64.urlsafe_b64encode(digest.digest()).rstrip(b"=").decode("ascii")
    return encoded, total


def _single_metadata_header(metadata: Any, name: str, *, message: str) -> str:
    values = metadata.get_all(name, [])
    if len(values) != 1:
        raise DeliveryError(message)
    return values[0].strip()


def _validated_operational_wheel_metadata(
    archive: zipfile.ZipFile,
    *,
    names: list[str],
    dist_info: PurePosixPath,
) -> dict[str, bytes]:
    expected = {
        f"{dist_info.as_posix()}/WHEEL": EXPECTED_WHEEL_METADATA,
        f"{dist_info.as_posix()}/entry_points.txt": EXPECTED_ENTRY_POINTS,
    }
    for canonical, payload in expected.items():
        suffix = "/" + PurePosixPath(canonical).name.casefold()
        observed = [name for name in names if name.casefold().endswith(f".dist-info{suffix}")]
        if observed != [canonical]:
            raise DeliveryError(f"DefenseClaw wheel operational metadata is incomplete: {canonical}")
        info = archive.getinfo(canonical)
        if not _wheel_member_is_regular(info) or info.file_size != len(payload):
            raise DeliveryError(f"DefenseClaw wheel operational metadata is unsafe: {canonical}")
        if archive.read(info) != payload:
            raise DeliveryError(f"DefenseClaw wheel operational metadata is inconsistent: {canonical}")
    return expected


def _validate_recorded_wheel_members(
    archive: zipfile.ZipFile,
    *,
    dist_info: PurePosixPath,
    members: dict[str, bytes],
    require_complete: bool = False,
) -> None:
    record_name = f"{dist_info.as_posix()}/RECORD"
    if archive.namelist().count(record_name) != 1:
        raise DeliveryError("DefenseClaw production wheel must contain exactly one RECORD")
    info = archive.getinfo(record_name)
    if not _wheel_member_is_regular(info) or info.file_size <= 0 or info.file_size > MAX_JSON_BYTES:
        raise DeliveryError("DefenseClaw production wheel RECORD is unsafe")
    record_payload = archive.read(info)
    if len(record_payload) != info.file_size or b"\0" in record_payload:
        raise DeliveryError("DefenseClaw production wheel RECORD is malformed")
    try:
        rows = list(
            csv.reader(
                io.StringIO(record_payload.decode("utf-8", errors="strict"), newline=""),
                strict=True,
            )
        )
    except (UnicodeDecodeError, csv.Error) as exc:
        raise DeliveryError("DefenseClaw production wheel RECORD is malformed") from exc
    if any(len(row) != 3 for row in rows) or len({row[0] for row in rows}) != len(rows):
        raise DeliveryError("DefenseClaw production wheel RECORD is malformed")
    by_name = {row[0]: row for row in rows}
    for member_name, payload in members.items():
        row = by_name.get(member_name)
        if row is None:
            raise DeliveryError(f"DefenseClaw production wheel member is absent from RECORD: {member_name}")
        digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode("ascii")
        if row[1:] != [f"sha256={digest}", str(len(payload))]:
            raise DeliveryError(f"DefenseClaw production wheel RECORD entry is inconsistent: {member_name}")

    if require_complete:
        files = {info.filename: info for info in archive.infolist() if not info.is_dir()}
        if set(by_name) != set(files):
            raise DeliveryError("DefenseClaw wheel RECORD inventory is incomplete or contains unexpected members")
        if by_name.get(record_name, [None, None, None])[1:] != ["", ""]:
            raise DeliveryError("DefenseClaw wheel RECORD entry for RECORD is inconsistent")
        for member_name, member_info in files.items():
            if member_name == record_name:
                continue
            digest, size = _wheel_member_sha256(archive, member_info)
            if by_name[member_name][1:] != [f"sha256={digest}", str(size)]:
                raise DeliveryError(f"DefenseClaw production wheel RECORD entry is inconsistent: {member_name}")


def _validate_wheel_license_metadata(wheel: Path, *, version: str, core_terms: str) -> None:
    base_notice = regular_file(
        ROOT / "NOTICE",
        label="source NOTICE",
        max_bytes=MAX_SOURCE_LICENSE_BYTES,
    )
    source_third_party = regular_file(
        ROOT / "THIRD_PARTY_LICENSES.txt",
        label="source THIRD_PARTY_LICENSES.txt",
        max_bytes=MAX_SOURCE_LICENSE_BYTES,
    )
    expected_payload = production_notice(base_notice, core_terms)
    try:
        with zipfile.ZipFile(wheel) as archive:
            infos = _validated_wheel_archive_members(archive)
            names = [info.filename for info in infos]
            expected_metadata_name = f"defenseclaw-{version}.dist-info/METADATA"
            metadata_names = [name for name in names if name.casefold().endswith(".dist-info/metadata")]
            if metadata_names != [expected_metadata_name]:
                raise DeliveryError("DefenseClaw wheel must contain exactly one distribution metadata file")
            metadata_name = expected_metadata_name
            metadata_info = archive.getinfo(metadata_name)
            if (
                not _wheel_member_is_regular(metadata_info)
                or metadata_info.file_size <= 0
                or metadata_info.file_size > MAX_JSON_BYTES
            ):
                raise DeliveryError("DefenseClaw wheel distribution metadata is unsafe")
            metadata_payload = archive.read(metadata_info)
            if (
                len(metadata_payload) != metadata_info.file_size
                or b"\r" in metadata_payload
                or b"\0" in metadata_payload
            ):
                raise DeliveryError("DefenseClaw wheel distribution metadata is not canonical LF text")
            metadata = BytesParser(policy=policy.default).parsebytes(metadata_payload)
            if metadata.defects:
                raise DeliveryError("DefenseClaw wheel distribution metadata is malformed")
            distribution_name = _single_metadata_header(
                metadata,
                "Name",
                message="DefenseClaw wheel distribution identity is invalid",
            )
            if distribution_name.lower() != "defenseclaw":
                raise DeliveryError("DefenseClaw wheel distribution identity is invalid")
            distribution_version = _single_metadata_header(
                metadata,
                "Version",
                message="DefenseClaw wheel distribution version is inconsistent",
            )
            if distribution_version != version:
                raise DeliveryError("DefenseClaw wheel distribution version is inconsistent")
            if metadata.get_all("License"):
                raise DeliveryError("DefenseClaw production wheel carries legacy License metadata")
            expressions = metadata.get_all("License-Expression", [])
            if expressions != [SGW_MIXED_LICENSE]:
                raise DeliveryError("DefenseClaw production wheel license expression is inconsistent")
            license_files = metadata.get_all("License-File", [])
            if sorted(license_files) != WHEEL_LICENSE_FILES:
                raise DeliveryError("DefenseClaw production wheel license file headers are inconsistent")

            dist_info = PurePosixPath(metadata_name).parent
            operational_metadata = _validated_operational_wheel_metadata(
                archive,
                names=names,
                dist_info=dist_info,
            )
            license_member = f"{dist_info.as_posix()}/licenses/LICENSE"
            license_name = f"{dist_info.as_posix()}/licenses/NOTICE"
            third_party_name = f"{dist_info.as_posix()}/licenses/THIRD_PARTY_LICENSES.txt"
            if any(names.count(name) != 1 for name in (license_member, license_name, third_party_name)):
                raise DeliveryError("DefenseClaw production wheel lacks its exact license files")
            source_license = regular_file(
                ROOT / "LICENSE",
                label="source LICENSE",
                max_bytes=MAX_SOURCE_LICENSE_BYTES,
            )
            license_file_info = archive.getinfo(license_member)
            if not _wheel_member_is_regular(license_file_info) or license_file_info.file_size != len(source_license):
                raise DeliveryError("DefenseClaw production wheel LICENSE file is unsafe")
            license_payload = archive.read(license_file_info)
            if license_payload != source_license:
                raise DeliveryError("DefenseClaw production wheel LICENSE differs from the source LICENSE")
            license_info = archive.getinfo(license_name)
            if (
                not _wheel_member_is_regular(license_info)
                or license_info.file_size <= 0
                or license_info.file_size > MAX_WHEEL_NOTICE_BYTES
            ):
                raise DeliveryError("DefenseClaw production wheel NOTICE file is unsafe")
            payload = archive.read(license_info)
            if payload != expected_payload or len(payload) != license_info.file_size:
                raise DeliveryError(
                    "DefenseClaw production wheel NOTICE differs from source or authenticated s-gw Core terms"
                )
            third_party_info = archive.getinfo(third_party_name)
            if not _wheel_member_is_regular(third_party_info) or third_party_info.file_size != len(source_third_party):
                raise DeliveryError("DefenseClaw production wheel THIRD_PARTY_LICENSES.txt file is unsafe")
            third_party_payload = archive.read(third_party_info)
            if third_party_payload != source_third_party:
                raise DeliveryError(
                    "DefenseClaw production wheel THIRD_PARTY_LICENSES.txt differs from the source"
                )
            _validate_recorded_wheel_members(
                archive,
                dist_info=dist_info,
                members={
                    metadata_name: metadata_payload,
                    license_member: license_payload,
                    license_name: payload,
                    third_party_name: third_party_payload,
                    **operational_metadata,
                },
                require_complete=True,
            )
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        raise DeliveryError(f"could not validate DefenseClaw wheel licensing: {exc}") from exc


def validate_source_only_wheel(wheel: Path, *, version: str) -> dict[str, Any]:
    wheel = wheel.resolve(strict=True)
    prefix = "defenseclaw/_data/sgw/"
    expected_sgw = {f"{prefix}{name}" for name in (*BASE_ASSETS, RUNTIME_ASSET_NAME)}
    source_license = regular_file(
        ROOT / "LICENSE",
        label="source LICENSE",
        max_bytes=MAX_SOURCE_LICENSE_BYTES,
    )
    source_notice = regular_file(
        ROOT / "NOTICE",
        label="source NOTICE",
        max_bytes=MAX_SOURCE_LICENSE_BYTES,
    )
    source_third_party = regular_file(
        ROOT / "THIRD_PARTY_LICENSES.txt",
        label="source THIRD_PARTY_LICENSES.txt",
        max_bytes=MAX_SOURCE_LICENSE_BYTES,
    )
    expected_payloads = {
        f"{prefix}sgw_module.py": regular_file(
            ROOT / BASE_ASSETS["sgw_module.py"],
            label="source s-gw runtime driver",
            max_bytes=MAX_DRIVER_BYTES,
        ),
        f"{prefix}s-gw-module.json": regular_file(
            ROOT / BASE_ASSETS["s-gw-module.json"],
            label="source s-gw module manifest",
            max_bytes=MAX_JSON_BYTES,
        ),
        f"{prefix}{RUNTIME_ASSET_NAME}": sanitized_runtime_manifest(
            regular_file(
                ROOT / "release" / RUNTIME_ASSET_NAME,
                label="source s-gw runtime manifest",
                max_bytes=MAX_JSON_BYTES,
            )
        ),
    }

    try:
        with zipfile.ZipFile(wheel) as archive:
            infos = _validated_wheel_archive_members(archive)
            names = [info.filename for info in infos]
            observed_sgw = {
                name
                for name in names
                if [part.casefold() for part in name.split("/")[:3]] == ["defenseclaw", "_data", "sgw"]
            }
            if observed_sgw != expected_sgw:
                missing = sorted(expected_sgw - observed_sgw)
                unexpected = sorted(observed_sgw - expected_sgw)
                raise DeliveryError(
                    f"source-only wheel s-gw inventory mismatch: missing={missing}, unexpected={unexpected}"
                )

            recorded: dict[str, bytes] = {}
            for name, expected in expected_payloads.items():
                info = archive.getinfo(name)
                if (
                    not _wheel_member_is_regular(info)
                    or info.file_size <= 0
                    or info.file_size > max(MAX_DRIVER_BYTES, MAX_JSON_BYTES)
                ):
                    raise DeliveryError(f"source-only wheel contains an unsafe s-gw member: {name}")
                payload = archive.read(info)
                if len(payload) != info.file_size or payload != expected:
                    raise DeliveryError(f"source-only wheel s-gw member differs from reviewed source: {name}")
                recorded[name] = payload

            expected_metadata_name = f"defenseclaw-{version}.dist-info/METADATA"
            metadata_names = [name for name in names if name.casefold().endswith(".dist-info/metadata")]
            if metadata_names != [expected_metadata_name]:
                raise DeliveryError("DefenseClaw wheel must contain exactly one distribution metadata file")
            metadata_name = expected_metadata_name
            metadata_info = archive.getinfo(metadata_name)
            if (
                not _wheel_member_is_regular(metadata_info)
                or metadata_info.file_size <= 0
                or metadata_info.file_size > MAX_JSON_BYTES
            ):
                raise DeliveryError("DefenseClaw wheel distribution metadata is unsafe")
            metadata_payload = archive.read(metadata_info)
            if (
                len(metadata_payload) != metadata_info.file_size
                or b"\r" in metadata_payload
                or b"\0" in metadata_payload
            ):
                raise DeliveryError("DefenseClaw wheel distribution metadata is not canonical LF text")
            metadata = BytesParser(policy=policy.default).parsebytes(metadata_payload)
            if metadata.defects:
                raise DeliveryError("DefenseClaw wheel distribution metadata is malformed")
            distribution_name = _single_metadata_header(
                metadata,
                "Name",
                message="DefenseClaw wheel distribution identity is invalid",
            )
            if distribution_name.lower() != "defenseclaw":
                raise DeliveryError("DefenseClaw wheel distribution identity is invalid")
            distribution_version = _single_metadata_header(
                metadata,
                "Version",
                message="DefenseClaw wheel distribution version is inconsistent",
            )
            if distribution_version != version:
                raise DeliveryError("DefenseClaw wheel distribution version is inconsistent")
            if metadata.get_all("License"):
                raise DeliveryError("DefenseClaw source-only wheel carries legacy License metadata")
            if metadata.get_all("License-Expression", []) != ["Apache-2.0"]:
                raise DeliveryError("DefenseClaw source-only wheel license expression is inconsistent")
            if sorted(metadata.get_all("License-File", [])) != WHEEL_LICENSE_FILES:
                raise DeliveryError("DefenseClaw source-only wheel license file headers are inconsistent")

            dist_info = PurePosixPath(metadata_name).parent
            recorded.update(
                _validated_operational_wheel_metadata(
                    archive,
                    names=names,
                    dist_info=dist_info,
                )
            )
            license_name = f"{dist_info.as_posix()}/licenses/LICENSE"
            notice_name = f"{dist_info.as_posix()}/licenses/NOTICE"
            third_party_name = f"{dist_info.as_posix()}/licenses/THIRD_PARTY_LICENSES.txt"
            license_payloads = (
                (license_name, source_license),
                (notice_name, source_notice),
                (third_party_name, source_third_party),
            )
            if any(names.count(name) != 1 for name, _ in license_payloads):
                raise DeliveryError("DefenseClaw source-only wheel lacks its exact license files")
            for name, expected in license_payloads:
                info = archive.getinfo(name)
                if not _wheel_member_is_regular(info) or info.file_size != len(expected):
                    raise DeliveryError(f"DefenseClaw source-only wheel {PurePosixPath(name).name} file is unsafe")
                payload = archive.read(info)
                if len(payload) != info.file_size or payload != expected:
                    raise DeliveryError(
                        f"DefenseClaw source-only wheel {PurePosixPath(name).name} differs from the source"
                    )
                recorded[name] = payload
            recorded[metadata_name] = metadata_payload
            _validate_recorded_wheel_members(
                archive,
                dist_info=dist_info,
                members=recorded,
                require_complete=True,
            )
    except (OSError, NotImplementedError, zipfile.BadZipFile, KeyError) as exc:
        raise DeliveryError(f"could not validate DefenseClaw source-only wheel: {exc}") from exc

    return {
        "schema_version": 1,
        "wheel": os.fspath(wheel),
        "version": version,
        "production_modules": False,
    }


def _copy_sgw_wheel_inputs(wheel: Path, destination: Path) -> tuple[Path, bytes, bytes]:
    prefix = "defenseclaw/_data/sgw/"
    expected = {
        f"{prefix}sgw_module.py",
        f"{prefix}s-gw-module.json",
        f"{prefix}{RUNTIME_ASSET_NAME}",
        f"{prefix}checksums.txt",
    }
    for target in TARGETS:
        artifact_name = f"{prefix}modules/{target}/s-gw-module.tar.gz"
        expected.update({artifact_name, f"{artifact_name}.sha256"})
    destination.mkdir(mode=0o700)
    try:
        with zipfile.ZipFile(wheel) as archive:
            infos = _validated_wheel_archive_members(archive)
            observed = {
                info.filename
                for info in infos
                if [part.casefold() for part in info.filename.split("/")[:3]] == ["defenseclaw", "_data", "sgw"]
            }
            if observed != expected:
                raise DeliveryError("wheel s-gw inventory is incomplete or contains unexpected members")
            module_name = f"{prefix}s-gw-module.json"
            runtime_name = f"{prefix}{RUNTIME_ASSET_NAME}"
            for name in (module_name, runtime_name, f"{prefix}checksums.txt"):
                info = archive.getinfo(name)
                if not _wheel_member_is_regular(info):
                    raise DeliveryError(f"wheel contains an unsafe s-gw member: {name}")
                output = destination / PurePosixPath(name).name
                copy_zip_member(archive, info, output, max_bytes=MAX_JSON_BYTES)
            modules = destination / "modules"
            modules.mkdir()
            for target in TARGETS:
                name = f"{prefix}modules/{target}/s-gw-module.tar.gz"
                info = archive.getinfo(name)
                if not _wheel_member_is_regular(info):
                    raise DeliveryError(f"wheel contains an unsafe s-gw member: {name}")
                target_dir = modules / target
                target_dir.mkdir()
                copy_zip_member(
                    archive,
                    info,
                    target_dir / "s-gw-module.tar.gz",
                    max_bytes=MAX_ARTIFACT_BYTES,
                )
                checksum_name = f"{name}.sha256"
                checksum_info = archive.getinfo(checksum_name)
                if not _wheel_member_is_regular(checksum_info):
                    raise DeliveryError(f"wheel contains an unsafe s-gw member: {checksum_name}")
                copy_zip_member(
                    archive,
                    checksum_info,
                    target_dir / "s-gw-module.tar.gz.sha256",
                    max_bytes=1024,
                )
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        raise DeliveryError(f"could not read s-gw wheel inventory: {exc}") from exc
    module_payload = regular_file(
        destination / "s-gw-module.json",
        label="wheel s-gw module manifest",
        max_bytes=MAX_JSON_BYTES,
    )
    runtime_payload = regular_file(
        destination / RUNTIME_ASSET_NAME,
        label="wheel s-gw runtime manifest",
        max_bytes=MAX_JSON_BYTES,
    )
    if runtime_payload != sanitized_runtime_manifest(runtime_payload):
        raise DeliveryError("wheel s-gw runtime manifest leaks build-source metadata")
    digests: dict[str, str] = {}
    for target in TARGETS:
        artifact = modules / target / "s-gw-module.tar.gz"
        digests[target] = validated_checksum(
            artifact.with_suffix(artifact.suffix + ".sha256"),
            artifact,
        )
    checksums = regular_file(
        destination / "checksums.txt",
        label="wheel s-gw checksum manifest",
        max_bytes=MAX_JSON_BYTES,
    )
    if checksums != checksum_manifest(digests):
        raise DeliveryError("wheel s-gw checksum manifest is invalid")
    return modules, module_payload, runtime_payload


def _module_file_inventory(package_root: Path) -> dict[str, tuple[str, str, Path]]:
    result: dict[str, tuple[str, str, Path]] = {}
    total = 0
    for path in sorted(package_root.rglob("*"), key=lambda item: item.relative_to(package_root).as_posix()):
        relative = path.relative_to(package_root).as_posix()
        if path.is_symlink() or (not path.is_dir() and not path.is_file()):
            raise DeliveryError(f"s-gw module contains an unsafe SBOM entry: {relative}")
        if path.is_dir():
            continue
        metadata = path.stat()
        total += metadata.st_size
        if (
            metadata.st_size > sgw_module.MAX_ARCHIVE_FILE_BYTES
            or len(result) >= sgw_module.MAX_ARCHIVE_FILES
            or total > sgw_module.MAX_ARCHIVE_TOTAL_BYTES
        ):
            raise DeliveryError("s-gw module exceeds its SBOM inventory limits")
        sha256, sha1 = _path_digests(
            path,
            label=f"s-gw module file {relative}",
            max_bytes=sgw_module.MAX_ARCHIVE_FILE_BYTES,
        )
        result[relative] = (sha256, sha1, path)
    if not result:
        raise DeliveryError("s-gw module has no files to inventory")
    return result


def _checked_module_metadata(
    package_root: Path,
    target: str,
    inventory: dict[str, tuple[str, str, Path]],
) -> dict[str, Any]:
    metadata = _strict_json_file(
        package_root / sgw_module.MODULE_METADATA_FILE,
        label=f"{target} s-gw module metadata",
        max_bytes=MAX_JSON_BYTES,
    )
    files = metadata.get("files")
    observed = {
        relative: digest
        for relative, (digest, _sha1, _path) in inventory.items()
        if relative != sgw_module.MODULE_METADATA_FILE
    }
    if metadata.get("target") != target or metadata.get("production_ready") is not True or files != observed:
        raise DeliveryError(f"{target} s-gw module metadata does not cover its exact files")
    if not isinstance(metadata.get("package_name"), str) or not isinstance(metadata.get("package_version"), str):
        raise DeliveryError(f"{target} s-gw module package identity is invalid")
    package = _strict_json_file(
        package_root / "package.json",
        label=f"{target} s-gw package metadata",
        max_bytes=MAX_JSON_BYTES,
    )
    if package.get("name") != metadata["package_name"] or package.get("version") != metadata["package_version"]:
        raise DeliveryError(f"{target} s-gw package metadata differs from its signed module identity")
    components = metadata.get("components")
    expected_components = {"runner", "credential_helper", "approval_ui", "license_bundle"}
    if not isinstance(components, dict) or set(components) != expected_components:
        raise DeliveryError(f"{target} s-gw module component inventory is incomplete")
    for name, component in components.items():
        if not isinstance(component, dict) or set(component) != {
            "artifact_sha256",
            "installed_sha256",
            "signature",
            "destination",
            "files",
        }:
            raise DeliveryError(f"{target} s-gw {name} component metadata is malformed")
        component_files = component.get("files")
        if (
            not isinstance(component_files, list)
            or not component_files
            or len(component_files) != len(set(component_files))
            or any(not isinstance(item, str) or item not in observed for item in component_files)
            or not isinstance(component.get("artifact_sha256"), str)
            or not SHA256_RE.fullmatch(component["artifact_sha256"])
            or not isinstance(component.get("installed_sha256"), str)
            or not SHA256_RE.fullmatch(component["installed_sha256"])
        ):
            raise DeliveryError(f"{target} s-gw {name} component inventory is invalid")
        installed = sgw_module.component_inventory_sha256(
            {relative: observed[relative] for relative in component_files}
        )
        if installed != component["installed_sha256"]:
            raise DeliveryError(f"{target} s-gw {name} installed digest is invalid")
    return metadata


def validated_core_license_text(value: object) -> str:
    if not isinstance(value, str):
        raise DeliveryError("authenticated s-gw Core license terms must be UTF-8 text")
    if "\r" in value or "\x00" in value:
        raise DeliveryError("authenticated s-gw Core license terms must use canonical LF text")
    text = value.strip("\n")
    if len(text) < 80 or len(text.encode("utf-8")) > MAX_CORE_LICENSE_BYTES:
        raise DeliveryError("authenticated s-gw Core license terms have an invalid length")
    lowered = text.lower()
    if not re.search(r"\b(?:license|permission|rights?)\b", lowered):
        raise DeliveryError("authenticated s-gw Core license terms lack a licensing grant or restriction")
    pointer_patterns = (
        r"\b(?:see|refer to)\b.{0,80}\b(?:agreement|terms|license)\b",
        r"\b(?:terms|license)\b.{0,40}\b(?:supplied|provided|available)\b.{0,40}"
        r"\b(?:separately|elsewhere|distribution|agreement)\b",
        r"\b(?:supplied|provided|available)\b.{0,40}\b(?:separate|external)\b.{0,40}"
        r"\b(?:agreement|terms|license)\b",
    )
    if any(marker in lowered for marker in ("placeholder", "todo", "tbd")) or any(
        re.search(pattern, lowered) for pattern in pointer_patterns
    ):
        raise DeliveryError("authenticated s-gw Core license terms contain placeholder text")
    return text


def _core_license_from_module(package_root: Path, metadata: dict[str, Any], target: str) -> str:
    component = metadata["components"]["license_bundle"]
    files = component.get("files")
    if not isinstance(files, list) or len(files) != 1 or not isinstance(files[0], str):
        raise DeliveryError(f"{target} s-gw license bundle must contain exactly one signed file")
    relative = sgw_module.safe_relative_path(files[0], code="artifact_invalid")
    payload = regular_file(
        package_root.joinpath(*relative.parts),
        label=f"{target} authenticated s-gw license bundle",
        max_bytes=MAX_SOURCE_LICENSE_BYTES,
    )
    if b"\r" in payload or b"\0" in payload:
        raise DeliveryError(f"{target} authenticated s-gw license bundle must use canonical LF text")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise DeliveryError(f"{target} authenticated s-gw license bundle is not UTF-8") from exc
    lines = text.splitlines()
    if text.count(SGW_CORE_LICENSE_BEGIN) != 1 or text.count(SGW_CORE_LICENSE_END) != 1:
        raise DeliveryError(f"{target} authenticated s-gw license bundle lacks one {SGW_CORE_LICENSE} section")
    try:
        begin = lines.index(SGW_CORE_LICENSE_BEGIN)
        end = lines.index(SGW_CORE_LICENSE_END)
    except ValueError as exc:
        raise DeliveryError(f"{target} authenticated s-gw license markers must occupy complete lines") from exc
    if begin >= end:
        raise DeliveryError(f"{target} authenticated s-gw Core license section is malformed")
    return validated_core_license_text("\n".join(lines[begin + 1 : end]))


def _npm_name(lock_path: str, record: dict[str, Any]) -> str:
    if isinstance(record.get("name"), str) and record["name"]:
        return record["name"]
    parts = PurePosixPath(lock_path).parts
    indices = [index for index, value in enumerate(parts) if value == "node_modules"]
    if not indices or indices[-1] + 1 >= len(parts):
        raise DeliveryError(f"s-gw package lock has an invalid installed path: {lock_path}")
    tail = parts[indices[-1] + 1 :]
    if tail[0].startswith("@"):
        if len(tail) != 2:
            raise DeliveryError(f"s-gw package lock has an invalid scoped path: {lock_path}")
        return "/".join(tail)
    if len(tail) != 1:
        raise DeliveryError(f"s-gw package lock has an invalid installed path: {lock_path}")
    return tail[0]


def _installed_npm_packages(
    package_root: Path,
    inventory: dict[str, tuple[str, str, Path]],
) -> tuple[dict[str, Any], list[tuple[str, str, str, str, str | None, set[str]]]]:
    lock = _strict_json_file(
        package_root / "package-lock.json",
        label="s-gw production package lock",
        max_bytes=MAX_PACKAGE_LOCK_BYTES,
    )
    packages = lock.get("packages")
    root = packages.get("") if isinstance(packages, dict) else None
    if lock.get("lockfileVersion") != 3 or not isinstance(root, dict):
        raise DeliveryError("s-gw production package lock must use npm lockfile version 3")

    installed: dict[str, tuple[str, str, str, str | None]] = {}
    for raw_path, raw_record in packages.items():
        if raw_path == "":
            continue
        if not isinstance(raw_path, str) or not isinstance(raw_record, dict):
            raise DeliveryError("s-gw production package lock contains malformed package metadata")
        relative = sgw_module.safe_relative_path(raw_path, code="artifact_invalid")
        if "node_modules" not in relative.parts:
            continue
        directory = package_root.joinpath(*relative.parts)
        if not directory.exists():
            continue
        if directory.is_symlink() or not directory.is_dir():
            raise DeliveryError(f"s-gw installed npm package path is unsafe: {raw_path}")
        version = raw_record.get("version")
        if not isinstance(version, str) or not version:
            raise DeliveryError(f"s-gw installed npm package has no version: {raw_path}")
        name = _npm_name(raw_path, raw_record)
        declared, license_comment = _spdx_license(raw_record.get("license"))
        installed[relative.as_posix()] = (name, version, declared, license_comment)
    if not installed:
        raise DeliveryError("s-gw production module has no installed npm dependencies")

    owned: dict[str, set[str]] = {path: set() for path in installed}
    node_files = [relative for relative in inventory if relative.startswith("node_modules/")]
    ordered_roots = sorted(installed, key=lambda value: len(PurePosixPath(value).parts), reverse=True)
    for relative in node_files:
        owner = next(
            (root_path for root_path in ordered_roots if relative.startswith(f"{root_path}/")),
            None,
        )
        if owner is None:
            raise DeliveryError(f"s-gw npm file is absent from package-lock.json: {relative}")
        owned[owner].add(relative)

    result: list[tuple[str, str, str, str, str | None, set[str]]] = []
    for lock_path in sorted(installed):
        name, version, declared, license_comment = installed[lock_path]
        files = owned[lock_path]
        if not files or f"{lock_path}/package.json" not in files:
            raise DeliveryError(f"s-gw installed npm package inventory is incomplete: {lock_path}")
        result.append((lock_path, name, version, declared, license_comment, files))
    return root, result


def _add_target_inventory(
    document: SgwSpdxDocument,
    *,
    target: str,
    archive: Path,
    package_root: Path,
    metadata: dict[str, Any],
    inventory: dict[str, tuple[str, str, Path]],
) -> str:
    module_sha256, _module_sha1 = _path_digests(
        archive,
        label=f"{target} s-gw module archive",
        max_bytes=MAX_ARTIFACT_BYTES,
    )
    version = metadata["package_version"]
    module_id = document.add_package(
        f"module:{target}:{module_sha256}",
        name=f"s-gw authenticated module ({target})",
        version=version,
        purpose="ARCHIVE",
        license_declared=SGW_MIXED_LICENSE,
        checksum=module_sha256,
        package_file_name=f"modules/{target}/s-gw-module.tar.gz",
        comment=f"DefenseClaw s-gw inventory role=module-archive; target={target}",
    )

    file_ids: dict[str, str] = {}
    for relative, (sha256, sha1, _path) in inventory.items():
        file_id = document.add_file(f"./sgw/{target}/{relative}", sha256, sha1)
        file_ids[relative] = file_id
        document.contains_file(module_id, file_id)

    component_files: set[str] = set()
    component_licenses = {
        "runner": SGW_CORE_LICENSE,
        "credential_helper": SGW_CORE_LICENSE,
        "approval_ui": "Apache-2.0",
        "license_bundle": "NOASSERTION",
    }
    for name, component in sorted(metadata["components"].items()):
        files = set(component["files"])
        component_files.update(files)
        purpose = "APPLICATION" if name in {"runner", "credential_helper", "approval_ui"} else "FILE"
        component_id = document.add_package(
            f"component:{target}:{name}:{component['artifact_sha256']}",
            name=f"s-gw {name.replace('_', ' ')} ({target})",
            version=version,
            purpose=purpose,
            license_declared=component_licenses[name],
            checksum=component["artifact_sha256"],
            comment=(
                "DefenseClaw s-gw inventory role=native-component; "
                f"target={target}; component={name}; installed_sha256={component['installed_sha256']}"
            ),
        )
        document.relate(module_id, "CONTAINS", component_id)
        for relative in sorted(files):
            document.contains_file(component_id, file_ids[relative])

    root_lock, dependencies = _installed_npm_packages(package_root, inventory)
    root_name = root_lock.get("name")
    root_version = root_lock.get("version")
    if root_name != metadata["package_name"] or root_version != version:
        raise DeliveryError(f"{target} npm lock root differs from the signed s-gw package identity")
    node_files = {relative for relative in inventory if relative.startswith("node_modules/")}
    root_files = set(inventory) - node_files - component_files - {sgw_module.MODULE_METADATA_FILE}
    required_root_files = {"package.json", "package-lock.json", "dist/cli.js", "dist/mcp-server.js"}
    if not required_root_files.issubset(root_files):
        raise DeliveryError(f"{target} s-gw npm root inventory is incomplete")
    package_json = _strict_json_file(
        package_root / "package.json",
        label=f"{target} s-gw npm root package metadata",
        max_bytes=MAX_JSON_BYTES,
    )
    root_license, root_license_comment = _spdx_license(package_json.get("license"))
    if root_license != "Apache-2.0" or root_license_comment is not None:
        raise DeliveryError(f"{target} s-gw npm root must declare Apache-2.0")
    npm_name = urllib.parse.quote(root_name, safe="/")
    npm_version = urllib.parse.quote(root_version, safe="-._~+!")
    root_id = document.add_package(
        f"npm:{target}:root:{root_name}@{root_version}",
        name=root_name,
        version=root_version,
        purpose="APPLICATION",
        license_declared="Apache-2.0",
        purl=f"pkg:npm/{npm_name}@{npm_version}",
        comment=f"DefenseClaw s-gw inventory role=npm-root; target={target}; path=.",
    )
    document.relate(module_id, "CONTAINS", root_id)
    for relative in sorted(root_files):
        document.contains_file(root_id, file_ids[relative])

    for lock_path, name, package_version, license_declared, license_comment, files in dependencies:
        purl_name = urllib.parse.quote(name, safe="/")
        purl_version = urllib.parse.quote(package_version, safe="-._~+!")
        dependency_id = document.add_package(
            f"npm:{target}:{lock_path}:{name}@{package_version}",
            name=name,
            version=package_version,
            purpose="LIBRARY",
            license_declared=license_declared,
            license_comment=(f"npm package-lock license metadata: {license_comment}" if license_comment else None),
            purl=f"pkg:npm/{purl_name}@{purl_version}",
            comment=f"DefenseClaw s-gw inventory role=npm-dependency; target={target}; path={lock_path}",
        )
        document.relate(module_id, "CONTAINS", dependency_id)
        document.relate(root_id, "DEPENDS_ON", dependency_id)
        for relative in sorted(files):
            document.contains_file(dependency_id, file_ids[relative])
    return module_id


def _build_sgw_sbom(
    wheel: Path,
    *,
    version: str,
    source_commit: str,
    source_epoch: int,
    authenticate: bool,
) -> dict[str, Any]:
    if not COMMIT_RE.fullmatch(source_commit):
        raise DeliveryError("s-gw SBOM source commit must be a lowercase full Git object ID")
    if source_epoch < 0:
        raise DeliveryError("s-gw SBOM source epoch must be nonnegative")
    if authenticate:
        verify_wheel(argparse.Namespace(wheel=wheel))
    wheel_sha256, _wheel_sha1 = _path_digests(
        wheel,
        label="DefenseClaw wheel",
        max_bytes=MAX_ARTIFACT_BYTES,
    )
    try:
        with zipfile.ZipFile(wheel) as archive:
            observed_version = _wheel_version(archive)
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        raise DeliveryError(f"could not read DefenseClaw wheel identity: {exc}") from exc
    if observed_version != version:
        raise DeliveryError(f"DefenseClaw wheel version {observed_version!r} does not match {version!r}")
    created = (
        datetime.fromtimestamp(source_epoch, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )
    document = SgwSpdxDocument(
        version=version,
        commit=source_commit,
        created=created,
        wheel_sha256=wheel_sha256,
    )
    wheel_id = document.add_package(
        f"wheel:{wheel_sha256}",
        name="DefenseClaw Python wheel with s-gw runtime modules",
        version=version,
        purpose="LIBRARY",
        license_declared=SGW_MIXED_LICENSE,
        checksum=wheel_sha256,
        package_file_name=f"defenseclaw-{version}-py3-none-any.whl",
        purl=f"pkg:pypi/defenseclaw@{urllib.parse.quote(version, safe='-._~')}",
        comment="DefenseClaw s-gw inventory role=wheel",
        files_analyzed=False,
    )
    document.described.append(wheel_id)
    document.relate("SPDXRef-DOCUMENT", "DESCRIBES", wheel_id)

    with tempfile.TemporaryDirectory(prefix="defenseclaw-sgw-sbom-") as temp:
        temp_root = Path(temp)
        modules, module_payload, runtime_payload = _copy_sgw_wheel_inputs(
            wheel,
            temp_root / "wheel",
        )
        manifest = parse_json(module_payload, label="wheel s-gw module manifest")
        for target in TARGETS:
            artifact = modules / target / "s-gw-module.tar.gz"
            extract_root = temp_root / "expanded" / target
            extract_root.mkdir(parents=True, mode=0o700)
            try:
                package_root = sgw_module.extract_module_artifact(artifact, extract_root)
                sgw_module.private_tree(package_root)
                inventory = _module_file_inventory(package_root)
                if authenticate:
                    reviewed_manifest, records = module_control(
                        module_payload,
                        runtime_payload,
                        target,
                        require_approved=True,
                    )
                    metadata, verified_inventory = sgw_module.verified_module_metadata(
                        package_root,
                        reviewed_manifest,
                        target,
                        records,
                    )
                    if verified_inventory != {
                        relative: digest for relative, (digest, _sha1, _path) in inventory.items()
                    }:
                        raise DeliveryError(f"{target} authenticated s-gw inventory changed during SBOM generation")
                else:
                    metadata = _checked_module_metadata(package_root, target, inventory)
            except sgw_module.ModuleError as exc:
                raise DeliveryError(f"{target} s-gw module is invalid for SBOM generation: {exc}") from exc
            if metadata.get("package_name") != manifest.get("package_name"):
                raise DeliveryError(f"{target} s-gw module package name differs from the delivery manifest")
            core_license = _core_license_from_module(package_root, metadata, target)
            if document.core_license_text is None:
                document.core_license_text = core_license
            elif document.core_license_text != core_license:
                raise DeliveryError("authenticated s-gw Core license terms differ across target modules")
            module_id = _add_target_inventory(
                document,
                target=target,
                archive=artifact,
                package_root=package_root,
                metadata=metadata,
                inventory=inventory,
            )
            document.relate(wheel_id, "CONTAINS", module_id)
    if document.core_license_text is None:
        raise DeliveryError("authenticated s-gw Core license terms are absent from the module set")
    _validate_wheel_license_metadata(
        wheel,
        version=version,
        core_terms=document.core_license_text,
    )
    return document.render()


def generate_sgw_sbom(args: argparse.Namespace) -> dict[str, Any]:
    wheel = args.wheel.resolve(strict=True)
    output = args.output.resolve()
    document = _build_sgw_sbom(
        wheel,
        version=args.version,
        source_commit=args.source_commit,
        source_epoch=args.source_epoch,
        authenticate=True,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "schema_version": 1,
        "output": os.fspath(output),
        "wheel_sha256": next(
            checksum["checksumValue"]
            for package in document["packages"]
            if package.get("comment") == "DefenseClaw s-gw inventory role=wheel"
            for checksum in package["checksums"]
            if checksum["algorithm"] == "SHA256"
        ),
        "targets": list(TARGETS),
        "packages": len(document["packages"]),
        "files": len(document["files"]),
    }


def validate_sgw_sbom(
    wheel: Path,
    sbom: Path,
    *,
    version: str | None = None,
    source_commit: str | None = None,
    authenticate: bool = False,
) -> dict[str, Any]:
    payload = regular_file(sbom, label="s-gw SPDX SBOM", max_bytes=MAX_SGW_SBOM_BYTES)
    try:
        document = json.loads(payload, object_pairs_hook=sgw_module.unique_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError, sgw_module.DuplicateJSONKeyError) as exc:
        raise DeliveryError("s-gw SPDX SBOM is malformed") from exc
    if not isinstance(document, dict):
        raise DeliveryError("s-gw SPDX SBOM must contain one JSON object")
    if (
        document.get("spdxVersion") != "SPDX-2.3"
        or document.get("dataLicense") != "CC0-1.0"
        or document.get("SPDXID") != "SPDXRef-DOCUMENT"
    ):
        raise DeliveryError("s-gw SPDX SBOM document identity is invalid")
    match = re.fullmatch(r"DefenseClaw s-gw runtime modules (.+)", str(document.get("name", "")))
    observed_version = match.group(1) if match else ""
    commit_match = re.fullmatch(r"DefenseClaw source commit: ([0-9a-f]{40})", str(document.get("comment", "")))
    observed_commit = commit_match.group(1) if commit_match else ""
    creation = document.get("creationInfo")
    created = creation.get("created") if isinstance(creation, dict) else None
    try:
        parsed = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.microsecond or parsed.isoformat().replace("+00:00", "Z") != created:
            raise ValueError
        source_epoch = int(parsed.timestamp())
    except (TypeError, ValueError, OverflowError) as exc:
        raise DeliveryError("s-gw SPDX SBOM creation timestamp is invalid") from exc
    if version is not None and observed_version != version:
        raise DeliveryError("s-gw SPDX SBOM version does not match the release")
    if source_commit is not None and observed_commit != source_commit:
        raise DeliveryError("s-gw SPDX SBOM commit does not match the release")
    expected = _build_sgw_sbom(
        wheel.resolve(strict=True),
        version=observed_version,
        source_commit=observed_commit,
        source_epoch=source_epoch,
        authenticate=authenticate,
    )
    if document != expected:
        raise DeliveryError("s-gw SPDX SBOM is incomplete or differs from the authenticated wheel inventory")
    return {
        "schema_version": 1,
        "wheel": os.fspath(wheel),
        "sbom": os.fspath(sbom),
        "version": observed_version,
        "source_commit": observed_commit,
        "targets": list(TARGETS),
        "packages": len(document["packages"]),
        "files": len(document["files"]),
    }


def verify_sgw_sbom(args: argparse.Namespace) -> dict[str, Any]:
    return validate_sgw_sbom(
        args.wheel,
        args.sbom,
        version=args.version,
        source_commit=args.source_commit,
        authenticate=args.authenticate,
    )


def require_all_default() -> bool:
    value = os.environ.get("DEFENSECLAW_REQUIRE_SGW_MODULES", "").strip().lower()
    if not value:
        return False
    if value in {"1", "true", "yes"}:
        return True
    if value in {"0", "false", "no"}:
        return False
    raise DeliveryError("DEFENSECLAW_REQUIRE_SGW_MODULES must be true or false")


def environment_path(name: str, default: str) -> Path:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return Path(default)
    return Path(value)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    stage_parser = subparsers.add_parser("stage")
    stage_parser.add_argument("--root", type=Path, default=ROOT)
    stage_parser.add_argument("--destination", type=Path, required=True)
    stage_parser.add_argument(
        "--artifact-dir",
        type=Path,
        default=environment_path("DEFENSECLAW_SGW_ARTIFACT_DIR", "dist/sgw"),
    )
    stage_parser.add_argument(
        "--runtime-manifest",
        type=Path,
        default=environment_path("DEFENSECLAW_SGW_RUNTIME_MANIFEST", "release/s-gw-runners.json"),
    )
    stage_parser.add_argument("--require-all", action="store_true", default=require_all_default())
    verify_parser = subparsers.add_parser("verify-wheel")
    verify_parser.add_argument("--wheel", type=Path, required=True)
    sbom_parser = subparsers.add_parser("generate-sbom")
    sbom_parser.add_argument("--wheel", type=Path, required=True)
    sbom_parser.add_argument("--output", type=Path, required=True)
    sbom_parser.add_argument("--version", required=True)
    sbom_parser.add_argument("--source-commit", required=True)
    sbom_parser.add_argument("--source-epoch", type=int, required=True)
    verify_sbom_parser = subparsers.add_parser("verify-sbom")
    verify_sbom_parser.add_argument("--wheel", type=Path, required=True)
    verify_sbom_parser.add_argument("--sbom", type=Path, required=True)
    verify_sbom_parser.add_argument("--version")
    verify_sbom_parser.add_argument("--source-commit")
    verify_sbom_parser.add_argument("--authenticate", action="store_true")
    license_parser = subparsers.add_parser("license-metadata")
    license_parser.add_argument("--staged-root", type=Path, required=True)
    license_parser.add_argument("--output", type=Path, required=True)
    license_parser.add_argument("--base-notice", type=Path, required=True)
    license_parser.add_argument("--validate-only", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(sys.argv[1:] if argv is None else argv)
        if args.command == "stage":
            result = stage(args)
        elif args.command == "verify-wheel":
            result = verify_wheel(args)
        elif args.command == "generate-sbom":
            result = generate_sgw_sbom(args)
        elif args.command == "license-metadata":
            result = materialize_wheel_license_metadata(args)
        else:
            result = verify_sgw_sbom(args)
    except (DeliveryError, OSError, ValueError) as exc:
        print(f"s-gw module delivery failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
