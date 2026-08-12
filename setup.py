# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Build hooks for package-local runtime assets."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from email import policy
from email.parser import BytesParser
from pathlib import Path

from setuptools import setup
from setuptools.command.bdist_wheel import bdist_wheel
from setuptools.command.build_py import build_py
from setuptools.command.dist_info import dist_info
from setuptools.command.editable_wheel import editable_wheel

BASE_LICENSE_EXPRESSION = "Apache-2.0"
SGW_CORE_NOTICE_FILE = "NOTICE"
SGW_MIXED_LICENSE_EXPRESSION = "Apache-2.0 AND LicenseRef-s-gw-Core"
WHEEL_LICENSE_FILES = ["LICENSE", SGW_CORE_NOTICE_FILE, "THIRD_PARTY_LICENSES.txt"]

CONFIG_SOURCE_ROOT = Path("schemas/config/v8")
CONFIG_ASSETS = {
    "defenseclaw-config.schema.json": Path("defenseclaw-config.schema.json"),
    "observability.yaml": Path("reference/observability.yaml"),
    "observability.md": Path("reference/observability.md"),
}
TELEMETRY_SOURCE_ROOT = Path("schemas/telemetry/runtime")
TELEMETRY_ASSETS = {
    "telemetry.schema.json": Path("telemetry.schema.json.gz"),
    "catalog.json": Path("catalog.json.gz"),
    "v7-exporter-selection.json": Path("compatibility/v7-exporter-selection.json.gz"),
    "galileo-rich-v2.json": Path("compatibility/galileo-rich-v2.json.gz"),
    "local-observability-v1.json": Path("compatibility/local-observability-v1.json.gz"),
    "openinference-v1.json": Path("compatibility/openinference-v1.json.gz"),
}


def _relative_file_inventory(root: Path) -> set[str]:
    if not root.is_dir() or root.is_symlink():
        raise RuntimeError(f"required runtime asset directory is unavailable: {root}")
    files: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise RuntimeError(f"runtime asset source must not be a symlink: {path}")
        if path.is_file():
            files.add(path.relative_to(root).as_posix())
    return files


def _require_exact_inventory(root: Path, expected: set[str], *, label: str) -> None:
    actual = _relative_file_inventory(root)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise RuntimeError(f"{label} inventory mismatch: missing={missing}, unexpected={unexpected}")


def _validated_json(payload: bytes, *, label: str) -> None:
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"required runtime JSON is malformed: {label}") from exc
    if not isinstance(document, dict):
        raise RuntimeError(f"required runtime JSON must be an object: {label}")


def _stage_v8_assets(root: Path, build_lib: Path) -> None:
    config_root = root / CONFIG_SOURCE_ROOT
    expected_config_sources = {path.as_posix() for path in CONFIG_ASSETS.values()}
    if len(expected_config_sources) != len(CONFIG_ASSETS):
        raise RuntimeError("v8 config asset sources or destinations are duplicated")
    _require_exact_inventory(config_root, expected_config_sources, label="v8 config source")

    config_destination = build_lib / "defenseclaw" / "_data" / "config" / "v8"
    if config_destination.exists():
        shutil.rmtree(config_destination)
    config_destination.mkdir(parents=True)
    for destination_name, source_relative in CONFIG_ASSETS.items():
        source = config_root / source_relative
        try:
            payload = source.read_bytes()
        except OSError as exc:
            raise RuntimeError(f"required v8 config asset is unavailable: {source_relative}") from exc
        if not payload:
            raise RuntimeError(f"required v8 config asset is empty: {source_relative}")
        if source_relative.suffix == ".json":
            _validated_json(payload, label=source_relative.as_posix())
        target = config_destination / destination_name
        target.write_bytes(payload)
        if target.read_bytes() != payload:
            raise RuntimeError(f"staged v8 config asset differs from source: {destination_name}")
    _require_exact_inventory(
        config_destination,
        set(CONFIG_ASSETS),
        label="staged v8 config",
    )

    telemetry_source_names = {path.as_posix() for path in TELEMETRY_ASSETS.values()}
    telemetry_destination_names = set(TELEMETRY_ASSETS)
    if len(telemetry_source_names) != len(TELEMETRY_ASSETS):
        raise RuntimeError("v8 telemetry asset sources or destinations are duplicated")
    _require_exact_inventory(
        root / TELEMETRY_SOURCE_ROOT,
        telemetry_source_names,
        label="v8 telemetry source",
    )

    telemetry_destination = build_lib / "defenseclaw" / "_data" / "telemetry" / "v8"
    if telemetry_destination.exists():
        shutil.rmtree(telemetry_destination)
    telemetry_helper = root / "scripts" / "telemetry_runtime_assets.py"
    if not telemetry_helper.is_file() or telemetry_helper.is_symlink():
        raise RuntimeError("canonical v8 telemetry staging helper is unavailable")
    completed = subprocess.run(
        [
            sys.executable,
            str(telemetry_helper),
            "--root",
            str(root),
            "--stage",
            str(telemetry_destination),
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    if completed.returncode != 0:
        raise RuntimeError("failed to stage canonical v8 telemetry assets")
    _require_exact_inventory(
        telemetry_destination,
        telemetry_destination_names,
        label="staged v8 telemetry",
    )
    for destination_name in sorted(telemetry_destination_names):
        try:
            payload = (telemetry_destination / destination_name).read_bytes()
        except OSError as exc:
            raise RuntimeError(f"staged v8 telemetry asset is unavailable: {destination_name}") from exc
        _validated_json(payload, label=destination_name)


def _stage_sgw_driver_assets(root: Path, build_lib: Path) -> None:
    destination = build_lib / "defenseclaw" / "_data" / "sgw"
    helper = root / "scripts" / "stage_sgw_modules.py"
    if helper.is_symlink() or not helper.is_file():
        raise RuntimeError("canonical s-gw module staging helper is unavailable")
    completed = subprocess.run(
        [
            sys.executable,
            str(helper),
            "stage",
            "--root",
            str(root),
            "--destination",
            str(destination),
        ],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=600,
    )
    if completed.returncode != 0:
        raise RuntimeError("failed to stage authenticated s-gw module assets")


def _sgw_file_inventory(
    staged_root: Path,
    *,
    expected: dict[str, tuple[str, int]] | None = None,
    label: str = "staged s-gw runtime",
) -> dict[str, tuple[str, int]]:
    files = _relative_file_inventory(staged_root)
    if expected is not None and files != set(expected):
        raise RuntimeError(f"{label} differs from authenticated staging")

    path_state: dict[str, os.stat_result] = {}
    for relative in sorted(files):
        path = staged_root / relative
        try:
            before = path.lstat()
        except OSError as exc:
            raise RuntimeError(f"{label} file is unavailable: {relative}") from exc
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError(f"{label} file is not regular: {relative}")
        if expected is not None and before.st_size != expected[relative][1]:
            raise RuntimeError(f"{label} differs from authenticated staging")
        path_state[relative] = before

    inventory: dict[str, tuple[str, int]] = {}
    for relative in sorted(files):
        path = staged_root / relative
        before = path_state[relative]
        try:
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            digest = hashlib.sha256()
            with os.fdopen(os.open(path, flags), "rb") as source:
                opened = os.fstat(source.fileno())
                if not stat.S_ISREG(opened.st_mode) or opened.st_dev != before.st_dev or opened.st_ino != before.st_ino:
                    raise RuntimeError(f"{label} file changed before hashing: {relative}")
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
                after = os.fstat(source.fileno())
            final = path.lstat()
        except OSError as exc:
            raise RuntimeError(f"{label} file is unavailable: {relative}") from exc
        if (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_mode != opened.st_mode
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
            or final.st_dev != before.st_dev
            or final.st_ino != before.st_ino
            or final.st_mode != before.st_mode
            or final.st_size != before.st_size
            or final.st_mtime_ns != before.st_mtime_ns
            or final.st_ctime_ns != before.st_ctime_ns
            or final.st_dev != after.st_dev
            or final.st_ino != after.st_ino
        ):
            raise RuntimeError(f"{label} file changed while hashing: {relative}")
        inventory[relative] = digest.hexdigest(), opened.st_size
    if expected is not None and inventory != expected:
        raise RuntimeError(f"{label} differs from authenticated staging")
    return inventory


def _sgw_wheel_license_contract(
    root: Path,
    staged_root: Path,
    dist_info: Path,
    *,
    validate_only: bool,
) -> dict:
    helper = root / "scripts" / "stage_sgw_modules.py"
    notice_file = dist_info / "licenses" / SGW_CORE_NOTICE_FILE
    command = [
        sys.executable,
        str(helper),
        "license-metadata",
        "--staged-root",
        str(staged_root),
        "--output",
        str(notice_file),
        "--base-notice",
        str(root / "NOTICE"),
    ]
    if validate_only:
        command.append("--validate-only")
    completed = subprocess.run(
        command,
        check=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
    )
    if completed.returncode != 0:
        raise RuntimeError("failed to validate s-gw wheel licensing")
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("s-gw wheel license contract returned malformed output") from exc
    expected_keys = {
        "schema_version",
        "production_modules",
        "license_expression",
        "license_file",
        "license_sha256",
    }
    if not isinstance(result, dict) or set(result) != expected_keys or result.get("schema_version") != 1:
        raise RuntimeError("s-gw wheel license contract is invalid")

    production = result.get("production_modules")
    if production is False:
        if (
            result.get("license_expression") != BASE_LICENSE_EXPRESSION
            or result.get("license_file") is not None
            or result.get("license_sha256") is not None
        ):
            raise RuntimeError("source-only wheel license contract is invalid")
        return result
    if production is not True:
        raise RuntimeError("s-gw wheel license contract has an invalid module state")
    if (
        result.get("license_expression") != SGW_MIXED_LICENSE_EXPRESSION
        or result.get("license_file") != SGW_CORE_NOTICE_FILE
    ):
        raise RuntimeError("production wheel license contract is invalid")
    digest = result.get("license_sha256")
    if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise RuntimeError("production wheel license digest is invalid")
    try:
        payload = notice_file.read_bytes()
    except OSError as exc:
        raise RuntimeError("production wheel s-gw Core license file is unavailable") from exc
    if not payload or hashlib.sha256(payload).hexdigest() != digest:
        raise RuntimeError("production wheel s-gw Core license digest does not match")
    return result


def _update_wheel_metadata(metadata_path: Path, contract: dict, *, allow_update: bool) -> None:
    try:
        source_payload = metadata_path.read_bytes()
    except OSError as exc:
        raise RuntimeError("wheel distribution metadata is unavailable") from exc
    if b"\0" in source_payload:
        raise RuntimeError("wheel distribution metadata is not canonical LF or CRLF text")
    carriage_return = bytes((13,))
    line_feed = bytes((10,))
    crlf = carriage_return + line_feed
    if carriage_return in source_payload:
        unpaired_newlines = source_payload.replace(crlf, b"")
        if carriage_return in unpaired_newlines:
            raise RuntimeError("wheel distribution metadata is not canonical LF or CRLF text")
        payload = source_payload.replace(crlf, line_feed)
    else:
        payload = source_payload
    if b"\n\n" not in payload:
        raise RuntimeError("wheel distribution metadata is not canonical LF or CRLF text")
    metadata = BytesParser(policy=policy.default).parsebytes(payload)
    if metadata.defects:
        raise RuntimeError("wheel distribution metadata is malformed")
    if metadata.get_all("License"):
        raise RuntimeError("wheel distribution metadata carries a legacy License field")
    expressions = metadata.get_all("License-Expression", [])
    license_files = metadata.get_all("License-File", [])
    if sorted(license_files) != WHEEL_LICENSE_FILES:
        raise RuntimeError("wheel distribution metadata has unexpected license file headers")

    production = contract["production_modules"]
    expression = contract["license_expression"]
    if not production:
        if expression != BASE_LICENSE_EXPRESSION or expressions != [BASE_LICENSE_EXPRESSION]:
            raise RuntimeError("source-only wheel license expression is invalid")
    elif expressions != [expression]:
        if expressions != [BASE_LICENSE_EXPRESSION]:
            raise RuntimeError("production wheel license expression is invalid")
        if not allow_update:
            raise RuntimeError("prepared wheel license expression does not match the requested s-gw module mode")

        headers, body = payload.split(b"\n\n", 1)
        lines = headers.split(b"\n")
        replaced = False
        output: list[bytes] = []
        for line in lines:
            if line.startswith(b"License-Expression:"):
                if replaced:
                    raise RuntimeError("wheel distribution metadata repeats its license expression")
                output.append(f"License-Expression: {expression}".encode("ascii"))
                replaced = True
                continue
            output.append(line)
        if not replaced:
            raise RuntimeError("wheel distribution metadata lacks its license expression")
        payload = b"\n".join(output) + b"\n\n" + body

    if payload == source_payload:
        return
    try:
        metadata_path.write_bytes(payload)
    except OSError as exc:
        raise RuntimeError("could not write canonical wheel license metadata") from exc


def _apply_sgw_wheel_license(
    root: Path,
    dist_info_dir: Path,
    *,
    allow_update: bool,
) -> tuple[dict, dict[str, tuple[str, int]]]:
    with tempfile.TemporaryDirectory(prefix="defenseclaw-sgw-wheel-license-") as temp:
        build_root = Path(temp)
        _stage_sgw_driver_assets(root, build_root)
        staged_root = build_root / "defenseclaw" / "_data" / "sgw"
        contract = _sgw_wheel_license_contract(
            root,
            staged_root,
            dist_info_dir,
            validate_only=not allow_update,
        )
        expected_inventory = _sgw_file_inventory(staged_root)
    _update_wheel_metadata(dist_info_dir / "METADATA", contract, allow_update=allow_update)
    return contract, expected_inventory


class BuildPyWithRuntimeAssets(build_py):
    """Copy authoritative non-Python runtime assets into every wheel build."""

    def run(self) -> None:
        super().run()
        root = Path(__file__).resolve().parent
        for bundle_name in ("local_observability_stack", "splunk_local_bridge"):
            source = root / "bundles" / bundle_name
            destination = Path(self.build_lib) / "defenseclaw" / "_data" / bundle_name
            if not source.is_dir():
                raise RuntimeError(f"required runtime bundle is missing: {source}")
            shutil.rmtree(destination, ignore_errors=True)
            shutil.copytree(
                source,
                destination,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )

        registry_source = root / "internal" / "envvars" / "registry.json"
        registry_destination = Path(self.build_lib) / "defenseclaw" / "_data" / "envvars" / "registry.json"
        if not registry_source.is_file():
            raise RuntimeError(f"required environment registry is missing: {registry_source}")
        registry_destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(registry_source, registry_destination)

        _stage_v8_assets(root, Path(self.build_lib))
        _stage_sgw_driver_assets(root, Path(self.build_lib))


class DistInfoWithSgwLicense(dist_info):
    def run(self) -> None:
        super().run()
        _apply_sgw_wheel_license(
            Path(__file__).resolve().parent,
            Path(self.dist_info_dir),
            allow_update=True,
        )


class EditableWheelWithSgwLicense(editable_wheel):
    def run(self) -> None:
        marker = "_defenseclaw_editable_build"
        had_marker = hasattr(self.distribution, marker)
        previous = getattr(self.distribution, marker, None)
        setattr(self.distribution, marker, self.dist_info_dir is not None)
        try:
            super().run()
        finally:
            if had_marker:
                setattr(self.distribution, marker, previous)
            else:
                delattr(self.distribution, marker)


class BdistWheelWithSgwLicense(bdist_wheel):
    building_archive = False

    def run(self) -> None:
        self.building_archive = True
        try:
            super().run()
        finally:
            self.building_archive = False

    def write_wheelfile(self, wheelfile_base: str, generator: str | None = None) -> None:
        root = Path(__file__).resolve().parent
        dist_info = Path(wheelfile_base)
        is_editable = hasattr(self.distribution, "_defenseclaw_editable_build")
        contract, expected_inventory = _apply_sgw_wheel_license(
            root,
            dist_info,
            allow_update=not is_editable and self.building_archive and not bool(self.dist_info_dir),
        )
        if not is_editable:
            packaged_root = Path(self.bdist_dir) / "defenseclaw" / "_data" / "sgw"
            if not packaged_root.is_dir():
                raise RuntimeError("wheel build lacks packaged s-gw runtime assets")
            _sgw_file_inventory(
                packaged_root,
                expected=expected_inventory,
                label="packaged s-gw runtime",
            )
            packaged_contract = _sgw_wheel_license_contract(
                root,
                packaged_root,
                dist_info,
                validate_only=True,
            )
            if packaged_contract != contract:
                raise RuntimeError("packaged s-gw runtime and wheel licensing differ")
        else:
            package_root = root / "cli" / "defenseclaw"
            data_root = package_root / "_data"
            editable_root = data_root / "sgw"
            for path in (root / "cli", package_root):
                if path.is_symlink() or not path.is_dir():
                    raise RuntimeError("editable s-gw runtime package path is unsafe")
            if data_root.is_symlink() or (data_root.exists() and not data_root.is_dir()):
                raise RuntimeError("editable s-gw runtime data path is unsafe")
            try:
                state = editable_root.lstat()
            except FileNotFoundError:
                _stage_sgw_driver_assets(root, root / "cli")
            except OSError as exc:
                raise RuntimeError("editable s-gw runtime path is unavailable") from exc
            else:
                if not stat.S_ISDIR(state.st_mode):
                    raise RuntimeError("editable s-gw runtime path is unsafe")
            _sgw_file_inventory(
                editable_root,
                expected=expected_inventory,
                label="editable s-gw runtime",
            )
            editable_contract = _sgw_wheel_license_contract(
                root,
                editable_root,
                dist_info,
                validate_only=True,
            )
            if editable_contract != contract:
                raise RuntimeError("editable s-gw runtime and wheel licensing differ")
        if generator is None:
            super().write_wheelfile(wheelfile_base)
            return
        super().write_wheelfile(wheelfile_base, generator)


setup(
    license_expression=BASE_LICENSE_EXPRESSION,
    cmdclass={
        "bdist_wheel": BdistWheelWithSgwLicense,
        "build_py": BuildPyWithRuntimeAssets,
        "dist_info": DistInfoWithSgwLicense,
        "editable_wheel": EditableWheelWithSgwLicense,
    },
)
