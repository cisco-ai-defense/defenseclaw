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

import json
import shutil
import subprocess
import sys
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py

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
        registry_destination = (
            Path(self.build_lib) / "defenseclaw" / "_data" / "envvars" / "registry.json"
        )
        if not registry_source.is_file():
            raise RuntimeError(f"required environment registry is missing: {registry_source}")
        registry_destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(registry_source, registry_destination)

        _stage_v8_assets(root, Path(self.build_lib))

setup(cmdclass={"build_py": BuildPyWithRuntimeAssets})
