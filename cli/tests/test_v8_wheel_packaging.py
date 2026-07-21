# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from collections.abc import Iterator
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import NamedTuple
from unittest import mock

import pytest

from scripts.telemetry_runtime_assets import LOGICAL_TO_ENCODED, read_logical_asset

ROOT = Path(__file__).resolve().parents[2]
PACKAGE_PREFIX = "defenseclaw/_data/"
CONFIG_SOURCES = {
    f"{PACKAGE_PREFIX}config/v8/defenseclaw-config.schema.json": (
        ROOT / "schemas/config/v8/defenseclaw-config.schema.json"
    ),
    f"{PACKAGE_PREFIX}config/v8/observability.yaml": (ROOT / "schemas/config/v8/reference/observability.yaml"),
    f"{PACKAGE_PREFIX}config/v8/observability.md": (ROOT / "schemas/config/v8/reference/observability.md"),
}
TELEMETRY_SOURCES = {f"{PACKAGE_PREFIX}telemetry/v8/{Path(logical).name}": logical for logical in LOGICAL_TO_ENCODED}
EXPECTED_WHEEL_RESOURCES = {*CONFIG_SOURCES, *TELEMETRY_SOURCES}
EXPECTED_SDIST_CONFIG_INPUTS = {
    "schemas/config/v8/defenseclaw-config.schema.json",
    "schemas/config/v8/reference/observability.yaml",
    "schemas/config/v8/reference/observability.md",
}
EXPECTED_SDIST_TELEMETRY_INPUTS = set(LOGICAL_TO_ENCODED.values())


class BuiltArtifacts(NamedTuple):
    wheel: Path
    sdist: Path
    sdist_wheel: Path


@pytest.fixture(scope="module")
def build_hook_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("defenseclaw_build_setup", ROOT / "setup.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    setuptools_module = ModuleType("setuptools")
    setuptools_module.setup = lambda **_kwargs: None  # type: ignore[attr-defined]
    command_module = ModuleType("setuptools.command")
    build_py_module = ModuleType("setuptools.command.build_py")
    build_py_module.build_py = object  # type: ignore[attr-defined]
    with mock.patch.dict(
        sys.modules,
        {
            "setuptools": setuptools_module,
            "setuptools.command": command_module,
            "setuptools.command.build_py": build_py_module,
        },
    ):
        spec.loader.exec_module(module)
    return module


def _copy_v8_build_inputs(destination: Path) -> None:
    required = {
        Path("scripts/telemetry_runtime_assets.py"),
        *[Path(path) for path in EXPECTED_SDIST_CONFIG_INPUTS],
        *[Path(path) for path in EXPECTED_SDIST_TELEMETRY_INPUTS],
    }
    for relative in sorted(required):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)


def _copy_pristine_source(destination: Path) -> None:
    required_files = {
        Path("pyproject.toml"),
        Path("setup.py"),
        Path("MANIFEST.in"),
        Path("README.md"),
        Path("LICENSE"),
        Path("NOTICE"),
        Path("internal/envvars/registry.json"),
        Path("scripts/telemetry_runtime_assets.py"),
        *[Path(path) for path in EXPECTED_SDIST_CONFIG_INPUTS],
        *[Path(path) for path in EXPECTED_SDIST_TELEMETRY_INPUTS],
    }
    for relative in sorted(required_files):
        source = ROOT / relative
        assert source.is_file(), relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)

    for relative in (
        Path("cli/defenseclaw"),
        Path("bundles/local_observability_stack"),
        Path("bundles/splunk_local_bridge"),
    ):
        shutil.copytree(
            ROOT / relative,
            destination / relative,
            ignore=shutil.ignore_patterns("_data", "__pycache__", "*.pyc"),
        )


@pytest.mark.parametrize("mutation", ["missing", "unexpected", "malformed-config", "malformed-gzip"])
def test_build_hook_fails_closed_for_invalid_v8_inputs(
    build_hook_module: ModuleType,
    tmp_path: Path,
    mutation: str,
) -> None:
    source = tmp_path / "source"
    _copy_v8_build_inputs(source)
    if mutation == "missing":
        (source / "schemas/config/v8/defenseclaw-config.schema.json").unlink()
    elif mutation == "unexpected":
        (source / "schemas/config/v8/unexpected.json").write_text("{}\n", encoding="utf-8")
    elif mutation == "malformed-config":
        (source / "schemas/config/v8/defenseclaw-config.schema.json").write_text(
            "{",
            encoding="utf-8",
        )
    else:
        (source / "schemas/telemetry/runtime/catalog.json.gz").write_bytes(b"not-gzip")

    with pytest.raises(RuntimeError):
        build_hook_module._stage_v8_assets(source, tmp_path / "build")


def test_build_hook_rejects_duplicate_v8_source_contract(
    build_hook_module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    _copy_v8_build_inputs(source)
    duplicate_contract = {
        **build_hook_module.CONFIG_ASSETS,
        "duplicate.json": Path("defenseclaw-config.schema.json"),
    }
    monkeypatch.setattr(build_hook_module, "CONFIG_ASSETS", duplicate_contract)

    with pytest.raises(RuntimeError, match="duplicated"):
        build_hook_module._stage_v8_assets(source, tmp_path / "build")


def _run_build(arguments: list[str], *, cwd: Path, environment: dict[str, str]) -> None:
    completed = subprocess.run(
        arguments,
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    assert completed.returncode == 0, (completed.stdout + completed.stderr)[-8000:]


@pytest.fixture(scope="module")
def pristine_artifacts() -> Iterator[BuiltArtifacts]:
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is required to verify PEP 517 packaging")

    with tempfile.TemporaryDirectory(prefix="dc-v8-wheel-") as temporary_name:
        temporary = Path(temporary_name)
        source = temporary / "source"
        source.mkdir()
        _copy_pristine_source(source)
        assert not (source / "cli/defenseclaw/_data").exists()

        environment = os.environ.copy()
        environment.pop("PYTHONHOME", None)
        environment.pop("PYTHONPATH", None)
        environment["UV_CACHE_DIR"] = str(temporary / "uv-cache")

        wheel_output = temporary / "wheel"
        _run_build(
            [uv, "build", "--force-pep517", "--wheel", "--out-dir", str(wheel_output)],
            cwd=source,
            environment=environment,
        )
        wheel = next(wheel_output.glob("defenseclaw-*.whl"))

        sdist_output = temporary / "sdist"
        _run_build(
            [uv, "build", "--force-pep517", "--sdist", "--out-dir", str(sdist_output)],
            cwd=source,
            environment=environment,
        )
        sdist = next(sdist_output.glob("defenseclaw-*.tar.gz"))

        sdist_wheel_output = temporary / "sdist-wheel"
        _run_build(
            [
                uv,
                "build",
                "--force-pep517",
                "--wheel",
                "--out-dir",
                str(sdist_wheel_output),
                str(sdist),
            ],
            cwd=temporary,
            environment=environment,
        )
        sdist_wheel = next(sdist_wheel_output.glob("defenseclaw-*.whl"))
        assert not (source / "cli/defenseclaw/_data").exists()
        yield BuiltArtifacts(wheel=wheel, sdist=sdist, sdist_wheel=sdist_wheel)


def _expected_resource_bytes() -> dict[str, bytes]:
    return {
        **{member: source.read_bytes() for member, source in CONFIG_SOURCES.items()},
        **{member: read_logical_asset(ROOT, logical) for member, logical in TELEMETRY_SOURCES.items()},
    }


def _assert_exact_v8_wheel(wheel: Path) -> None:
    expected = _expected_resource_bytes()
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        actual = {
            name
            for name in names
            if not name.endswith("/")
            and (name.startswith(f"{PACKAGE_PREFIX}config/v8/") or name.startswith(f"{PACKAGE_PREFIX}telemetry/v8/"))
        }
        assert actual == EXPECTED_WHEEL_RESOURCES
        assert not any(name.startswith("schemas/") for name in names)
        for member, source in expected.items():
            assert names.count(member) == 1
            assert archive.read(member) == source


def _extract_wheel_safely(wheel: Path, destination: Path) -> None:
    destination.mkdir()
    resolved_destination = destination.resolve()
    with zipfile.ZipFile(wheel) as archive:
        for member in archive.infolist():
            relative = PurePosixPath(member.filename)
            if relative.is_absolute() or ".." in relative.parts:
                raise AssertionError(f"unsafe wheel member path: {member.filename}")
            if ((member.external_attr >> 16) & 0o170000) == 0o120000:
                raise AssertionError(f"wheel member must not be a symlink: {member.filename}")
            target = (destination / Path(*relative.parts)).resolve()
            try:
                target.relative_to(resolved_destination)
            except ValueError as exc:
                raise AssertionError(f"wheel member escapes destination: {member.filename}") from exc
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)


def test_pristine_pep517_wheel_contains_exact_v8_resources(
    pristine_artifacts: BuiltArtifacts,
) -> None:
    _assert_exact_v8_wheel(pristine_artifacts.wheel)


def test_sdist_contains_exact_build_inputs_and_builds_complete_wheel(
    pristine_artifacts: BuiltArtifacts,
) -> None:
    with tarfile.open(pristine_artifacts.sdist, mode="r:gz") as archive:
        relative_names = []
        for member in archive.getmembers():
            parts = PurePosixPath(member.name).parts
            if len(parts) > 1 and member.isfile():
                relative_names.append(PurePosixPath(*parts[1:]).as_posix())

    assert set(name for name in relative_names if name.startswith("schemas/config/v8/")) == (
        EXPECTED_SDIST_CONFIG_INPUTS
    )
    assert (
        set(name for name in relative_names if name.startswith("schemas/telemetry/runtime/"))
        == EXPECTED_SDIST_TELEMETRY_INPUTS
    )
    for required in (
        "setup.py",
        "internal/envvars/registry.json",
        "scripts/telemetry_runtime_assets.py",
    ):
        assert relative_names.count(required) == 1

    _assert_exact_v8_wheel(pristine_artifacts.sdist_wheel)


@pytest.mark.parametrize("wheel_kind", ["wheel", "sdist_wheel"])
def test_installed_wheel_loads_v8_resources_without_checkout_fallback(
    pristine_artifacts: BuiltArtifacts,
    tmp_path: Path,
    wheel_kind: str,
) -> None:
    wheel = getattr(pristine_artifacts, wheel_kind)
    installed = tmp_path / "installed"
    _extract_wheel_safely(wheel, installed)

    code = """
import json
import sys
from importlib import resources
from pathlib import Path

installed = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(installed))

import defenseclaw
from defenseclaw.observability.schema_resources import (
    telemetry_v8_catalog_bytes,
    telemetry_v8_compatibility_profile_bytes,
    telemetry_v8_schema_bytes,
    v7_exporter_selection_bytes,
)
from defenseclaw.observability.v8_config import load_validate_v8

module_path = Path(defenseclaw.__file__).resolve()
assert module_path.is_relative_to(installed)
fallback = module_path.parents[2] / "schemas" / "config" / "v8" / "defenseclaw-config.schema.json"
assert not fallback.exists()

package = resources.files("defenseclaw")
reference = package.joinpath("_data", "config", "v8", "observability.yaml").read_text(
    encoding="utf-8"
)
documentation = package.joinpath("_data", "config", "v8", "observability.md").read_text(
    encoding="utf-8"
)
assert reference.strip()
assert documentation.strip()
load_validate_v8({"config_version": 8}, source_name="installed-package-probe")

payloads = [
    telemetry_v8_schema_bytes(),
    telemetry_v8_catalog_bytes(),
    v7_exporter_selection_bytes(),
    *[
        telemetry_v8_compatibility_profile_bytes(profile_id)
        for profile_id in (
            "galileo-rich-v2",
            "local-observability-v1",
            "openinference-v1",
        )
    ],
]
assert len(payloads) == 6
assert all(isinstance(json.loads(payload), dict) for payload in payloads)
"""
    environment = os.environ.copy()
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [sys.executable, "-I", "-c", code, str(installed)],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
