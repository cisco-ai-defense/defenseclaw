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
import subprocess
import sys
import zipfile
from functools import partial
from pathlib import Path
from typing import Any

import pytest
from defenseclaw.observability import schema_resources

from scripts.telemetry_runtime_assets import read_logical_asset

ROOT = Path(__file__).resolve().parents[2]
STAGED_DIR = ROOT / "cli" / "defenseclaw" / "_data" / "telemetry" / "v8"
EXPECTED_RESOURCES = {
    "telemetry.schema.json": ("telemetry.schema.json", schema_resources.telemetry_v8_schema_bytes),
    "catalog.json": ("catalog.json", schema_resources.telemetry_v8_catalog_bytes),
    "v7-exporter-selection.json": (
        "compatibility/v7-exporter-selection.json",
        schema_resources.v7_exporter_selection_bytes,
    ),
    **{
        f"{profile_id}.json": (
            f"compatibility/{profile_id}.json",
            partial(schema_resources.telemetry_v8_compatibility_profile_bytes, profile_id),
        )
        for profile_id in (
            "galileo-rich-v2",
            "local-observability-v1",
            "openinference-v1",
        )
    },
}


def _source_bytes(source_name: str) -> bytes:
    return read_logical_asset(ROOT, f"schemas/telemetry/generated/{source_name}")
EXPECTED_PACKAGE_DATA = {
    "_data/telemetry/v8/telemetry.schema.json",
    "_data/telemetry/v8/catalog.json",
    "_data/telemetry/v8/v7-exporter-selection.json",
    "_data/telemetry/v8/galileo-rich-v2.json",
    "_data/telemetry/v8/local-observability-v1.json",
    "_data/telemetry/v8/openinference-v1.json",
}


def _load_pyproject() -> dict[str, Any]:
    try:
        import tomllib
    except ImportError:  # pragma: no cover - Python 3.10 support
        import tomli as tomllib  # type: ignore[no-redef]

    with (ROOT / "pyproject.toml").open("rb") as stream:
        return tomllib.load(stream)


@pytest.mark.parametrize(("name", "resource"), EXPECTED_RESOURCES.items())
def test_packaged_telemetry_resource_matches_generated_source(
    name: str,
    resource: tuple[str, Any],
) -> None:
    source_name, loader = resource
    source = _source_bytes(source_name)
    staged = (STAGED_DIR / name).read_bytes()
    packaged = loader()

    assert staged == source
    assert packaged == source
    assert type(packaged) is bytes
    with pytest.raises(TypeError):
        packaged[0] = 0  # type: ignore[index]

    document = json.loads(packaged)
    marker = document["x-defenseclaw-generated"]
    assert marker["artifact"] == source_name
    assert marker["registry_version"] == 1


def test_staged_telemetry_inventory_is_exact() -> None:
    assert {path.name for path in STAGED_DIR.iterdir() if path.is_file()} == set(EXPECTED_RESOURCES)
    assert not any(path.is_dir() for path in STAGED_DIR.iterdir())


@pytest.mark.parametrize(
    "loader",
    [
        schema_resources.telemetry_v8_schema_bytes,
        schema_resources.telemetry_v8_catalog_bytes,
        schema_resources.v7_exporter_selection_bytes,
        *(
            partial(schema_resources.telemetry_v8_compatibility_profile_bytes, profile_id)
            for profile_id in (
                "galileo-rich-v2",
                "local-observability-v1",
                "openinference-v1",
            )
        ),
    ],
)
def test_resource_loader_has_no_repository_fallback(
    monkeypatch: pytest.MonkeyPatch,
    loader: Any,
) -> None:
    class MissingResource:
        def joinpath(self, _resource: str) -> MissingResource:
            return self

        def read_bytes(self) -> bytes:
            raise FileNotFoundError("simulated missing package resource")

    monkeypatch.setattr(schema_resources.resources, "files", lambda _package: MissingResource())
    with pytest.raises(FileNotFoundError, match="simulated missing package resource"):
        loader()


def test_telemetry_package_data_is_exact_and_staging_is_untracked() -> None:
    package_data = _load_pyproject()["tool"]["setuptools"]["package-data"]["defenseclaw"]
    telemetry_entries = {entry for entry in package_data if entry.startswith("_data/telemetry/")}
    assert telemetry_entries == EXPECTED_PACKAGE_DATA

    tracked = subprocess.run(
        ["git", "ls-files", "--", "cli/defenseclaw/_data/telemetry"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert tracked.stdout == ""
    for name in EXPECTED_RESOURCES:
        ignored = subprocess.run(
            ["git", "check-ignore", "-q", str((STAGED_DIR / name).relative_to(ROOT))],
            cwd=ROOT,
            check=False,
        )
        assert ignored.returncode == 0


def test_built_wheel_loads_telemetry_compatibility_resources_from_installed_package_only(
    tmp_path: Path,
) -> None:
    dist = tmp_path / "dist"
    completed = subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(dist)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    wheel = next(dist.glob("*.whl"))
    installed = tmp_path / "installed"
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(installed)

    expected = {
        "v7-exporter-selection": hashlib.sha256(
            _source_bytes("compatibility/v7-exporter-selection.json")
        ).hexdigest(),
        **{
            profile_id: hashlib.sha256(_source_bytes(f"compatibility/{profile_id}.json")).hexdigest()
            for profile_id in (
                "galileo-rich-v2",
                "local-observability-v1",
                "openinference-v1",
            )
        },
    }
    code = f"""
import hashlib
import json
import sys
sys.path.insert(0, {str(installed)!r})
from defenseclaw.observability.schema_resources import (
    telemetry_v8_compatibility_profile_bytes,
    v7_exporter_selection_bytes,
)
from defenseclaw.observability.v8_compatibility import load_packaged_v7_compatibility_selection
raw = v7_exporter_selection_bytes()
selection = load_packaged_v7_compatibility_selection()
audit_selector = next(selector for selector in selection.exporter_selectors('audit_sink', 'logs') if selector.actions)
assert len(audit_selector.actions) == 188
print(json.dumps({{
    'v7-exporter-selection': hashlib.sha256(raw).hexdigest(),
    **{{profile_id: hashlib.sha256(telemetry_v8_compatibility_profile_bytes(profile_id)).hexdigest()
       for profile_id in ('galileo-rich-v2', 'local-observability-v1', 'openinference-v1')}},
}}, sort_keys=True))
"""
    loaded = subprocess.run(
        [sys.executable, "-I", "-c", code],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert loaded.returncode == 0, loaded.stderr
    assert json.loads(loaded.stdout) == expected


def test_unknown_compatibility_profile_fails_without_resource_probe() -> None:
    with pytest.raises(ValueError, match="unknown telemetry compatibility profile"):
        schema_resources.telemetry_v8_compatibility_profile_bytes("unknown-v1")
