# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Release dependency invariants for the managed Python environment."""

from __future__ import annotations

import email
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = REPO_ROOT / "pyproject.toml"
UV_LOCK = REPO_ROOT / "uv.lock"

RUNTIME_CONTRACT = {
    "rich": (">=14.2,<15", None),
    "textual": (">=7,<8", None),
    "litellm": (">=1.84.0,<2", None),
    "importlib-metadata": (">=8.7.1,<8.8", None),
}

MCP_SCANNER_VERSION = "4.3.0"
MCP_SCANNER_SHA256 = "ea1a30d6bc282f2b4081bc4eced4287a20326891588624d5b2e07b388710b812"


def _requirements(values: list[str]) -> dict[str, Requirement]:
    return {Requirement(value).name.lower(): Requirement(value) for value in values}


def _assert_runtime_contract(requirements: dict[str, Requirement]) -> None:
    for name, (specifier, marker) in RUNTIME_CONTRACT.items():
        requirement = requirements[name]
        assert requirement.specifier == SpecifierSet(specifier)
        assert (str(requirement.marker) if requirement.marker else None) == marker


def test_runtime_contract_is_direct_and_synchronized_with_uv_overrides() -> None:
    document = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    direct = _requirements(document["project"]["dependencies"])
    overrides = _requirements(document["tool"]["uv"]["override-dependencies"])

    _assert_runtime_contract(direct)
    _assert_runtime_contract(overrides)
    mcp_scanner = direct["cisco-ai-mcp-scanner"]
    assert str(mcp_scanner.url).endswith(
        f"cisco_ai_mcp_scanner-{MCP_SCANNER_VERSION}-py3-none-any.whl#sha256={MCP_SCANNER_SHA256}"
    )
    assert str(direct["cisco-ai-mcp-scanner"].marker) == 'python_version >= "3.11"'
    assert "cisco-ai-skill-scanner" in direct


def test_dependency_repair_cannot_lower_security_floors() -> None:
    document = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    for requirement_set in (
        document["project"]["dependencies"],
        document["tool"]["uv"]["override-dependencies"],
    ):
        requirements = _requirements(requirement_set)
        assert Version("1.83.7") not in requirements["litellm"].specifier
        assert Version("1.84.0") in requirements["litellm"].specifier
        assert Version("8.5.0") not in requirements["importlib-metadata"].specifier
        assert Version("8.7.1") in requirements["importlib-metadata"].specifier
        assert Version("8.8.0") not in requirements["importlib-metadata"].specifier


def test_lock_records_the_same_runtime_contract() -> None:
    lock = tomllib.loads(UV_LOCK.read_text(encoding="utf-8"))
    overrides = {entry["name"]: (entry["specifier"], entry.get("marker")) for entry in lock["manifest"]["overrides"]}
    expected = {
        "rich": (">=14.2,<15", None),
        "textual": (">=7,<8", None),
        "litellm": (">=1.84.0,<2", None),
        "importlib-metadata": (">=8.7.1,<8.8", None),
    }
    assert {name: overrides[name] for name in expected} == expected

    locked = {package["name"]: package["version"] for package in lock["package"]}
    assert locked["cisco-ai-mcp-scanner"] == MCP_SCANNER_VERSION
    assert locked["textual"] == "7.5.0"
    assert Version(locked["litellm"]) >= Version("1.84.0")
    assert Version(locked["importlib-metadata"]) >= Version("8.7.1")
    assert Version(locked["rich"]) in Requirement("rich>=14.2,<15").specifier


def test_scanner_metadata_intersection_is_satisfiable() -> None:
    # Authoritative Requires-Dist fields from the shipped scanner wheels:
    # skill scanner 2.0.11: rich>=14,<15 and textual>=7,<8;
    # Textual 7.5.0: rich>=14.2; MCP scanner 4.3.0: litellm>=1.77.0;
    # project security policy: litellm>=1.84.0 and importlib-metadata>=8.7.1.
    intersections = {
        "rich": [Requirement("rich>=14,<15"), Requirement("rich>=14.2"), Requirement("rich>=14.2,<15")],
        "textual": [Requirement("textual>=7,<8"), Requirement("textual>=7,<8")],
        "litellm": [Requirement("litellm>=1.77.0"), Requirement("litellm>=1.84.0,<2")],
        "importlib-metadata": [
            Requirement("importlib-metadata>=8.7.1,<8.8"),
        ],
    }
    witnesses = {
        "rich": Version("14.2.0"),
        "textual": Version("7.5.0"),
        "litellm": Version("1.84.0"),
        "importlib-metadata": Version("8.7.1"),
    }
    for name, requirements in intersections.items():
        assert all(witnesses[name] in requirement.specifier for requirement in requirements)


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv is required to build release metadata")
def test_fresh_wheel_metadata_contains_complete_runtime_contract(tmp_path: Path) -> None:
    source = tmp_path / "source"
    shutil.copytree(
        REPO_ROOT,
        source,
        ignore=shutil.ignore_patterns(
            ".git",
            ".venv",
            ".pytest_cache",
            "__pycache__",
            "*.pyc",
            "build",
            "dist",
            "*.egg-info",
        ),
    )
    output = tmp_path / "wheel"
    env = os.environ.copy()
    env.pop("PYTHONHOME", None)
    env.pop("PYTHONPATH", None)
    completed = subprocess.run(
        [shutil.which("uv"), "build", "--wheel", "--out-dir", str(output)],
        cwd=source,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
        check=False,
    )
    assert completed.returncode == 0, (completed.stdout + completed.stderr)[-4000:]
    wheel = next(output.glob("defenseclaw-*.whl"))
    with zipfile.ZipFile(wheel) as archive:
        metadata_name = next(name for name in archive.namelist() if name.endswith(".dist-info/METADATA"))
        metadata = email.message_from_bytes(archive.read(metadata_name))

    wheel_requirements = _requirements(metadata.get_all("Requires-Dist", []))
    _assert_runtime_contract(wheel_requirements)
    assert "cisco-ai-skill-scanner" in wheel_requirements
    assert "cisco-ai-mcp-scanner" in wheel_requirements
