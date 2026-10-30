# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-0020: MCP Scanner 4.8.7 pins litellm==1.93.2; DefenseClaw overrides it.

Every install path installs the hash-pinned lock with --no-deps, so the
environment must hold the secure LiteLLM, and the dependency check must
allow exactly that one override and nothing else.
"""

from __future__ import annotations

import importlib.metadata as importlib_metadata
import importlib.util
import shutil
import subprocess
from pathlib import Path

import pytest
from packaging.specifiers import SpecifierSet
from packaging.version import Version

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER = REPO_ROOT / "scripts" / "check_python_dependency_metadata.py"
SECURE_LITELLM = SpecifierSet(">=1.103.10,<1.104.0")


def _checker():
    spec = importlib.util.spec_from_file_location("check_python_dependency_metadata", CHECKER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_installed_environment_runs_mcp_scanner_4_8_7_on_the_secure_litellm() -> None:
    assert importlib_metadata.version("cisco-ai-mcp-scanner") == "4.8.7"
    assert Version(importlib_metadata.version("litellm")) in SECURE_LITELLM
    assert Version(importlib_metadata.version("mcp")) >= Version("2.2.0")


def test_the_only_allowed_override_is_mcp_scanner_4_8_7_litellm_pin() -> None:
    allowed = _checker().ALLOWED_OVERRIDES
    assert list(allowed) == [("cisco-ai-mcp-scanner", "4.8.7", "litellm==1.93.2")]
    package, specifier = allowed[("cisco-ai-mcp-scanner", "4.8.7", "litellm==1.93.2")]
    assert (package, SpecifierSet(specifier)) == ("litellm", SECURE_LITELLM)


def test_installed_environment_passes_the_dependency_check() -> None:
    assert _checker().problems() == []


class _Dist:
    def __init__(self, name: str, version: str, requires: list[str]) -> None:
        self.metadata = {"Name": name}
        self.version = version
        self.requires = requires


@pytest.mark.parametrize(
    ("scanner_version", "litellm_version", "expected"),
    [
        ("4.8.7", "1.103.10", []),
        # The allowance never covers a vulnerable LiteLLM ...
        ("4.8.7", "1.103.9", ["cisco-ai-mcp-scanner 4.8.7: litellm 1.103.9 violates ==1.93.2"]),
        # ... nor another scanner release.
        ("4.8.6", "1.103.10", ["cisco-ai-mcp-scanner 4.8.6: litellm 1.103.10 violates ==1.93.2"]),
    ],
)
def test_allowance_is_scoped_to_the_exact_release_and_the_secure_range(
    monkeypatch: pytest.MonkeyPatch, scanner_version: str, litellm_version: str, expected: list[str]
) -> None:
    module = _checker()
    dists = [
        _Dist("cisco-ai-mcp-scanner", scanner_version, ["litellm==1.93.2"]),
        _Dist("litellm", litellm_version, []),
    ]
    monkeypatch.setattr(module.metadata, "distributions", lambda path=None: list(dists))
    assert module.problems() == expected


def test_other_unmet_requirements_still_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _checker()
    dists = [
        _Dist("cisco-ai-mcp-scanner", "4.8.7", ["litellm==1.93.2", "mcp[cli]>=2.0.0", "puremagic>=1.28"]),
        _Dist("litellm", "1.103.10", []),
        _Dist("mcp", "1.30.0", []),
    ]
    monkeypatch.setattr(module.metadata, "distributions", lambda path=None: list(dists))
    assert module.problems() == [
        "cisco-ai-mcp-scanner 4.8.7: mcp 1.30.0 violates >=2.0.0",
        "cisco-ai-mcp-scanner 4.8.7: missing puremagic",
    ]


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv exports the release requirements")
def test_release_requirements_pin_the_secure_litellm_and_the_attested_scanner() -> None:
    # The same export `make dist-requirements` ships next to the wheel.
    completed = subprocess.run(
        [shutil.which("uv"), "export", "--frozen", "--no-dev", "--no-emit-project", "--no-header",
         "--format", "requirements-txt"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True, timeout=120,
    )
    lines = completed.stdout.splitlines()
    pins = [line.split(" ", 1)[0] for line in lines if line and not line.startswith((" ", "#"))]
    litellm = [pin for pin in pins if pin.startswith("litellm==")]
    assert len(litellm) == 1 and Version(litellm[0].split("==", 1)[1]) in SECURE_LITELLM
    assert "litellm==1.93.2" not in completed.stdout
    scanner = [line for line in lines if line.startswith("cisco-ai-mcp-scanner @ ")]
    assert len(scanner) == 1 and "cisco_ai_mcp_scanner-4.8.7-py3-none-any.whl" in scanner[0]
    mcp = [pin for pin in pins if pin.startswith("mcp==")]
    assert len(mcp) == 1 and Version(mcp[0].split("==", 1)[1]) >= Version("2.2.0")
    # Every pinned package carries a hash, so installers can use --require-hashes --no-deps.
    assert completed.stdout.count("--hash=sha256:") >= len(pins)


def test_checker_is_shipped_to_every_dependency_check_site() -> None:
    for rel in ("scripts/build-windows-installer.ps1", "scripts/windows-native-ci.ps1", ".github/workflows/ci.yml"):
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        assert "check_python_dependency_metadata.py" in text, rel
    native = (REPO_ROOT / "scripts/windows-native-ci.ps1").read_text(encoding="utf-8")
    assert "'pip', 'check'" not in native
