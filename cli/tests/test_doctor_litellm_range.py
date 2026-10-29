# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

import importlib.metadata
from pathlib import Path

import pytest
from defenseclaw.commands.cmd_doctor import _litellm_version_note
from defenseclaw.scanner import settings
from packaging.requirements import Requirement

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


@pytest.mark.parametrize(
    ("version", "status"),
    [
        ("1.91.5", "warn"),
        ("1.100.3", "warn"),
        ("1.100.4", "pass"),
        ("1.100.99", "pass"),
        ("1.101.0", "warn"),
        ("2.0.0", "warn"),
        ("1.100.4rc1", "warn"),
        ("1.100.4.dev1", "warn"),
        ("1.100.4.post1", "pass"),
        ("1.100.4+local", "pass"),
        ("unreadable", "warn"),
    ],
)
def test_litellm_doctor_checks_both_supported_boundaries(monkeypatch, version, status):
    original = importlib.metadata.version
    monkeypatch.setattr(importlib.metadata, "version", lambda name: version if name == "litellm" else original(name))
    actual, note = _litellm_version_note()
    assert actual == status
    if status == "warn":
        assert ">=1.100.4,<1.101.0" in note


def test_litellm_doctor_range_matches_the_runtime_dependency():
    project = tomllib.loads((Path(__file__).resolve().parents[2] / "pyproject.toml").read_text())
    dependency = next(
        Requirement(item) for item in project["project"]["dependencies"] if Requirement(item).name == "litellm"
    )
    bounds = (
        ">="
        + ".".join(map(str, settings.LITELLM_MIN_VERSION))
        + ",<"
        + ".".join(map(str, settings.LITELLM_MAX_VERSION))
    )
    assert dependency.specifier == Requirement("litellm" + bounds).specifier
