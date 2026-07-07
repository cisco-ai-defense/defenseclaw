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
import importlib.metadata as importlib_metadata
import inspect
import json
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
    "textual": (">=8.2.8,<9", None),
    "litellm": (">=1.84.0,<2", None),
    "importlib-metadata": (">=8.7.1,<8.8", None),
}

SKILL_SCANNER_VERSION = "2.0.4"
SKILL_SCANNER_SHA256 = "8ac399d4542870fad7b09027b9d45f0668788dfff3a5a95603c6f195430a5d74"
MCP_SCANNER_VERSION = "4.3.0"
MCP_SCANNER_SHA256 = "ea1a30d6bc282f2b4081bc4eced4287a20326891588624d5b2e07b388710b812"
TEXTUAL_LOCKED_VERSION = "8.2.8"


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
    skill_scanner = direct["cisco-ai-skill-scanner"]
    assert str(skill_scanner.url).endswith(
        f"cisco_ai_skill_scanner-{SKILL_SCANNER_VERSION}-py3-none-any.whl#sha256={SKILL_SCANNER_SHA256}"
    )


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


def test_dev_graph_does_not_force_incompatible_snapshot_metadata() -> None:
    """The unused snapshot plugin cannot coexist with the project's pytest 9 pin."""
    document = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    dev = _requirements(document["dependency-groups"]["dev"])
    overrides = _requirements(document["tool"]["uv"]["override-dependencies"])
    # pytest-textual-snapshot 1.1.0 pins syrupy==4.8.0, whose authoritative
    # wheel metadata requires pytest<9. DefenseClaw's SVG tests use Textual's
    # export_screenshot directly, so retaining an unused overridden plugin
    # would make uv pip check fail without providing test coverage.
    assert "pytest-textual-snapshot" not in dev
    assert "syrupy" not in overrides


def test_lock_records_the_same_runtime_contract() -> None:
    lock = tomllib.loads(UV_LOCK.read_text(encoding="utf-8"))
    overrides = {entry["name"]: (entry["specifier"], entry.get("marker")) for entry in lock["manifest"]["overrides"]}
    expected = {
        "rich": (">=14.2,<15", None),
        "textual": (">=8.2.8,<9", None),
        "litellm": (">=1.84.0,<2", None),
        "importlib-metadata": (">=8.7.1,<8.8", None),
    }
    assert {name: overrides[name] for name in expected} == expected

    locked = {package["name"]: package["version"] for package in lock["package"]}
    assert locked["cisco-ai-skill-scanner"] == SKILL_SCANNER_VERSION
    assert locked["cisco-ai-mcp-scanner"] == MCP_SCANNER_VERSION
    assert locked["textual"] == TEXTUAL_LOCKED_VERSION
    assert Version(locked["litellm"]) >= Version("1.84.0")
    assert Version(locked["importlib-metadata"]) >= Version("8.7.1")
    assert Version(locked["rich"]) in Requirement("rich>=14.2,<15").specifier


def test_scanner_metadata_intersection_is_satisfiable() -> None:
    # Authoritative Requires-Dist fields from the shipped scanner wheels:
    # skill scanner 2.0.4: rich>=13, textual>=1, and litellm>=1.77;
    # Textual 8.2.8: rich>=14.2; MCP scanner 4.3.0: litellm>=1.77.0;
    # project policy: Textual>=8.2.8,<9, Rich>=14.2,<15, LiteLLM>=1.84,<2.
    # Scanner 2.0.5-2.0.9 instead pin old LiteLLM/Textual releases, and
    # 2.0.10-2.0.12 cap Textual<8, so 2.0.4 is the newest viable wheel.
    intersections = {
        "rich": [Requirement("rich>=13"), Requirement("rich>=14.2"), Requirement("rich>=14.2,<15")],
        "textual": [Requirement("textual>=1"), Requirement("textual>=8.2.8,<9")],
        "litellm": [
            Requirement("litellm>=1.77.0"),
            Requirement("litellm>=1.77.0"),
            Requirement("litellm>=1.84.0,<2"),
        ],
        "importlib-metadata": [
            Requirement("importlib-metadata>=8.7.1,<8.8"),
        ],
    }
    witnesses = {
        "rich": Version("14.3.4"),
        "textual": Version(TEXTUAL_LOCKED_VERSION),
        "litellm": Version("1.91.0"),
        "importlib-metadata": Version("8.7.1"),
    }
    for name, requirements in intersections.items():
        assert all(witnesses[name] in requirement.specifier for requirement in requirements)


def test_production_textual_behavior_has_a_packaging_floor() -> None:
    """The wheel must exclude releases missing APIs used by the production TUI."""
    document = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    textual_requirement = _requirements(document["project"]["dependencies"])["textual"]

    # Tabs.get_tab arrived in Textual 8.0; ansi-dark/ansi-light and the
    # theme-driven App.ansi_color behavior arrived in 8.2.5. The tested floor
    # is 8.2.8, so metadata must reject both Textual 7 and early 8.2 builds.
    for unsupported in (Version("7.5.0"), Version("8.0.0"), Version("8.2.4")):
        assert unsupported not in textual_requirement.specifier
    assert Version(TEXTUAL_LOCKED_VERSION) in textual_requirement.specifier
    assert Version("9.0.0") not in textual_requirement.specifier

    from textual.app import App
    from textual.dom import DOMNode
    from textual.theme import BUILTIN_THEMES
    from textual.widgets import Tabs

    assert callable(Tabs.get_tab)
    assert callable(DOMNode.update_classes)
    assert {"ansi-dark", "ansi-light"}.issubset(BUILTIN_THEMES)
    assert hasattr(App, "ansi_color")


def test_pinned_skill_scanner_api_and_local_scan(tmp_path: Path) -> None:
    """Exercise every upstream API entry point used by the production wrapper."""
    assert importlib_metadata.version("cisco-ai-skill-scanner") == SKILL_SCANNER_VERSION

    from skill_scanner import SkillScanner
    from skill_scanner.core.analyzer_factory import build_analyzers
    from skill_scanner.core.scan_policy import ScanPolicy

    factory_parameters = inspect.signature(build_analyzers).parameters
    assert {
        "policy",
        "use_behavioral",
        "use_llm",
        "llm_model",
        "llm_api_key",
        "llm_base_url",
        "use_virustotal",
        "use_aidefense",
        "use_trigger",
        "llm_consensus_runs",
    }.issubset(factory_parameters)
    assert "lenient" in inspect.signature(SkillScanner.scan_skill).parameters

    skill = tmp_path / "clean-skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\n"
        "name: clean-test-skill\n"
        "description: A local deterministic fixture that echoes operator-provided text.\n"
        "license: Apache-2.0\n"
        "---\n\n"
        "# Clean test skill\n\nReturn the provided text unchanged.\n",
        encoding="utf-8",
    )
    policy = ScanPolicy.default()
    analyzers = build_analyzers(policy=policy)
    result = SkillScanner(analyzers=analyzers, policy=policy).scan_skill(skill)
    assert result is not None
    assert hasattr(result, "findings")


def test_pinned_mcp_scanner_runs_offline_yara_scan(tmp_path: Path) -> None:
    assert importlib_metadata.version("cisco-ai-mcp-scanner") == MCP_SCANNER_VERSION
    executable = shutil.which("mcp-scanner")
    assert executable is not None
    fixture = tmp_path / "tools.json"
    fixture.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "get_weather",
                        "description": "Return the current weather for a named city.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"city": {"type": "string"}},
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    completed = subprocess.run(
        [executable, "--analyzers", "yara", "--format", "raw", "static", "--tools", str(fixture)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["scan_results"][0]["tool_name"] == "get_weather"


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
        assert "defenseclaw/_data/envvars/registry.json" in archive.namelist()
        bundled_registry = json.loads(archive.read("defenseclaw/_data/envvars/registry.json"))
        source_registry = json.loads((REPO_ROOT / "internal" / "envvars" / "registry.json").read_bytes())
        assert bundled_registry == source_registry

    wheel_requirements = _requirements(metadata.get_all("Requires-Dist", []))
    _assert_runtime_contract(wheel_requirements)
    assert str(wheel_requirements["cisco-ai-skill-scanner"].url).endswith(
        f"cisco_ai_skill_scanner-{SKILL_SCANNER_VERSION}-py3-none-any.whl#sha256={SKILL_SCANNER_SHA256}"
    )
    assert "cisco-ai-mcp-scanner" in wheel_requirements
