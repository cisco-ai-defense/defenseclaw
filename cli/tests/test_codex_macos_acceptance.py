# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

from defenseclaw import agent_selection, platform_support
from defenseclaw.inventory import claw_inventory


def _load_macos_evidence_validator():
    path = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "live-connector-e2e"
        / "assert-macos-codex-evidence.py"
    )
    spec = importlib.util.spec_from_file_location("macos_codex_evidence", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_codex_macos_is_preview_until_latest_packaged_live_evidence_exists() -> None:
    support = platform_support.connector_platform_support("codex", "darwin")
    assert support.status == "preview"
    assert "green latest-version packaged plus authenticated live record" in support.reason


def test_codex_macos_outdatedness_decision_separates_compatibility_and_certification() -> None:
    root = Path(__file__).resolve().parents[2]
    contracts = json.loads(
        (root / "cli" / "defenseclaw" / "inventory" / "hook_contracts.json").read_text()
    )["connectors"]["codex"]["contracts"]
    ranges = [
        (
            item["contract_id"],
            item["agent_version"]["min_inclusive"],
            item["agent_version"]["max_exclusive"],
        )
        for item in contracts
    ]
    assert ranges == [
        ("codex-hooks-v1", "0.124.0", "0.129.0"),
        ("codex-hooks-v2", "0.129.0", "0.133.0"),
        ("codex-hooks-v3", "0.133.0", "0.145.0"),
        ("codex-hooks-v4", "0.145.0", ""),
    ]
    assert contracts[-1]["events"] == [
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse",
        "PermissionRequest",
        "PostToolUse",
        "SubagentStart",
        "SubagentStop",
        "PreCompact",
        "PostCompact",
        "Stop",
        "SessionEnd",
    ]

    validated = json.loads(
        (root / "cli" / "defenseclaw" / "inventory" / "validated_versions.json").read_text()
    )
    macos = validated["connectors"]["codex"]["os"]["macos"]
    assert macos == {"last_validated_version": "", "last_validated_at": "", "run_url": ""}

    ledger = (
        root / "docs" / "research" / "NATIVE-MACOS-CODEX-CONNECTOR-ACCEPTANCE.md"
    ).read_text()
    assert all(label in ledger for label in ("**OUTDATED**", "**CURRENT**", "**UNCERTIFIED**"))


@unittest.skipUnless(sys.platform == "darwin", "native macOS signing fixture")
def test_macos_codex_signature_admission_checks_team_identifier_and_quarantine(
    tmp_path: Path,
    monkeypatch,
) -> None:
    executable = tmp_path / "codex"
    executable.write_bytes(b"\xcf\xfa\xed\xfe" + b"native")
    executable.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    responses = iter(
        [
            subprocess.CompletedProcess([], 0, "arm64\n", ""),
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess(
                [],
                0,
                "",
                "Identifier=codex\n"
                "Authority=Developer ID Application: OpenAI OpCo, LLC (2DC432GLL2)\n"
                "TeamIdentifier=2DC432GLL2\n",
            ),
            subprocess.CompletedProcess([], 0, "", ""),
        ]
    )
    monkeypatch.setattr(agent_selection.subprocess, "run", lambda *_args, **_kwargs: next(responses))

    assert agent_selection._macos_codex_binary_is_trusted(str(executable))


@unittest.skipUnless(sys.platform == "darwin", "native macOS signing fixture")
def test_macos_codex_signature_admission_rejects_quarantine(
    tmp_path: Path,
    monkeypatch,
) -> None:
    executable = tmp_path / "codex"
    executable.write_bytes(b"\xcf\xfa\xed\xfe" + b"native")
    executable.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    responses = iter(
        [
            subprocess.CompletedProcess([], 0, "arm64\n", ""),
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess(
                [],
                0,
                "",
                "Identifier=codex\n"
                "Authority=Developer ID Application: OpenAI OpCo, LLC (2DC432GLL2)\n"
                "TeamIdentifier=2DC432GLL2\n",
            ),
            subprocess.CompletedProcess([], 0, "com.apple.quarantine: 0081;download\n", ""),
        ]
    )
    monkeypatch.setattr(agent_selection.subprocess, "run", lambda *_args, **_kwargs: next(responses))

    assert not agent_selection._macos_codex_binary_is_trusted(str(executable))


@unittest.skipUnless(sys.platform == "darwin", "native macOS signing fixture")
def test_macos_codex_signature_admission_rejects_wrong_architecture(
    tmp_path: Path,
    monkeypatch,
) -> None:
    executable = tmp_path / "codex"
    executable.write_bytes(b"\xcf\xfa\xed\xfe" + b"native")
    executable.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    monkeypatch.setattr(
        agent_selection.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "x86_64\n", ""),
    )

    assert not agent_selection._macos_codex_binary_is_trusted(str(executable))


def test_codex_extension_inventory_classifies_all_official_surfaces(
    tmp_path: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "home"
    workspace = tmp_path / "repo"
    home.mkdir()
    workspace.mkdir()
    monkeypatch.setenv("HOME", str(home))
    cfg = SimpleNamespace(connector_workspace_dir=lambda: str(workspace))

    surfaces = claw_inventory._codex_extension_surfaces(cfg)

    assert set(surfaces) == {
        "config",
        "hooks_notify_otel",
        "mcp",
        "skills",
        "plugins",
        "rules",
        "instructions_agents_md",
        "custom_agents",
        "microagents",
        "custom_commands",
        "legacy_extensions_directory",
        "separate_memory_files",
    }
    assert surfaces["config"]["classification"] == "I"
    assert surfaces["custom_commands"]["classification"] == "L"
    assert surfaces["legacy_extensions_directory"]["classification"] == "N/A"
    assert os.path.join(str(workspace), ".codex", "config.toml") in surfaces["mcp"]["paths"]
    assert os.path.join(str(workspace), ".agents", "skills") in surfaces["skills"]["paths"]


def test_codex_custom_agent_and_deprecated_command_inventory(tmp_path: Path) -> None:
    agents = tmp_path / "agents"
    prompts = tmp_path / "prompts"
    agents.mkdir()
    prompts.mkdir()
    (agents / "reviewer.toml").write_text(
        'name = "reviewer"\n'
        'description = "Review focused changes"\n'
        'developer_instructions = "Inspect the diff."\n'
    )
    (agents / "invalid.toml").write_text('name = "missing-fields"\n')
    (prompts / "draftpr.md").write_text("# Draft a PR\n")

    agent_rows = claw_inventory._agents_from_codex_toml_dirs([str(agents)])
    command_rows = claw_inventory._codex_custom_prompt_commands(str(prompts))

    assert [row["id"] for row in agent_rows] == ["reviewer"]
    assert command_rows == [
        {
            "id": "prompts:draftpr",
            "name": "/prompts:draftpr",
            "description": "Deprecated Codex custom prompt; migrate reusable workflows to skills.",
            "source": str(prompts / "draftpr.md"),
            "kind": "custom-command",
        }
    ]


@unittest.skipUnless(sys.platform == "darwin", "native macOS architecture fixture")
def test_macos_release_evidence_requires_latest_authenticated_complete_run() -> None:
    validator = _load_macos_evidence_validator()
    digest = "a" * 64
    payload = {
        "schema_version": 1,
        "connector": "codex",
        "os": "macos",
        "requested_version": "latest",
        "resolved_version": "0.146.0",
        "authenticated": True,
        "package": {
            "name": "@openai/codex",
            "version": "0.146.0",
            "integrity": "sha512-test",
        },
        "native": {
            "architecture": "arm64",
            "macho": True,
            "codesign_valid": True,
            "identifier": "codex",
            "team_identifier": "2DC432GLL2",
            "quarantined": False,
            "sha256": digest,
        },
        "results": {name: "pass" for name in validator.REQUIRED_RESULTS},
        "restoration": {
            "before_sha256": digest,
            "after_sha256": digest,
            "before_mode": "0600",
            "after_mode": "0600",
        },
        "artifacts": {name: digest for name in validator.REQUIRED_ARTIFACTS},
    }

    validator.validate(payload, "0.146.0")
    payload["authenticated"] = False
    try:
        validator.validate(payload, "0.146.0")
    except ValueError as exc:
        assert "not authenticated" in str(exc)
    else:
        raise AssertionError("unauthenticated evidence was accepted")

    payload["authenticated"] = True
    payload["restoration"]["before_mode"] = None
    payload["restoration"]["after_mode"] = None
    try:
        validator.validate(payload, "0.146.0")
    except ValueError as exc:
        assert "mode was not restored" in str(exc)
    else:
        raise AssertionError("null restoration modes were accepted")

    payload["restoration"]["before_mode"] = "0600"
    payload["restoration"]["after_mode"] = "0600"
    payload["artifacts"].pop("doctor.log")
    try:
        validator.validate(payload, "0.146.0")
    except ValueError as exc:
        assert "required artifacts are missing" in str(exc)
    else:
        raise AssertionError("incomplete artifact evidence was accepted")
