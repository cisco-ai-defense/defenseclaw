# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Static release contracts for the native OpenHands macOS connector."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_openhands_macos_is_implemented_but_uncertified() -> None:
    registry = json.loads(
        (ROOT / "cli/defenseclaw/inventory/validated_versions.json").read_text(
            encoding="utf-8"
        )
    )
    openhands = registry["connectors"]["openhands"]

    assert openhands["version_probe"] == "openhands --version"
    assert openhands["live"] is True
    assert set(openhands["os"]) == {"linux", "macos"}
    assert openhands["os"]["macos"] == {
        "last_validated_version": "",
        "last_validated_at": "",
        "run_url": "",
    }
    assert "uncertified" in openhands["notes"].lower()
    assert "Standalone OpenHands SDK 1.39.1" in openhands["notes"]
    assert "does not change the CLI compatibility range" in openhands["notes"]

    contracts = json.loads(
        (ROOT / "cli/defenseclaw/inventory/hook_contracts.json").read_text(
            encoding="utf-8"
        )
    )
    contract = contracts["connectors"]["openhands"]["contracts"][0]
    assert contract["agent_version"] == {
        "min_inclusive": "1.12.0",
        "max_exclusive": "",
    }
    assert contract["native_otlp"] is True
    assert any("OpenHands SDK 1.39.1" in note for note in contract["notes"])


def test_openhands_live_driver_uses_official_cli_on_macos() -> None:
    driver = (
        ROOT / "scripts/live-connector-e2e/drivers/openhands.sh"
    ).read_text(encoding="utf-8")
    workflow = (
        ROOT / ".github/workflows/connector-live-e2e.yml"
    ).read_text(encoding="utf-8")

    assert 'package="openhands"' in driver
    assert "openhands-ai" not in driver
    assert "linux|macos" in driver
    assert "DC_E2E_AGENT_VERSION_REQUEST" in driver
    assert "uv tool install --python 3.12 --force" in driver
    assert "DC_DRIVER_SUPPORTS_OTLP=1" in driver
    assert "--override-with-envs" in driver
    assert ".otlp-openhands.token" in driver
    assert "{ connector: openhands,  os: macos-latest,   dcos: macos }" in workflow


def test_openhands_current_discovery_and_asset_classifications() -> None:
    signatures = json.loads(
        (ROOT / "cli/defenseclaw/inventory/ai_signatures.json").read_text(
            encoding="utf-8"
        )
    )
    openhands = next(
        signature for signature in signatures["signatures"] if signature["id"] == "openhands"
    )

    assert openhands["package_names"] == ["openhands"]
    assert {
        "OPENHANDS_PERSISTENCE_DIR",
        "OPENHANDS_WORK_DIR",
        "OPENHANDS_CONVERSATIONS_DIR",
    } <= set(openhands["env_var_names"])
    assert {
        ".agents/agents",
        ".openhands/agents",
        ".agents/skills",
        ".openhands/microagents",
        "AGENTS.md",
        "AGENT.md",
        "CLAUDE.md",
        "GEMINI.md",
        ".cursorrules",
    } <= set(openhands["config_paths"])


def test_openhands_docs_separate_outdated_current_and_uncertified() -> None:
    docs = " ".join((
        ROOT / "docs-site/content/docs/connectors/openhands.mdx"
    ).read_text(encoding="utf-8").split())

    for classification in ("**OUTDATED**", "**CURRENT**", "**UNCERTIFIED**"):
        assert classification in docs
    assert "CLI plugins are explicitly **N/A**" in docs
    assert "**trace-only native OTLP**" in docs
    assert "standalone OpenHands SDK 1.39.1" in docs
    assert "does not widen or otherwise change the CLI compatibility range" in docs
    assert "does not natively export OTLP logs or metrics" in docs
    assert "does not contain stable turn, action, tool-call, event, or model-response IDs" in docs
    assert "general-purpose`, `code-explorer`, and `bash-runner" in docs
    assert "intentionally installs only CLI command hooks" in docs
