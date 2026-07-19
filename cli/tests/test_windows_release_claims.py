# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Consistency gates for the certified native Windows release surface."""

from pathlib import Path

from defenseclaw.platform_support import (
    WINDOWS_CERTIFIED_ARCHITECTURES,
    WINDOWS_NOT_CERTIFIED_ARCHITECTURES,
    WINDOWS_NOT_CERTIFIED_CONNECTORS,
    WINDOWS_SUPPORTED_CONNECTORS,
    WINDOWS_UNSUPPORTED_CONNECTORS,
    WINDOWS_UNSUPPORTED_FEATURES,
)

ROOT = Path(__file__).resolve().parents[2]


def test_windows_release_metadata_is_exact() -> None:
    assert WINDOWS_SUPPORTED_CONNECTORS == {"codex", "claudecode"}
    assert WINDOWS_NOT_CERTIFIED_CONNECTORS == {
        "cursor",
        "windsurf",
        "geminicli",
        "copilot",
        "antigravity",
        "opencode",
        "hermes",
    }
    assert WINDOWS_UNSUPPORTED_CONNECTORS == {"openhands", "omnigent", "openclaw", "zeptoclaw"}
    assert WINDOWS_CERTIFIED_ARCHITECTURES == {"amd64"}
    assert WINDOWS_NOT_CERTIFIED_ARCHITECTURES == {"arm64"}
    assert WINDOWS_UNSUPPORTED_FEATURES == {
        "sandbox",
        "enterprise-hooks",
        "openhands",
        "omnigent",
        "openclaw",
        "zeptoclaw",
    }


def test_windows_guide_has_unambiguous_claims_and_powershell_examples() -> None:
    text = (ROOT / "docs-site/content/docs/get-started/windows.mdx").read_text(encoding="utf-8")
    install_text = (ROOT / "docs/INSTALL.md").read_text(encoding="utf-8")
    assert "WSL is unsupported" in text
    assert "Native Windows x64 (`amd64`)" in text
    assert "Windows ARM64 requires separate certification" in text
    assert "Codex CLI | `codex` | certified" in text
    assert "Claude Code | `claudecode` | certified" in text
    assert "local observability" in text
    assert "Local Splunk" in text
    assert "Hyper-V backend" in text
    assert "Docker Desktop per-user and WSL-only installations" in text
    assert "Hermes remains preview" not in text
    assert "Hermes is preview" not in install_text
    assert "```bash" not in text and "```sh" not in text
    assert text.count("```powershell") >= 8
    for label in (
        "Sandbox",
        "enterprise hooks",
        "OpenHands",
        "OmniGent",
        "OpenClaw",
        "ZeptoClaw",
    ):
        assert label in text


def test_release_runtime_custody_includes_arm64_without_certifying_arm64_setup() -> None:
    release = (ROOT / ".goreleaser.yaml").read_text(encoding="utf-8")
    assert "goos:\n      - linux\n      - darwin\n      - windows" in release
    assert "goarch:\n      - amd64\n      - arm64" in release
    assert "ignore:\n      - goos: windows\n        goarch: arm64" not in release
    installer = (ROOT / "scripts/install.ps1").read_text(encoding="utf-8")
    assert '"ARM64" { Die "Windows ARM64 is not certified' in installer
    assert '"codex",\n    "claudecode",\n    "none"' in installer


def test_connector_matrix_preserves_macos_and_linux_support() -> None:
    text = (ROOT / "docs/CONNECTOR-MATRIX.md").read_text(encoding="utf-8")
    assert "### WSL research (out of current Windows scope)" in text
    assert "current Windows product scope is **native Windows only**" in text
    for connector in (
        "Codex",
        "Claude Code",
        "Cursor",
        "Windsurf",
        "Gemini CLI",
        "Copilot CLI",
        "Antigravity",
        "OpenCode",
        "Hermes",
        "OpenHands",
        "OmniGent",
        "OpenClaw",
        "ZeptoClaw",
    ):
        row = next(line for line in text.splitlines() if line.startswith(f"| {connector} |"))
        assert "| supported | supported |" in row


def test_windows_live_harness_avoids_automatic_variable_assignments() -> None:
    text = (ROOT / "scripts/live-connector-e2e/run-windows.ps1").read_text(encoding="utf-8").lower()
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8").lower()
    native_workflow = (ROOT / ".github/workflows/windows-native.yml").read_text(
        encoding="utf-8"
    ).lower()
    assert "$agentargs =" in text
    assert "$eventrecord =" in text
    assert "[string]$eventname," in text
    assert "$args =" not in text
    assert "$event =" not in text
    assert "[string]$event," not in text
    assert "$profile =" not in workflow + native_workflow
    assert "windows-native-required:" in native_workflow
    assert "name: windows native required" in native_workflow


def test_disposable_connector_workspace_includes_the_v8_jsonl_validator() -> None:
    launcher = (ROOT / "scripts/invoke-windows-setup-standard-user-ci.ps1").read_text(
        encoding="utf-8"
    )
    contract_files = launcher[
        launcher.index("if ($Mode -eq 'contract')") : launcher.index(
            "foreach ($file in $harnessFiles)"
        )
    ]

    assert "'assert-observability-v8-jsonl.py'" in contract_files
