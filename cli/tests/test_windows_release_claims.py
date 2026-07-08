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
        "cursor", "windsurf", "geminicli", "copilot", "antigravity", "opencode", "hermes"
    }
    assert WINDOWS_UNSUPPORTED_CONNECTORS == {"openhands", "omnigent", "openclaw", "zeptoclaw"}
    assert WINDOWS_CERTIFIED_ARCHITECTURES == {"amd64"}
    assert WINDOWS_NOT_CERTIFIED_ARCHITECTURES == {"arm64"}
    assert WINDOWS_UNSUPPORTED_FEATURES == {
        "sandbox", "enterprise-hooks", "openhands", "omnigent", "openclaw", "zeptoclaw",
        "local-observability-shell-stack", "splunk-shell-stack", "native-desktop-toasts",
    }


def test_windows_guide_has_unambiguous_claims_and_powershell_examples() -> None:
    text = (ROOT / "docs-site/content/docs/get-started/windows.mdx").read_text(encoding="utf-8")
    assert "WSL is unsupported" in text
    assert "Native Windows x64 (`amd64`)" in text
    assert "Windows ARM64 requires separate certification" in text
    assert "Codex CLI | `codex` | certified" in text
    assert "Claude Code | `claudecode` | certified" in text
    assert "```bash" not in text and "```sh" not in text
    assert text.count("```powershell") >= 8
    for label in ("Sandbox", "enterprise hooks", "OpenHands", "OmniGent", "OpenClaw", "ZeptoClaw", "native desktop toasts"):
        assert label in text


def test_release_packaging_keeps_non_windows_arm64_but_not_windows_arm64() -> None:
    release = (ROOT / ".goreleaser.yaml").read_text(encoding="utf-8")
    assert "ignore:\n      - goos: windows\n        goarch: arm64" in release
    installer = (ROOT / "scripts/install.ps1").read_text(encoding="utf-8")
    assert '"ARM64" { Die "Windows ARM64 is not certified' in installer
    assert '"codex",\n    "claudecode",\n    "none"' in installer


def test_connector_matrix_preserves_macos_and_linux_support() -> None:
    text = (ROOT / "docs/CONNECTOR-MATRIX.md").read_text(encoding="utf-8")
    assert "### WSL research" not in text
    assert "WSL is unsupported" in text
    for connector in ("Codex", "Claude Code", "Cursor", "Windsurf", "Gemini CLI", "Copilot CLI", "Antigravity", "OpenCode", "Hermes", "OpenHands", "OmniGent", "OpenClaw", "ZeptoClaw"):
        row = next(line for line in text.splitlines() if line.startswith(f"| {connector} |"))
        assert "| supported | supported |" in row
