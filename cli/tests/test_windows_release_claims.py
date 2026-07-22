# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Consistency gates for the certified native Windows release surface."""

from pathlib import Path

import yaml

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
    guide_dir = ROOT / "docs-site/content/docs/get-started/windows"
    raw_text = "\n".join(
        page.read_text(encoding="utf-8") for page in sorted(guide_dir.glob("*.mdx"))
    )
    text = " ".join(raw_text.split())
    install_text = (ROOT / "docs/INSTALL.md").read_text(encoding="utf-8")
    assert "WSL is not supported" in text
    assert "Windows x64" in text and "`amd64`" in text
    assert "Windows ARM64" in text and "Not certified" in text
    assert "| Codex | `codex` | **Supported**" in text
    assert "| Claude Code | `claudecode` | **Supported**" in text
    assert "local observability" in text
    assert "Local Splunk" in text
    assert "Hyper-V backend" in text
    assert "per-user Docker Desktop" in text
    assert "WSL2 engines" in text
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


def test_release_runtime_custody_splits_certified_x64_from_compatibility_arm64() -> None:
    release = yaml.safe_load((ROOT / ".goreleaser.yaml").read_text(encoding="utf-8"))
    builds = {build["id"]: build for build in release["builds"]}

    assert set(builds) == {
        "defenseclaw",
        "defenseclaw-windows-amd64",
        "defenseclaw-windows-arm64",
        "defenseclaw-hook",
    }
    assert builds["defenseclaw"]["goos"] == ["linux", "darwin"]
    assert builds["defenseclaw"]["goarch"] == ["amd64", "arm64"]
    assert builds["defenseclaw-windows-amd64"]["goos"] == ["windows"]
    assert builds["defenseclaw-windows-amd64"]["goarch"] == ["amd64"]
    assert builds["defenseclaw-windows-arm64"]["goos"] == ["windows"]
    assert builds["defenseclaw-windows-arm64"]["goarch"] == ["arm64"]
    assert builds["defenseclaw-hook"]["goos"] == ["windows"]
    assert builds["defenseclaw-hook"]["goarch"] == ["amd64"]

    archives = {archive["id"]: archive for archive in release["archives"]}
    canonical_name = "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"
    assert set(archives) == {"default", "windows-amd64", "windows-arm64"}
    assert archives["default"]["ids"] == ["defenseclaw"]
    assert archives["default"]["formats"] == ["tar.gz"]
    assert archives["default"]["name_template"] == canonical_name
    assert archives["windows-amd64"]["ids"] == [
        "defenseclaw-windows-amd64",
        "defenseclaw-hook",
    ]
    assert archives["windows-amd64"]["formats"] == ["zip"]
    assert archives["windows-amd64"]["name_template"] == canonical_name
    assert archives["windows-arm64"]["ids"] == ["defenseclaw-windows-arm64"]
    assert archives["windows-arm64"]["formats"] == ["zip"]
    assert archives["windows-arm64"]["name_template"] == canonical_name
    assert all(
        "defenseclaw-hook" not in archive["ids"]
        for archive_id, archive in archives.items()
        if archive_id != "windows-amd64"
    )

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


def test_disposable_setup_workspace_includes_the_packaged_v8_validator() -> None:
    launcher = (ROOT / "scripts/invoke-windows-setup-standard-user-ci.ps1").read_text(
        encoding="utf-8"
    )
    harness_files_start = launcher.index("$harnessFiles = @(")
    harness_files = launcher[
        harness_files_start : launcher.index(
            "if ($Mode -eq 'contract')", harness_files_start
        )
    ]

    assert "'windows-native-ci.ps1'" in harness_files
    assert "'validate_packaged_v8_resources.py'" in harness_files
