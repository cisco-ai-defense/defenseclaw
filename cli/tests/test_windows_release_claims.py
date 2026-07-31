# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Consistency gates for the certified native Windows release surface."""

import json
import re
from pathlib import Path

import yaml
from defenseclaw.platform_support import (
    WINDOWS_CERTIFIED_ARCHITECTURES,
    WINDOWS_NOT_CERTIFIED_ARCHITECTURES,
    WINDOWS_NOT_CERTIFIED_CONNECTORS,
    WINDOWS_PREVIEW_CONNECTORS,
    WINDOWS_SUPPORTED_CONNECTORS,
    WINDOWS_UNSUPPORTED_CONNECTORS,
    WINDOWS_UNSUPPORTED_FEATURES,
)

ROOT = Path(__file__).resolve().parents[2]


def test_windows_release_metadata_is_exact() -> None:
    assert WINDOWS_SUPPORTED_CONNECTORS == set()
    assert WINDOWS_PREVIEW_CONNECTORS == {
        "claudecode",
        "codex",
        "cursor",
        "hermes",
        "windsurf",
        "opencode",
        "omnigent",
    }
    assert WINDOWS_NOT_CERTIFIED_CONNECTORS == {
        "copilot",
        "antigravity",
    }
    assert WINDOWS_UNSUPPORTED_CONNECTORS == {
        "geminicli",
        "openhands",
        "openclaw",
        "zeptoclaw",
    }
    assert WINDOWS_CERTIFIED_ARCHITECTURES == {"amd64"}
    assert WINDOWS_NOT_CERTIFIED_ARCHITECTURES == {"arm64"}
    assert WINDOWS_UNSUPPORTED_FEATURES == {
        "sandbox",
        "enterprise-hooks",
        "openhands",
        "omnigent-terminal-sandbox",
        "openclaw",
        "zeptoclaw",
    }


def test_windows_guide_has_unambiguous_claims_and_powershell_examples() -> None:
    guide_dir = ROOT / "docs-site/content/docs/get-started/windows"
    raw_text = "\n".join(
        page.read_text(encoding="utf-8") for page in sorted(guide_dir.glob("*.mdx"))
    )
    text = " ".join(raw_text.split())
    assert "WSL is not supported" in text
    assert "Windows x64" in text and "`amd64`" in text
    assert "Windows ARM64" in text and "Not certified" in text
    assert "| Codex | `codex` | **Preview**" in text
    assert "| Claude Code | `claudecode` | **Preview**" in text
    assert "| Windsurf | `windsurf` | **Preview**" in text
    assert "| OpenCode | `opencode` | **Preview**" in text
    assert "| OmniGent | `omnigent` | **Preview — native degraded**" in text
    assert "local observability" in text
    assert "Local Splunk" in text
    assert "Hyper-V backend" in text
    assert "per-user Docker Desktop" in text
    assert "WSL2 engines" in text
    assert "Hermes" in text and "Preview" in text
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


def test_claude_windows_docs_keep_preview_and_optional_git_boundary() -> None:
    windows_docs = ROOT / "docs-site/content/docs/get-started/windows"
    capabilities = (windows_docs / "capabilities-commands.mdx").read_text(
        encoding="utf-8"
    )
    lifecycle = (windows_docs / "install-lifecycle.mdx").read_text(encoding="utf-8")
    install = (
        ROOT / "docs-site/content/docs/get-started/install.mdx"
    ).read_text(encoding="utf-8")
    live_workflow = (
        ROOT / ".github/workflows/connector-live-e2e.yml"
    ).read_text(encoding="utf-8")

    assert "| Claude Code connector setup | **Preview**" in capabilities
    assert (
        "**Preview** for Claude Code/Codex/Cursor/Windsurf/Hermes/OpenCode/OmniGent"
        in capabilities
    )
    assert "`claude-code`, `codex`, `cursor`, `windsurf`, `hermes`" in capabilities
    assert "`opencode`, and `omnigent` are selectable previews" in capabilities
    assert "Claude Code connector setup | **Supported**" not in capabilities
    assert "`claude-code` is the certified connector alias" not in capabilities
    assert (
        "Native Windows x64 release certification currently covers Claude Code"
        not in live_workflow
    )
    assert (
        "Native Windows x64 release certification remains closed for Claude Code"
        in live_workflow
    )

    for text in (lifecycle, install):
        assert "Git for Windows" in text
        assert "it is optional; without it Claude uses its native PowerShell tool" in text
        assert "Claude Code's Git for Windows requirement" not in text
        assert "Claude Code retains its Git for Windows requirement" not in text


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
    choices_match = re.search(r"\$ConnectorChoices = @\((.*?)\)", installer, re.DOTALL)
    assert choices_match is not None
    choices = tuple(re.findall(r'"([^"]+)"', choices_match.group(1)))
    assert choices[-1] == "none"
    assert len(choices) == len(set(choices))
    assert set(choices[:-1]) == (
        WINDOWS_SUPPORTED_CONNECTORS
        | WINDOWS_PREVIEW_CONNECTORS
        | WINDOWS_NOT_CERTIFIED_CONNECTORS
    )


def test_connector_matrix_delegates_current_support_to_the_website() -> None:
    repository_pointer = (ROOT / "docs/CONNECTOR-MATRIX.md").read_text(encoding="utf-8")
    compatibility = (
        ROOT / "docs-site/content/docs/connectors/compatibility.mdx"
    ).read_text(encoding="utf-8")

    assert "https://cisco-ai-defense.github.io/defenseclaw/docs/connectors/compatibility/" in repository_pointer
    assert "https://cisco-ai-defense.github.io/defenseclaw/docs/capability-matrix/" in repository_pointer
    assert "not current support matrices" in " ".join(repository_pointer.split())
    for connector_id in (
        "codex",
        "claudecode",
        "cursor",
        "windsurf",
        "geminicli",
        "copilot",
        "antigravity",
        "opencode",
        "hermes",
        "openhands",
        "omnigent",
        "openclaw",
        "zeptoclaw",
    ):
        assert f'<ConnectorLabel id="{connector_id}" />' in compatibility


def test_antigravity_windows_claims_match_official_hook_boundary() -> None:
    connector_index = (ROOT / "docs-site/content/docs/connectors/index.mdx").read_text(
        encoding="utf-8"
    )
    connector_page = (
        ROOT / "docs-site/content/docs/connectors/antigravity.mdx"
    ).read_text(encoding="utf-8")
    config_reference = (
        ROOT / "docs-site/content/docs/reference/configuration.mdx"
    ).read_text(encoding="utf-8")
    setup_source = (
        ROOT / "cli/defenseclaw/commands/cmd_setup.py"
    ).read_text(encoding="utf-8")
    matrix = json.loads(
        (ROOT / "docs-site/data/capability-matrix.json").read_text(encoding="utf-8")
    )
    row = next(entry for entry in matrix["connectors"] if entry["id"] == "antigravity")
    connector_page_text = " ".join(connector_page.split())

    assert "Antigravity (`PreToolUse` only)" in connector_index
    assert row["toolInspection"] == "pre-execution"
    assert row["hooks"]["askEvents"] == ["PreToolUse"]
    assert row["hooks"]["blockEvents"] == ["PreToolUse"]
    assert row["hooks"]["supportsFailClosed"] is False
    assert "`~/.gemini/config/hooks.json`" in config_reference
    assert "Google documents no configuration-home environment override" in config_reference
    assert "<workspace>/.agents/hooks.json" in config_reference
    assert "only hard-blocking claim for the connector" in connector_page_text
    assert "does not document non-zero hook exit status as enforcement" in connector_page_text

    combined = "\n".join((connector_index, connector_page, config_reference, setup_source))
    assert "Claude-Code-compatible" not in combined
    assert "single global hook entry" not in combined
    assert "decision=ask overrides" not in combined
    assert "PreInvocation`, `PreToolUse" not in combined
    assert ".antigravitycli/hooks.json" not in combined
    assert "ANTIGRAVITY_CONFIG_DIR" not in combined
    assert "GEMINI_CONFIG_DIR" not in combined


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


def test_windows_native_ci_concurrency_cannot_cross_cancel_push_and_manual_runs() -> None:
    workflow = (ROOT / ".github/workflows/windows-native.yml").read_text(
        encoding="utf-8"
    )

    assert (
        "group: windows-native-${{ github.event_name }}-"
        "${{ github.event.pull_request.number || github.sha }}"
    ) in workflow
    assert "group: windows-native-${{ github.event.pull_request.number || github.ref }}" not in workflow


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
