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
    assert WINDOWS_SUPPORTED_CONNECTORS == {
        "amp",
        "claudecode",
        "codex",
        "copilot",
        "cursor",
        "hermes",
        "windsurf",
        "opencode",
        "omnigent",
        "antigravity",
    }
    assert WINDOWS_PREVIEW_CONNECTORS == set()
    assert WINDOWS_NOT_CERTIFIED_CONNECTORS == set()
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
    assert "| Codex | `codex` | **Supported**" in text
    assert "| Claude Code | `claudecode` | **Supported**" in text
    assert "| Devin Desktop — legacy Cascade only | `windsurf` | **Supported**" in text
    assert "| OpenCode | `opencode` | **Supported**" in text
    assert "| OmniGent | `omnigent` | **Supported — native degraded**" in text
    assert "| Copilot CLI, Antigravity | `copilot`, `antigravity` | **Supported**" in text
    assert "local observability" in text
    assert "Local Splunk" in text
    assert "Hyper-V backend" in text
    assert "per-user Docker Desktop" in text
    assert "WSL2 engines" in text
    assert "| Hermes | `hermes` | **Supported**" in text
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


def test_windows_docs_keep_supported_taxonomy_and_optional_git_boundary() -> None:
    windows_docs = ROOT / "docs-site/content/docs/get-started/windows"
    capabilities = (windows_docs / "capabilities-commands.mdx").read_text(
        encoding="utf-8"
    )
    lifecycle = (windows_docs / "install-lifecycle.mdx").read_text(encoding="utf-8")
    install = (
        ROOT / "docs-site/content/docs/get-started/install.mdx"
    ).read_text(encoding="utf-8")
    cli_reference = (
        ROOT / "docs-site/content/docs/reference/cli.mdx"
    ).read_text(encoding="utf-8")
    live_workflow = (
        ROOT / ".github/workflows/connector-live-e2e.yml"
    ).read_text(encoding="utf-8")

    assert "| Claude Code connector setup | **Supported**" in capabilities
    assert "| Copilot CLI and Antigravity setup | **Supported**" in capabilities
    assert "`amp`, `claude-code`, `codex`, `cursor`, `windsurf`, `hermes`" in capabilities
    assert "`copilot`, and `antigravity` are supported and selectable" in capabilities
    assert "selectable previews" not in capabilities
    assert "`claude-code` is the certified connector alias" not in capabilities
    assert "Native Windows supports Amp plus Codex, Claude Code, Cursor" in cli_reference
    assert "remain previews or not-certified choices" not in cli_reference
    assert "Preview user-hook alias for Cursor" not in cli_reference
    assert "excluded from the native Windows release" in cli_reference
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


def test_claude_windows_docs_use_official_config_override() -> None:
    claude_docs = (
        ROOT / "docs/reference/CLAUDE-CODE-WINDOWS.md",
        ROOT / "docs-site/content/docs/connectors/claudecode.mdx",
    )

    for path in claude_docs:
        text = path.read_text(encoding="utf-8")
        assert "CLAUDE_CONFIG_DIR" in text, path
        assert "$CLAUDE_HOME" not in text, path


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
        "amp",
        "hermes",
        "openhands",
        "omnigent",
        "openclaw",
        "zeptoclaw",
    ):
        assert f'<ConnectorLabel id="{connector_id}" />' in compatibility


def test_codex_compatibility_docs_list_current_versioned_contracts() -> None:
    compatibility = (
        ROOT / "docs-site/content/docs/connectors/compatibility.mdx"
    ).read_text(encoding="utf-8")
    text = " ".join(compatibility.split())

    for version_range in (
        ">=0.124.0, <0.129.0",
        ">=0.129.0, <0.133.0",
        ">=0.133.0, <0.135.0",
        ">=0.135.0, <0.145.0",
        ">=0.145.0",
    ):
        assert f"`{version_range}`" in compatibility
    assert "`>=0.133.0, <0.145.0`" not in compatibility
    assert "selective to generic local-function tool payloads" in text


def test_claude_directoryadded_docs_match_packaged_v2_contract() -> None:
    inventory = json.loads(
        (ROOT / "cli/defenseclaw/inventory/hook_contracts.json").read_text(
            encoding="utf-8"
        )
    )
    claude_contracts = {
        contract["contract_id"]: contract
        for contract in inventory["connectors"]["claudecode"]["contracts"]
    }

    assert claude_contracts["claudecode-hooks-v1"]["agent_version"] == {
        "min_inclusive": "2.1.154",
        "max_exclusive": "2.1.219",
    }
    assert len(claude_contracts["claudecode-hooks-v1"]["events"]) == 28
    assert "DirectoryAdded" not in claude_contracts["claudecode-hooks-v1"]["events"]
    assert claude_contracts["claudecode-hooks-v2"]["agent_version"] == {
        "min_inclusive": "2.1.219",
        "max_exclusive": "",
    }
    assert len(claude_contracts["claudecode-hooks-v2"]["events"]) == 29
    assert "DirectoryAdded" in claude_contracts["claudecode-hooks-v2"]["events"]
    v2_capabilities = claude_contracts["claudecode-hooks-v2"]["capabilities"]
    assert "DirectoryAdded" not in v2_capabilities["block_events"]
    assert "DirectoryAdded" not in v2_capabilities["ask_events"]

    for relative_path in (
        "docs/reference/CLAUDE-CODE-WINDOWS.md",
        "docs-site/content/docs/connectors/claudecode.mdx",
        "docs-site/content/docs/connectors/compatibility.mdx",
        "docs-site/content/docs/get-started/windows/connectors-enforcement.mdx",
        "docs-site/content/docs/get-started/windows/telemetry-security.mdx",
        "docs-site/content/docs/stories/observe-claude-code.mdx",
    ):
        text = " ".join((ROOT / relative_path).read_text(encoding="utf-8").split())
        assert "28" in text
        assert "29" in text
        assert "2.1.219" in text
        assert "DirectoryAdded" in text
        assert "28 current lifecycle/tool/configuration events" not in text
        assert not re.search(
            r"\b(?:the )?28 (?:registered|supported) (?:Claude )?lifecycle events\b",
            text,
            re.IGNORECASE,
        )


def test_codex_docs_keep_memories_and_history_separate() -> None:
    connector_page = (
        ROOT / "docs-site/content/docs/connectors/codex.mdx"
    ).read_text(encoding="utf-8")
    checklist = (
        ROOT / "docs/windows-native-connector-reference-checklist.md"
    ).read_text(encoding="utf-8")

    assert "`$CODEX_HOME/memories/`" in connector_page
    assert "`$CODEX_HOME/history.jsonl` is a separate" in connector_page
    assert "%CODEX_HOME%\\memories" in checklist
    assert "%CODEX_HOME%\\history.jsonl" in checklist


def test_opencode_docs_exclude_unqualified_enforcement_media() -> None:
    connector_page = (ROOT / "docs-site/content/docs/connectors/opencode.mdx").read_text(encoding="utf-8")
    contracts = json.loads((ROOT / "cli/defenseclaw/inventory/hook_contracts.json").read_text(encoding="utf-8"))[
        "connectors"
    ]["opencode"]["contracts"]
    validated = json.loads((ROOT / "cli/defenseclaw/inventory/validated_versions.json").read_text(encoding="utf-8"))[
        "connectors"
    ]["opencode"]

    assert len(contracts) == 1
    assert contracts[0]["agent_version"] == {
        "min_inclusive": "1.18.10",
        "max_exclusive": "1.18.12",
    }
    assert validated["live"] is False
    assert validated["os"]["windows"] == {
        "last_validated_version": "",
        "last_validated_at": "",
        "run_url": "",
    }
    # Enforcement media may return only with exact official-package 1.18.11
    # SHA-256 provenance plus matching version/date/run acceptance metadata.
    assert not re.search(r"<Video\b", connector_page)
    assert "v1.17.3" not in connector_page


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
    research_contract = (
        ROOT / "docs/development/antigravity-mcp-contract.md"
    ).read_text(encoding="utf-8")
    compatibility = (
        ROOT / "docs-site/content/docs/connectors/compatibility.mdx"
    ).read_text(encoding="utf-8")
    validated = json.loads(
        (ROOT / "cli/defenseclaw/inventory/validated_versions.json").read_text(
            encoding="utf-8"
        )
    )["connectors"]["antigravity"]
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
    assert "CLI v1.1.10" in connector_page
    assert "CLI v1.1.10" in research_contract
    assert "`>=1.1.8`" in compatibility
    assert "pins official CLI `1.1.10`" in compatibility
    assert validated["live"] is False
    assert validated["os"]["windows"]["last_validated_version"] == ""
    assert "availability metadata only" in validated["notes"]
    assert "Native Windows x64 setup is supported" in validated["notes"]
    assert "No protected-client, authentication, HITL, client-provenance, or official-client live evidence is claimed" in validated["notes"]
    assert "remain out of scope and unverified" in validated["notes"]

    combined = "\n".join((connector_index, connector_page, config_reference, setup_source))
    assert "Claude-Code-compatible" not in combined
    assert "single global hook entry" not in combined
    assert "decision=ask overrides" not in combined
    assert "PreInvocation`, `PreToolUse" not in combined
    assert ".antigravitycli/hooks.json" not in combined
    assert "ANTIGRAVITY_CONFIG_DIR" not in combined
    assert "GEMINI_CONFIG_DIR" not in combined


def test_hermes_latest_source_recheck_matches_the_pinned_contract() -> None:
    connector_page = (
        ROOT / "docs-site/content/docs/connectors/hermes.mdx"
    ).read_text(encoding="utf-8")
    research = (
        ROOT / "docs/research/HERMES-NATIVE-WINDOWS.md"
    ).read_text(encoding="utf-8")
    acceptance = (
        ROOT / "docs/research/NATIVE-WINDOWS-CONNECTOR-ACCEPTANCE.md"
    ).read_text(encoding="utf-8")
    contracts = json.loads(
        (ROOT / "cli/defenseclaw/inventory/hook_contracts.json").read_text(
            encoding="utf-8"
        )
    )["connectors"]["hermes"]["contracts"]
    validated = json.loads(
        (ROOT / "cli/defenseclaw/inventory/validated_versions.json").read_text(
            encoding="utf-8"
        )
    )["connectors"]["hermes"]

    assert len(contracts) == 1
    assert contracts[0]["agent_version"] == {
        "min_inclusive": "0.19.0",
        "max_exclusive": "0.21.0",
    }
    assert validated["live"] is False
    assert "v2026.8.3 (0.20.0)" in validated["notes"]

    connector_text = " ".join(connector_page.split())
    assert (
        "latest official release rechecked on 2026-08-04 is "
        "v0.20.0 (`v2026.8.3`)"
    ) in connector_text
    assert "v0.19.1 (`v2026.7.30`)" not in connector_page
    assert "live: false" in connector_page
    assert "source review is not packaged or real-client certification" in connector_text

    assert "Last verified: **2026-08-04**" in research
    assert "Hermes Agent v0.20.0, tag `v2026.8.3`" in research
    assert "preview / not certified" in research
    assert "latest rechecked tag [`v2026.8.3`]" in acceptance


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


def test_omnigent_required_ci_claims_remain_degraded_and_non_live() -> None:
    live_workflow = (ROOT / ".github/workflows/connector-live-e2e.yml").read_text(encoding="utf-8")
    native_workflow = yaml.safe_load((ROOT / ".github/workflows/windows-native.yml").read_text(encoding="utf-8"))
    validated = json.loads((ROOT / "cli/defenseclaw/inventory/validated_versions.json").read_text(encoding="utf-8"))[
        "connectors"
    ]["omnigent"]
    acceptance = (ROOT / "docs/research/NATIVE-WINDOWS-CONNECTOR-ACCEPTANCE.md").read_text(encoding="utf-8")
    acceptance_row = next(
        line for line in acceptance.splitlines() if line.startswith("| OmniGent |") and "scoped gateway calls" in line
    )

    jobs = native_workflow["jobs"]
    generic_connectors = set(jobs["connector-contract"]["strategy"]["matrix"]["connector"])
    required_connectors = generic_connectors | {"omnigent"}
    assert required_connectors == {
        "amp",
        "antigravity",
        "claudecode",
        "codex",
        "copilot",
        "cursor",
        "hermes",
        "omnigent",
        "opencode",
        "windsurf",
    }
    assert required_connectors.isdisjoint({"geminicli", "openhands", "openclaw", "zeptoclaw"})
    omnigent_job = jobs["omnigent-native-degraded"]
    assert omnigent_job["name"] == "Windows x64 OmniGent native degraded"
    assert "if" not in omnigent_job
    assert "continue-on-error" not in omnigent_job
    assert {
        "connector-contract",
        "omnigent-native-degraded",
    }.issubset(set(jobs["windows-native-required"]["needs"]))

    assert "separate required packaged native-degraded cell" in live_workflow
    assert "remains outside green live certification" in live_workflow
    assert "claims no authentication/HITL evidence" in live_workflow
    assert "separate advisory packaged native-degraded cell" not in live_workflow

    assert validated["live"] is False
    assert validated["os"]["windows"] == {
        "last_validated_version": "",
        "last_validated_at": "",
        "run_url": "",
    }
    assert "required CI remain native-degraded" in validated["notes"]
    assert "live=false" in validated["notes"]
    assert "authentication/HITL evidence remain pending and unclaimed" in validated["notes"]
    assert "public Setup availability gate" in validated["notes"]
    assert "advisory" not in validated["notes"]

    assert "required packaged native-degraded CI is defined" in acceptance_row
    assert "live=false" in acceptance_row
    assert "authentication/HITL evidence remain pending and unclaimed" in acceptance_row
    assert "neither certification nor a public Setup availability gate follows" in acceptance_row
    assert "advisory" not in acceptance_row
    assert "non-blocking upstream Windows CI" not in acceptance_row


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
