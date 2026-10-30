# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Consistency gates for the certified native Windows release surface."""

import json
import re
from pathlib import Path

import yaml
from defenseclaw import legacy_connector
from defenseclaw.platform_support import (
    ACP_ONLY_CONNECTORS,
    WINDOWS_CONNECTOR_SUPPORT,
    WINDOWS_NOT_CERTIFIED_CONNECTORS,
    WINDOWS_PREVIEW_CONNECTORS,
    WINDOWS_SUPPORTED_CONNECTORS,
    connector_platform_support,
)

ROOT = Path(__file__).resolve().parents[2]


# OpenHands and OmniGent are retired (#1182): the public docs no longer have
# pages for them while the code still registers them.
RETIRED_CONNECTORS = {"openhands", "omnigent"}


# The 1.0.3 docs layout (back since 2026-10-26, owner) keeps these reference pages in the
# Connectors section next to the connector pages.
_CONNECTOR_SECTION_REFERENCE_PAGES = {"capability-matrix", "compatibility", "openclaw-integration"}


def _active_connector_docs() -> dict[str, Path]:
    """The per-connector reference pages, which carry the platform status table."""
    connectors_dir = ROOT / "docs-site/content/docs/connectors"
    reference_dir = ROOT / "docs-site/content/docs/connectors"
    navigation = json.loads((connectors_dir / "meta.json").read_text(encoding="utf-8"))
    connector_ids: list[str] = []
    for item in navigation["pages"]:
        if item.startswith("("):
            # A sidebar group folder: its meta.json lists the pages as "../<id>".
            group = json.loads((connectors_dir / item / "meta.json").read_text(encoding="utf-8"))
            connector_ids.extend(page.removeprefix("../") for page in group["pages"])
        elif item != "index" and not item.startswith("---") and item not in _CONNECTOR_SECTION_REFERENCE_PAGES:
            connector_ids.append(item)
    return {connector_id: reference_dir / f"{connector_id}.mdx" for connector_id in connector_ids}


def _connector_text(connector_id: str) -> str:
    """A connector's user page and its reference page, whitespace-normalized."""
    docs = ROOT / "docs-site/content/docs"
    pages = (docs / "connectors" / f"{connector_id}.mdx",)
    return " ".join(" ".join(page.read_text(encoding="utf-8") for page in pages).split())


def _platform_status(text: str, platform: str) -> str:
    matches = re.findall(
        rf"^\|\s*{re.escape(platform)}\s*\|\s*\*\*([^*]+)\*\*\s*\|",
        text,
        re.MULTILINE,
    )
    assert len(matches) == 1, f"expected exactly one {platform!r} platform row"
    return matches[0].strip()




def test_windows_guide_has_unambiguous_platform_claims_and_powershell_examples() -> None:
    enterprise_deployment = (
        ROOT / "docs-site/content/docs/enterprise/secure-client.mdx"
    ).read_text(encoding="utf-8")
    raw_text = "\n".join(
        (ROOT / "docs-site/content/docs/get-started/windows" / page).read_text(encoding="utf-8")
        for page in ("index.mdx", "install-lifecycle.mdx")
    )
    text = " ".join(raw_text.split())
    assert "WSL is not supported" in text
    assert "Windows x64" in text and "`amd64`" in text
    assert "Windows ARM64" in text and "ARM64 is not certified" in text
    assert "local observability" in text
    assert "Local Splunk" in text
    assert "Hyper-V backend" in text
    assert "per-user Docker Desktop" in text
    assert "WSL2 engines" in text
    assert "```bash" not in text and "```sh" not in text
    assert text.count("```powershell") >= 8
    assert "OpenShell sandboxes run on Linux and macOS only" in text
    assert "enterprise hooks status" in enterprise_deployment


def test_connector_pages_are_the_canonical_cross_platform_support_source() -> None:
    connector_docs = _active_connector_docs()
    expected_connector_ids = set(WINDOWS_CONNECTOR_SUPPORT) - RETIRED_CONNECTORS
    assert set(connector_docs) == expected_connector_ids

    status_labels = {
        "supported": "Supported",
        "preview": "Preview",
        "not_certified": "Not certified",
        "unsupported": "Unsupported",
    }
    expected_windows_statuses: dict[str, str] = {}
    for connector_id, page in connector_docs.items():
        text = page.read_text(encoding="utf-8")
        assert text.count("## Platform support") == 1, page
        assert _platform_status(text, "macOS and Linux") == status_labels[connector_platform_support(connector_id, "darwin").status], page

        source_support = WINDOWS_CONNECTOR_SUPPORT[connector_id]
        expected_status = status_labels[source_support.status]
        if source_support.status == "supported" and "degraded mode" in source_support.reason:
            expected_status = "Supported — native degraded"
        expected_windows_statuses[connector_id] = expected_status
        assert _platform_status(text, "Native Windows x64") == expected_status, page

    assert {
        connector_id
        for connector_id, label in expected_windows_statuses.items()
        if label == "Supported — native degraded"
    } == set()

    connectors_index = (
        ROOT / "docs-site/content/docs/connectors/index.mdx"
    ).read_text(encoding="utf-8")
    assert connectors_index.count("## Platform support") == 1
    # The index renders the shared support matrix (data/support-matrix.ts)
    # instead of a hand-written table; the connector pages above stay the
    # per-connector source.
    assert "<ConnectorOsMatrix />" in connectors_index

    docs_content = ROOT / "docs-site/content"
    public_docs = "\n".join(
        page.read_text(encoding="utf-8") for page in sorted(docs_content.rglob("*.mdx"))
    )
    windows_navigation = json.loads(
        (ROOT / "docs-site/content/docs/get-started/windows/meta.json").read_text(encoding="utf-8")
    )["pages"]
    for stale_page in (
        "capabilities-commands",
        "connectors-enforcement",
        "managed-enterprise",
    ):
        stale_url = f"/docs/get-started/windows/{stale_page}"
        assert stale_page not in windows_navigation
        assert stale_url not in public_docs


def test_canonical_docs_keep_cli_taxonomy_and_claude_optional_git_boundary() -> None:
    lifecycle = "\n".join(
        (ROOT / "docs-site/content/docs/get-started/windows" / page).read_text(encoding="utf-8")
        for page in ("index.mdx", "install-lifecycle.mdx")
    )
    claude_connector = _connector_text("claudecode")
    cli_reference = (
        ROOT / "docs-site/content/docs/reference/cli.mdx"
    ).read_text(encoding="utf-8")
    live_workflow = (
        ROOT / ".github/workflows/connector-live-e2e.yml"
    ).read_text(encoding="utf-8")

    assert "Native Windows supports Amp plus Codex, Claude Code, Cursor" in cli_reference
    assert "remain previews or not-certified choices" not in cli_reference
    assert "Preview user-hook alias for Cursor" not in cli_reference
    assert (
        "Native Windows x64 release certification currently covers Claude Code"
        not in live_workflow
    )
    assert (
        "Native Windows x64 release certification remains closed for Claude Code"
        in live_workflow
    )

    normalized_claude = " ".join(claude_connector.split())
    assert re.search(r"Git for Windows\b.*\boptional\b", normalized_claude)
    assert "Git for Windows is not part of the DefenseClaw hook contract" in normalized_claude
    assert "Git for Windows" not in lifecycle


def test_claude_windows_docs_use_official_config_override() -> None:
    claude_docs = (ROOT / "docs-site/content/docs/connectors/claudecode.mdx",)

    for path in claude_docs:
        text = path.read_text(encoding="utf-8")
        assert "CLAUDE_CONFIG_DIR" in text, path
        assert "$CLAUDE_HOME" not in text, path


def test_release_builds_only_the_four_supported_targets_with_flat_names() -> None:
    release = yaml.safe_load((ROOT / ".goreleaser.yaml").read_text(encoding="utf-8"))
    builds = {build["id"]: build for build in release["builds"]}

    assert set(builds) == {
        "defenseclaw",
        "defenseclaw-windows-amd64",
        "defenseclaw-hook-post",
        "defenseclaw-hook",
        # The one-line install's GUI-subsystem Claude Code PreToolUse guard (GAP-2467).
        "defenseclaw-hook-guard",
        "defenseclaw-acp-posix",
        "defenseclaw-acp-windows-amd64",
        "defenseclaw-hook-posix",
        "defenseclaw-sensor-helper-posix",
        # The managed Linux and macOS packages' scanner launcher (GAP-1527);
        # no archive carries it (the payload archive has no scanners).
        "defenseclaw-scanners-posix",
    }
    assert builds["defenseclaw"]["binary"] == "defenseclaw-gateway"
    assert builds["defenseclaw-windows-amd64"]["binary"] == "defenseclaw-gateway"
    assert builds["defenseclaw-hook-post"]["binary"] == "defenseclaw-hook-post"
    for posix in (
        "defenseclaw",
        "defenseclaw-hook-post",
        "defenseclaw-acp-posix",
        "defenseclaw-hook-posix",
        "defenseclaw-sensor-helper-posix",
        "defenseclaw-scanners-posix",
    ):
        assert builds[posix]["goos"] == ["linux", "darwin"]
        assert builds[posix]["goarch"] == ["amd64", "arm64"]
        assert {"goos": "darwin", "goarch": "amd64"} in builds[posix]["ignore"]
    for windows in ("defenseclaw-windows-amd64", "defenseclaw-hook", "defenseclaw-hook-guard", "defenseclaw-acp-windows-amd64"):
        assert builds[windows]["goos"] == ["windows"]
        assert builds[windows]["goarch"] == ["amd64"]
    # The guard is a small GUI-subsystem program of its own: never a console
    # program, never the launcher it checks for.
    assert builds["defenseclaw-hook-guard"]["main"] == "./cmd/defenseclaw-hook-guard"
    assert builds["defenseclaw-hook-guard"]["binary"] == "defenseclaw-hook-guard"
    for windows_gui in ("defenseclaw-hook", "defenseclaw-hook-guard"):
        assert "-H=windowsgui" in builds[windows_gui]["ldflags"][0]
    assert "-buildid=defenseclaw-hook-guard-" in builds["defenseclaw-hook-guard"]["ldflags"][0]

    archives = {archive["id"]: archive for archive in release["archives"]}
    flat_name = "{{ .ProjectName }}-{{ .Version }}-{{ .Os }}-{{ .Arch }}"
    assert set(archives) == {"default", "enterprise-posix", "windows-amd64"}
    assert archives["default"]["ids"] == ["defenseclaw", "defenseclaw-hook-post", "defenseclaw-acp-posix", "defenseclaw-sensor-helper-posix"]
    # The standalone managed-enterprise payload is its own flat asset family;
    # per-user installers never fetch it.
    enterprise = archives.pop("enterprise-posix")
    assert enterprise["ids"] == [
        "defenseclaw",
        "defenseclaw-hook-posix",
        "defenseclaw-sensor-helper-posix",
        "defenseclaw-acp-posix",
    ]
    assert enterprise["formats"] == ["tar.gz"]
    assert enterprise["name_template"] == "{{ .ProjectName }}-enterprise-{{ .Version }}-{{ .Os }}-{{ .Arch }}"
    assert archives["default"]["formats"] == ["tar.gz"]
    assert archives["windows-amd64"]["ids"] == [
        "defenseclaw-windows-amd64",
        "defenseclaw-hook",
        "defenseclaw-hook-guard",
        "defenseclaw-acp-windows-amd64",
    ]
    assert archives["windows-amd64"]["formats"] == ["zip"]
    assert all(archive["name_template"] == flat_name for archive in archives.values())
    # The Release workflow writes and signs the one checksums.txt users verify.
    assert release["checksum"] == {"disable": True}
    assert "signs" not in release


def test_windows_installer_tracks_supported_connectors() -> None:
    installer = (ROOT / "scripts/install.ps1").read_text(encoding="utf-8")
    assert '"ARM64" { Die "Windows ARM64 is not certified, including x64 emulation' in installer
    choices_match = re.search(r"\$ConnectorChoices = @\((.*?)\)", installer, re.DOTALL)
    assert choices_match is not None
    choices = tuple(re.findall(r'"([^"]+)"', choices_match.group(1)))
    assert choices[-1] == "none"
    assert len(choices) == len(set(choices))
    assert set(choices[:-1]) == (
        WINDOWS_SUPPORTED_CONNECTORS
        | WINDOWS_PREVIEW_CONNECTORS
        | WINDOWS_NOT_CERTIFIED_CONNECTORS
    ) - ACP_ONLY_CONNECTORS


def test_connector_matrix_delegates_current_support_to_the_website() -> None:
    repository_pointer = (ROOT / "docs/CONNECTOR-MATRIX.md").read_text(encoding="utf-8")
    compatibility = (
        ROOT / "docs-site/content/docs/connectors/compatibility.mdx"
    ).read_text(encoding="utf-8")

    assert "https://cisco-ai-defense.github.io/defenseclaw/docs/connectors/compatibility/" in repository_pointer
    assert "https://cisco-ai-defense.github.io/defenseclaw/docs/connectors/capability-matrix/" in repository_pointer
    assert "not current support matrices" in " ".join(repository_pointer.split())
    for connector_id in (
        "codex",
        "claudecode",
        "cursor",
        "devin",
        "copilot",
        "antigravity",
        "opencode",
        "amp",
        "hermes",
        "kiro",
        "openclaw",
        "zeptoclaw",
    ):
        assert f'<ConnectorLabel id="{connector_id}" />' in compatibility


def test_public_docs_expose_devin_and_no_retired_desktop_setup_surface() -> None:
    docs_root = ROOT / "docs-site"
    public_sources = [
        *sorted((docs_root / "content").rglob("*.mdx")),
        *sorted((docs_root / "data").glob("*.json")),
        *sorted((docs_root / "data").glob("*.ts")),
        *sorted((docs_root / "lib").glob("*.ts")),
    ]
    combined = "\n".join(path.read_text(encoding="utf-8") for path in public_sources)

    retired = legacy_connector.RETIRED_DESKTOP_ID
    assert f"defenseclaw setup {retired}" not in combined
    assert f"/docs/connectors/{retired}" not in combined
    assert f'<ConnectorLabel id="{retired}"' not in combined
    assert f'"id": "{retired}"' not in combined
    assert f"id: '{retired}'" not in combined
    assert "defenseclaw setup devin" in combined
    assert "/docs/connectors/devin" in combined
    assert '<ConnectorLabel id="devin" />' in combined
    assert '"id": "devin"' in combined

    # Devin Desktop coverage is claimed only for its Devin Local agent, only on
    # vendor documentation until a live run is recorded, and never for Cascade.
    devin_page = (docs_root / "content/docs/connectors/devin.mdx").read_text(encoding="utf-8")
    assert "**Devin Local** agent (the default for new tabs) | **Yes, per vendor documentation**" in devin_page
    assert "before 3.9.19, legacy **Cascade** agent | **No; turned off under the standalone enterprise profile**" in devin_page


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
    assert "selective local-function tool payloads" in text
    assert "expand to generic local function tools (`codex-hooks-v3-generic`)" in text


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
        "docs-site/content/docs/connectors/claudecode.mdx",
        "docs-site/content/docs/connectors/compatibility.mdx",
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

    assert "`$CODEX_HOME/memories/`" in connector_page
    assert "`$CODEX_HOME/history.jsonl` is a separate" in connector_page


def test_opencode_docs_exclude_unqualified_enforcement_media() -> None:
    connector_page = (ROOT / "docs-site/content/docs/connectors/opencode.mdx").read_text(encoding="utf-8")
    contracts = json.loads((ROOT / "cli/defenseclaw/inventory/hook_contracts.json").read_text(encoding="utf-8"))[
        "connectors"
    ]["opencode"]["contracts"]
    validated = json.loads((ROOT / "cli/defenseclaw/inventory/validated_versions.json").read_text(encoding="utf-8"))[
        "connectors"
    ]["opencode"]

    by_id = {contract["contract_id"]: contract for contract in contracts}
    assert set(by_id) == {"opencode-hooks-v2"}
    assert by_id["opencode-hooks-v2"]["agent_version"] == {
        "min_inclusive": "2.0.0",
        "max_exclusive": "2.3.0",
    }
    assert "V2 support is currently a preview" in connector_page
    assert validated["live"] is False
    assert validated["os"]["windows"] == {
        "last_validated_version": "",
        "last_validated_at": "",
        "run_url": "",
    }
    # Enforcement media may return only with exact official V2 package
    # SHA-256 provenance plus matching version/date/run acceptance metadata.
    assert not re.search(r"<Video\b", connector_page)
    assert "v1.17.3" not in connector_page


def test_antigravity_windows_claims_match_official_hook_boundary() -> None:
    connector_index = (ROOT / "docs-site/content/docs/connectors/capability-matrix.mdx").read_text(
        encoding="utf-8"
    )
    connector_page = _connector_text("antigravity")
    # The negative checks below are about prose; the reference page's generated
    # contract table lists every registered event, PreInvocation first.
    user_page = (ROOT / "docs-site/content/docs/connectors/antigravity.mdx").read_text(encoding="utf-8")
    config_reference = (
        ROOT / "docs-site/content/docs/reference/configuration.mdx"
    ).read_text(encoding="utf-8")
    setup_source = (
        ROOT / "cli/defenseclaw/commands/cmd_setup.py"
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
    assert "`>=1.1.8`" in compatibility
    # The sandbox image pin follows the harness DefaultVersion.
    assert "installs agy `1.2.12`" in " ".join(compatibility.split())
    assert validated["live"] is False
    assert validated["os"]["windows"]["last_validated_version"] == ""
    assert "availability metadata only" in validated["notes"]
    assert "Native Windows x64 setup is supported" in validated["notes"]
    assert "No protected-client, authentication, HITL, client-provenance, or official-client live evidence is claimed" in validated["notes"]
    assert "remain out of scope and unverified" in validated["notes"]

    user_prose = "\n".join(line for line in user_page.splitlines() if not line.lstrip().startswith("|"))
    combined = "\n".join((connector_index, user_prose, config_reference, setup_source))
    assert "Claude-Code-compatible" not in combined
    assert "single global hook entry" not in combined
    assert "decision=ask overrides" not in combined
    assert "PreInvocation`, `PreToolUse" not in combined
    assert ".antigravitycli/hooks.json" not in combined
    assert "ANTIGRAVITY_CONFIG_DIR" not in combined


def test_hermes_latest_source_recheck_matches_the_pinned_contract() -> None:
    connector_page = (
        ROOT / "docs-site/content/docs/connectors/hermes.mdx"
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

    assert len(contracts) == 2
    # The exact pins are the release-date tags a Hermes git install prints
    # ("Hermes Agent vunknown (2026.9.24)"), GAP-0151.
    assert contracts[0]["agent_version"] == {
        "exact": [
            "2026.7.20",
            "2026.7.30",
            "2026.8.3",
            "2026.8.13",
            "2026.8.16",
            "2026.8.16.2",
            "2026.8.18",
            "2026.8.19",
            "2026.8.27",
        ],
        "min_inclusive": "0.19.0",
        "max_exclusive": "0.21.0",
    }
    assert contracts[1]["contract_id"] == "hermes-hooks-v2"
    assert contracts[1]["agent_version"] == {
        "exact": ["2026.8.31", "2026.9.7", "2026.9.11", "2026.9.14", "2026.9.21", "2026.9.24"],
        "min_inclusive": "0.21.0",
        "max_exclusive": "0.22.0",
    }
    assert validated["live"] is False
    assert validated["os"]["windows"] == {
        "last_validated_version": "",
        "last_validated_at": "",
        "run_url": "",
    }
    assert "v0.21.3 (v2026.9.14)" in validated["notes"]

    connector_text = " ".join(connector_page.split())
    assert (
        "latest official release rechecked on 2026-09-14 is "
        "v0.21.3 (`v2026.9.14`)"
    ) in connector_text
    assert "v0.19.1 (`v2026.7.30`)" not in connector_page
    assert "live: false" in connector_page
    assert "source review is not packaged or real-client certification" in connector_text


def test_amp_validation_status_is_boolean_and_pending_note_is_explicit() -> None:
    validated = json.loads(
        (ROOT / "cli/defenseclaw/inventory/validated_versions.json").read_text(
            encoding="utf-8"
        )
    )["connectors"]["amp"]

    assert validated["live"] is False
    assert "pending" in validated["notes"]
    assert "live=false" in validated["notes"]


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
