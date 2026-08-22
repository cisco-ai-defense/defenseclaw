# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

_FULL_MATRIX_ALLOWLIST_BEGIN = "# BEGIN connector full-matrix path allowlist"
_FULL_MATRIX_ALLOWLIST_END = "# END connector full-matrix path allowlist"


def _connector_full_matrix_patterns() -> tuple[re.Pattern[str], ...]:
    workflow = (ROOT / ".github/workflows/connector-live-e2e.yml").read_text(encoding="utf-8")
    assert workflow.count(_FULL_MATRIX_ALLOWLIST_BEGIN) == 1
    assert workflow.count(_FULL_MATRIX_ALLOWLIST_END) == 1
    policy = workflow.split(_FULL_MATRIX_ALLOWLIST_BEGIN, 1)[1].split(_FULL_MATRIX_ALLOWLIST_END, 1)[0]
    expressions = tuple(match.group(1) for line in policy.splitlines() if (match := re.match(r"\s*-e '([^']+)'", line)))
    assert expressions
    assert len(expressions) == len(set(expressions))
    assert all(expression.startswith("^") for expression in expressions)
    return tuple(re.compile(expression) for expression in expressions)


def _selects_full_connector_matrix(path: str) -> bool:
    return any(pattern.match(path) for pattern in _connector_full_matrix_patterns())


@pytest.mark.parametrize(
    "path",
    (
        # Preserve the established connector and golden-fixture behavior.
        "internal/gateway/connector/codex_policy.go",
        "internal/gateway/sidecar_observability_v8.go",
        "internal/audit/audit.go",
        "internal/observability/redaction/hash.go",
        "internal/cli/daemon.go",
        "cli/defenseclaw/inventory/hook_contracts.json",
        "cli/defenseclaw/commands/cmd_setup.py",
        "cli/defenseclaw/commands/cmd_init.py",
        "test/e2e/connector_lifecycle_matrix_test.go",
        "scripts/live-connector-e2e/golden/codex/session_start.json",
        ".github/workflows/connector-live-e2e.yml",
        # Windows release workflows and native payload sources.
        ".goreleaser.yaml",
        ".github/workflows/release.yaml",
        ".github/workflows/windows-native.yml",
        "cmd/defenseclaw/main.go",
        "cmd/defenseclaw-hook/main.go",
        "cmd/defenseclaw-launcher/main.go",
        "cmd/defenseclaw-setup/main.go",
        "cmd/defenseclaw-startup/main.go",
        "internal/windowsresources/resources.go",
        "internal/tools/windowsresources/main.go",
        # Installer lifecycle, signing, setup, and native acceptance.
        "cli/defenseclaw/commands/windows_uninstall_helper.py",
        "cli/defenseclaw/windows_acl.py",
        "scripts/build-windows-installer.ps1",
        "scripts/initialize-windows-native-ci-paths.ps1",
        "scripts/install.ps1",
        "scripts/install-pinned-windows-cosign.ps1",
        "scripts/invoke-windows-setup-standard-user-ci.ps1",
        "scripts/test-fresh-install-release-windows.ps1",
        "scripts/test-upgrade-release-windows.ps1",
        "scripts/test-windows-disposable-user-safety.ps1",
        "scripts/test-windows-setup-wizard.ps1",
        "scripts/upgrade.ps1",
        "scripts/validate_packaged_v8_resources.py",
        "scripts/windows-authenticode.ps1",
        "scripts/windows-binary-identity.ps1",
        "scripts/windows-disposable-user-safety.ps1",
        "scripts/windows-native-ci.ps1",
        "scripts/windows-native-paths.ps1",
        "scripts/windows_installer_artifacts.py",
        "scripts/windows-disposable-file-guard.cs",
        "scripts/windows-disposable-standard-user-launcher.cs",
        "scripts/windows-setup-standard-user-launcher.cs",
    ),
)
def test_full_matrix_allowlist_accepts_release_sensitive_paths(path: str) -> None:
    assert _selects_full_connector_matrix(path)


@pytest.mark.parametrize(
    "path",
    (
        "README.md",
        "docs/WINDOWS-NATIVE-INSTALLER.md",
        ".goreleaser.yaml.disabled",
        ".github/workflows/release.yaml.disabled",
        ".github/workflows/windows-native.yml.bak",
        ".github/workflows/docs-site.yml",
        "cmd/defenseclaw-setup-notes/main.go",
        "internal/windowsresources-archive/resources.go",
        "internal/tools/windowsresources-notes/main.go",
        "cli/defenseclaw/commands/windows_uninstall_helper.py.bak",
        "cli/defenseclaw/windows_acl.py.old",
        "scripts/build-macos-app-release.sh",
        "scripts/build-windows-installer.ps1.md",
        "scripts/test-windows-setup-wizard.md",
        "scripts/windows-authenticode.ps1.bak",
        "scripts/windows-installer-artifacts.py",
        "scripts/windows-native-ci.ps10",
    ),
)
def test_full_matrix_allowlist_rejects_unrelated_and_near_miss_paths(
    path: str,
) -> None:
    assert not _selects_full_connector_matrix(path)


def test_amp_is_reachable_through_contract_and_manual_live_layers() -> None:
    workflow = (ROOT / ".github/workflows/connector-live-e2e.yml").read_text(encoding="utf-8")
    full_match = re.search(r"^\s*full='([^']+)'$", workflow, flags=re.MULTILINE)
    assert full_match is not None
    assert "amp" in json.loads(full_match.group(1))["connector"]
    assert re.search(r"^\s+- amp$", workflow, flags=re.MULTILINE)

    live = workflow.split("  live-matrix:", 1)[1].split("  windows-live:", 1)[0]
    assert "if: ${{ github.event_name == 'workflow_dispatch' }}" in live
    assert "{ connector: amp,        os: ubuntu-latest,  dcos: linux }" in live
    assert "{ connector: amp,        os: macos-latest,   dcos: macos }" in live
    assert "AMP_API_KEY: ${{ matrix.connector == 'amp' && secrets.AMP_API_KEY || '' }}" in live
    assert "AMP_VERSION:" in live

    windows = workflow.split("  windows-live:", 1)[1].split("  report:", 1)[0]
    assert "github.event_name == 'workflow_dispatch'" in windows
    assert "connector: [codex, claudecode, amp, cursor, opencode]" in windows
    assert "AMP_API_KEY: ${{ matrix.connector == 'amp' && secrets.AMP_API_KEY || '' }}" in windows
    assert "AMP_VERSION: ${{ inputs.version }}" in windows

    run = (ROOT / "scripts/live-connector-e2e/run.sh").read_text(encoding="utf-8")
    assert re.search(r"^ALL_CONNECTORS=\([^)]*\bamp\b", run, flags=re.MULTILINE)

    setup = (ROOT / "scripts/live-connector-e2e/lib/setup.sh").read_text(encoding="utf-8")
    assert ".config/amp/plugins/defenseclaw.ts" in setup

    common = (ROOT / "scripts/live-connector-e2e/lib/common.sh").read_text(encoding="utf-8")
    assert ".hook_event_name" in common
    assert '[ "${amp_event}" != "${event}" ]' in common
    assert "Amp event mismatch" in common
    assert 'defenseclaw-gateway hook --connector amp --event "${event}"' in common

    contract = (ROOT / "scripts/live-connector-e2e/contract-smoke.sh").read_text(encoding="utf-8")
    assert 'dc_invoke_hook "${DC_E2E_CONNECTOR}" "${native_event}"' in contract

    driver = (ROOT / "scripts/live-connector-e2e/drivers/amp.sh").read_text(encoding="utf-8")
    assert "@ampcode/cli@${AMP_VERSION:-latest}" in driver
    assert 'dc_write_env_key AMP_API_KEY "${AMP_API_KEY}"' in driver
    assert 'amp -x "${prompt}" --plugin-ready-timeout 30' in driver
    assert "DC_DRIVER_SUPPORTS_BLOCK=1" in driver
    assert "DC_DRIVER_SUPPORTS_OTLP=0" in driver


def test_codex_live_driver_reports_registry_metadata_without_pre_setup_execution() -> None:
    driver = (ROOT / "scripts/live-connector-e2e/drivers/codex.sh").read_text(encoding="utf-8")

    assert "_codex_is_exact_version" in driver
    assert "dc_without_provider_credentials npm view @openai/codex@latest version" in driver
    assert (
        'dc_without_provider_credentials npm install -g --ignore-scripts "@openai/codex@${version}"'
        in driver
    )
    assert 'DC_E2E_AGENT_VERSION="${version}"' in driver
    assert "dc_capture_version codex" not in driver
    assert "codex --version" not in driver
    assert driver.index('DC_E2E_AGENT_VERSION="${version}"') < driver.index("dc_driver_main codex")


def test_opencode_is_reachable_only_through_the_manual_macos_live_layer() -> None:
    workflow = (ROOT / ".github/workflows/connector-live-e2e.yml").read_text(encoding="utf-8")
    full_match = re.search(r"^\s*full='([^']+)'$", workflow, flags=re.MULTILINE)
    assert full_match is not None
    assert "opencode" not in json.loads(full_match.group(1))["connector"]

    live = workflow.split("  live-matrix:", 1)[1].split("  windows-live:", 1)[0]
    assert "if: ${{ github.event_name == 'workflow_dispatch' }}" in live
    assert "{ connector: opencode,   os: macos-latest,   dcos: macos }" in live
    assert "{ connector: opencode,   os: ubuntu-latest,  dcos: linux }" not in live

    run = (ROOT / "scripts/live-connector-e2e/run.sh").read_text(encoding="utf-8")
    contract_match = re.search(r"^ALL_CONNECTORS=\(([^)]*)\)$", run, flags=re.MULTILINE)
    live_match = re.search(r"^LIVE_CONNECTORS=\(([^)]*)\)$", run, flags=re.MULTILINE)
    assert contract_match is not None
    assert live_match is not None
    assert "opencode" not in contract_match.group(1).split()
    assert "opencode" in live_match.group(1).split()

    setup = (ROOT / "scripts/live-connector-e2e/lib/setup.sh").read_text(encoding="utf-8")
    assert "${OPENCODE_CONFIG_DIR:-${HOME}/.config/opencode}" in setup
    assert "/plugins/defenseclaw.js" in setup

    driver = (ROOT / "scripts/live-connector-e2e/drivers/opencode.sh").read_text(encoding="utf-8")
    assert 'OPENCODE_REVIEWED_VERSION="1.18.19"' in driver
    assert "^1\\.18\\.1[0-9]$" in driver
    assert "export OPENCODE_DISABLE_AUTOUPDATE=1" in driver
    assert driver.index("export OPENCODE_DISABLE_AUTOUPDATE=1") < driver.index("dc_driver_main opencode")
    assert 'npm install -g "opencode-ai@${requested}"' in driver
    assert 'dc_write_env_key OPENAI_API_KEY "${OPENAI_API_KEY}"' in driver
    assert "OPENAI_API_KEY is required" in driver
    assert "currently scoped to macOS" in driver
    assert 'DC_DRIVER_MODE="${DC_DRIVER_MODE:-action}"' in driver
    assert "DC_DRIVER_SUPPORTS_BLOCK=1" in driver
    assert "DC_DRIVER_SUPPORTS_LIFECYCLE=0" in driver
    assert "DC_DRIVER_SUPPORTS_OTLP=0" in driver
    assert "opencode run --format json" in driver


def test_claudecode_posix_live_driver_uses_the_sealed_official_native_release() -> None:
    driver = (ROOT / "scripts/live-connector-e2e/drivers/claudecode.sh").read_text(encoding="utf-8")

    assert "@anthropic-ai/claude-code" not in driver
    assert "https://downloads.claude.ai/claude-code-releases/latest" in driver
    assert '"https://downloads.claude.ai/claude-code-releases/${version}/manifest.json"' in driver
    assert '"https://downloads.claude.ai/claude-code-releases/${version}/${platform}/claude"' in driver
    assert "--proto '=https' --proto-redir '=https' --tlsv1.2" in driver
    assert "--max-filesize 536870912" in driver
    assert 're.fullmatch(r"[0-9a-f]{64}", checksum)' in driver
    assert "size > 536_870_912" in driver
    assert 'actual_checksum="$(claude_sha256_file "${download_path}")"' in driver
    assert 'actual_checksum="$(claude_sha256_file "${staged}")"' in driver
    assert '[ -e "${target}" ] || [ -L "${target}" ]' in driver
    assert '[ -e "${launcher}" ] || [ -L "${launcher}" ]' in driver
    assert 'ln -s "${target}" "${launcher}"' in driver
    assert "ln -sfn" not in driver
    assert "export DISABLE_AUTOUPDATER=1" in driver
    assert 'DC_E2E_AGENT_VERSION="${version}"' in driver
    assert "dc_capture_version claudecode" not in driver
    assert "claude --version" not in driver
    assert driver.index("export DISABLE_AUTOUPDATER=1") < driver.index('DC_E2E_AGENT_VERSION="${version}"')

    docs = " ".join(
        (ROOT / "docs-site/content/docs/connectors/claudecode.mdx").read_text(encoding="utf-8").split()
    )
    assert "Native macOS arm64 setup is **preview**" in docs
    assert "`~/.local/share/claude/versions/<version>`" in docs
    assert "Anthropic's pinned Developer ID identity" in docs
    assert "no quarantine xattr" in docs


def test_openhands_official_cli_and_protected_macos_live_path_are_reachable() -> None:
    workflow = (ROOT / ".github/workflows/connector-live-e2e.yml").read_text(encoding="utf-8")
    live = workflow.split("  live-matrix:", 1)[1].split("  windows-live:", 1)[0]
    assert "{ connector: openhands,  os: ubuntu-latest,  dcos: linux }" in live
    assert "{ connector: openhands,  os: macos-latest,   dcos: macos }" in live

    driver = (ROOT / "scripts/live-connector-e2e/drivers/openhands.sh").read_text(encoding="utf-8")
    assert "openhands-ai" not in driver
    # Linux retains upstream's uv tool path; protected Darwin execution uses
    # the real standalone Mach-O rather than sealing uv's console script.
    assert 'package="openhands"' in driver
    assert 'uv tool install --python 3.12 --force "${package}"' in driver
    assert 'OPENHANDS_REVIEWED_MACOS_VERSION="1.16.0"' in driver
    assert 'OPENHANDS_REVIEWED_MACOS_ARM64_SIZE="86732736"' in driver
    assert (
        'OPENHANDS_REVIEWED_MACOS_ARM64_SHA256="fa238330a452f2f1e933affb7edffda43c01f1ebd84194ecc564c5a6a306317f"'
        in driver
    )
    assert "https://github.com/OpenHands/OpenHands-CLI/releases/download/${version}/openhands-macos-arm64" in driver
    assert "--proto '=https' --proto-redir '=https' --tlsv1.2" in driver
    assert "--max-filesize 100663296" in driver
    assert 'target_dir="${versions_root}/${version}"' in driver
    assert 'target="${target_dir}/openhands"' in driver
    assert 'install -m 0500 "${download_path}" "${staged_dir}/openhands"' in driver
    assert 'ln -s "${target}" "${launcher}"' in driver
    assert 'DC_E2E_AGENT_VERSION="${version}"' in driver
    assert "pinned to reviewed standalone release" in driver
    assert 'DC_DRIVER_MODE="${DC_DRIVER_MODE:-action}"' in driver
    assert 'if [ "$(dc_detect_os)" = "macos" ]; then' in driver
    assert "DC_DRIVER_SUPPORTS_OTLP=1" in driver
    assert "DC_DRIVER_SUPPORTS_OTLP=0" in driver
    protected = "defenseclaw-gateway connector launch --connector openhands --"
    assert protected in driver
    assert '--headless --override-with-envs -t "${prompt}"' in driver
    assert driver.index(protected) < driver.index("dc_driver_main openhands")

    docs = " ".join(
        (ROOT / "docs-site/content/docs/connectors/openhands.mdx").read_text(encoding="utf-8").split()
    )
    assert "macOS support remains **preview**" in docs
    assert "`>=1.12.0`" in docs
    assert "`~/.local/share/openhands/versions/<version>/openhands`" in docs
    assert "refuses scripts" in docs
    assert "reviewed byte size and SHA-256" in docs
    assert "**trace-only native OTLP**" in docs
    assert "standalone OpenHands SDK `1.39.1`" in docs
    assert "does not widen or otherwise change the CLI compatibility range" in docs
    assert "Plugins TUI panel stays hidden" in docs

    run = (ROOT / "scripts/live-connector-e2e/run.sh").read_text(encoding="utf-8")
    assert "/usr/bin/cc -Os" in run
    assert "fixture would incorrectly bypass the protected live execution boundary" in run


def test_unix_contract_matrix_covers_executable_shell_hook_connectors() -> None:
    workflow = (ROOT / ".github/workflows/connector-live-e2e.yml").read_text(encoding="utf-8")
    full_match = re.search(r"^\s*full='([^']+)'$", workflow, flags=re.MULTILINE)
    assert full_match is not None
    expected = {
        "codex",
        "claudecode",
        "amp",
        "cursor",
        "copilot",
        "openhands",
        "hermes",
        "devin",
        "antigravity",
    }
    assert set(json.loads(full_match.group(1))["connector"]) == expected

    run = (ROOT / "scripts/live-connector-e2e/run.sh").read_text(encoding="utf-8")
    shell_match = re.search(r"^ALL_CONNECTORS=\(([^)]*)\)$", run, flags=re.MULTILINE)
    assert shell_match is not None
    assert set(shell_match.group(1).split()) == expected

    dispatch = workflow.split("      connector:", 1)[1].split("      os:", 1)[0]
    for connector in expected:
        assert f"          - {connector}" in dispatch
    # OpenCode and OmniGent use plugin/policy transports rather than the shell
    # hook entrypoint exercised by contract-smoke.sh. Neither belongs in this
    # generic executable-hook matrix.
    assert "opencode" not in json.loads(full_match.group(1))["connector"]
    assert "omnigent" not in json.loads(full_match.group(1))["connector"]
    assert "          - openclaw" not in dispatch
    assert "          - zeptoclaw" not in dispatch
    assert "          - geminicli" not in dispatch


def test_copilot_contract_normalizes_fixture_event_to_native_registration() -> None:
    fixture = json.loads(
        (ROOT / "scripts/live-connector-e2e/golden/copilot/pre_tool_allow.json").read_text(encoding="utf-8")
    )
    assert fixture["hook_event_name"] == "preToolUse"

    common = (ROOT / "scripts/live-connector-e2e/lib/common.sh").read_text(encoding="utf-8")
    assert 'copilot:PreToolUse) bound_event="preToolUse" ;;' in common
