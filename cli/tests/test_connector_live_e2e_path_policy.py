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
        "scripts/invoke-windows-setup-standard-user-ci.ps1",
        "scripts/test-fresh-install-release-windows.ps1",
        "scripts/test-upgrade-release-windows.ps1",
        "scripts/test-windows-disposable-user-safety.ps1",
        "scripts/test-windows-setup-wizard.ps1",
        "scripts/upgrade.ps1",
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
