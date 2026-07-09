# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CURRENT_RELEASE = "0.8.3"
STALE_RELEASES = ("0.8.0", "0.8.1", "0.8.2")

BASH_INSTALL_LINES = (
    f"VERSION={CURRENT_RELEASE}",
    'INSTALL_URL="https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/${VERSION}/scripts/install.sh"',
    'curl -LsSf "$INSTALL_URL" | VERSION="$VERSION" bash',
)
UPGRADE_SCRIPT_LINES = (
    f"UPGRADE_SCRIPT_VERSION={CURRENT_RELEASE}",
    'UPGRADE_URL="https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/${UPGRADE_SCRIPT_VERSION}/scripts/upgrade.sh"',
)

DOC_INSTALL_COMMANDS = {
    "README.md": BASH_INSTALL_LINES,
    "docs/QUICKSTART.md": BASH_INSTALL_LINES,
    "docs/INSTALL.md": BASH_INSTALL_LINES
    + (
        'curl -LsSf "$INSTALL_URL" | VERSION="$VERSION" bash -s -- --connector codex',
        'curl -LsSf "$INSTALL_URL" | VERSION="$VERSION" bash -s -- --connector claudecode',
        'curl -LsSf "$INSTALL_URL" | VERSION="$VERSION" bash -s -- --connector zeptoclaw',
        'curl -LsSf "$INSTALL_URL" | VERSION="$VERSION" bash -s -- --connector none',
        'curl -LsSf "$INSTALL_URL" | VERSION="$VERSION" bash -s -- --no-openclaw',
    ),
    "docs-site/content/docs/get-started/install.mdx": BASH_INSTALL_LINES
    + (
        f'$Version = "{CURRENT_RELEASE}"',
        '$InstallUrl = "https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/$Version/scripts/install.ps1"',
        "& ([scriptblock]::Create((irm $InstallUrl))) -Version $Version",
        "& ([scriptblock]::Create((irm $InstallUrl))) -Version $Version -Connector codex -Quickstart -Yes",
    ),
    "docs-site/content/docs/get-started/first-guardrail.mdx": (
        f"VERSION={CURRENT_RELEASE}",
        'INSTALL_URL="https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/${VERSION}/scripts/install.sh"',
        'curl -LsSf "$INSTALL_URL" | VERSION="$VERSION" bash -s -- --connector claudecode',
    ),
    "docs-site/components/terminal-demo.tsx": (
        f"const INSTALL_VERSION = '{CURRENT_RELEASE}';",
        "text: `curl -LsSf https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/${INSTALL_VERSION}/scripts/install.sh | VERSION=${INSTALL_VERSION} bash`,",
    ),
}

INSTALLER_FILES = (
    "scripts/install.sh",
    "scripts/install.ps1",
)


def test_quickstart_docs_do_not_pipe_main_installer() -> None:
    for rel, expected_lines in DOC_INSTALL_COMMANDS.items():
        text = (ROOT / rel).read_text()
        assert "raw.githubusercontent.com/cisco-ai-defense/defenseclaw/main/scripts/install.sh" not in text
        assert "raw.githubusercontent.com/cisco-ai-defense/defenseclaw/main/scripts/install.ps1" not in text
        for expected in expected_lines:
            assert expected in text, f"{rel} is missing install snippet line: {expected}"


def test_install_docs_do_not_pipe_main_upgrader() -> None:
    text = (ROOT / "docs/INSTALL.md").read_text()
    assert "raw.githubusercontent.com/cisco-ai-defense/defenseclaw/main/scripts/upgrade.sh" not in text

    upgrade_start = text.index("### Upgrading from 0.2.0 to an artifact-backed release")
    rollback_start = text.index("### Rollback")
    troubleshooting_start = text.index("## Troubleshooting")
    upgrade_section = text[upgrade_start:rollback_start]
    rollback_section = text[rollback_start:troubleshooting_start]

    for section in (upgrade_section, rollback_section):
        for expected in UPGRADE_SCRIPT_LINES:
            assert expected in section
    for expected in UPGRADE_SCRIPT_LINES:
        assert text.count(expected) == 2


def test_installer_help_does_not_pipe_main_installer() -> None:
    for rel in INSTALLER_FILES:
        text = (ROOT / rel).read_text()
        assert "defenseclaw/main" not in text


def test_install_docs_track_current_release() -> None:
    for rel, expected_lines in DOC_INSTALL_COMMANDS.items():
        snippet = "\n".join(expected_lines)
        assert CURRENT_RELEASE in snippet, f"{rel} must pin at least one installer version"
        for stale in STALE_RELEASES:
            assert stale not in snippet, f"{rel} still expects stale install snippet version {stale}"
