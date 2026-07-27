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

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNBOOK = ROOT / "docs" / "RELEASE_RUNBOOK.md"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _words(path: Path) -> str:
    return " ".join(_text(path).split())


def test_release_runbook_covers_both_operator_flows() -> None:
    runbook = _words(RUNBOOK)
    raw_runbook = _text(RUNBOOK)

    assert "scripts/release-preflight.py operator" in runbook
    assert "--operation release" in runbook
    assert "--operation repair-channel" in runbook
    assert "immutable-releases-confirmed true" in runbook
    assert "immutable-releases-confirmed false" not in runbook
    assert "gh workflow run release.yaml" in runbook
    assert "--repo cisco-ai-defense/defenseclaw" in runbook
    assert "--ref main" in runbook
    assert '-f expected_commit="$RELEASE_COMMIT"' in runbook
    assert "The preflight does not dispatch or publish anything." in runbook
    assert "From a macOS or Linux checkout" in runbook
    assert "POSIX `O_NOFOLLOW` descriptor custody" in runbook
    assert "Repair never builds, edits, uploads, or replaces a tagged asset." in runbook
    assert raw_runbook.count('RELEASE_COMMIT="replace-with-exact-40-character-workflow-commit"') == 2
    assert "RELEASE_COMMIT=<" not in raw_runbook


def test_release_runbook_preserves_channel_and_immutability_contracts() -> None:
    runbook = _words(RUNBOOK)
    policy = json.loads(_text(ROOT / "release" / "release-channel-ruleset-policy.json"))

    assert "release/release-channel-ruleset-policy.json" in runbook
    assert policy["target_ref"] in runbook
    for rule in policy["required_rules"]:
        assert f"`{rule}`" in runbook
    bypass = policy["publisher_bypass"]
    assert f"Organization `{policy['source']}`" in runbook
    assert "`defenseclaw`" in runbook
    assert f"`{bypass['actor_type']}` actor `{bypass['actor_id']}`" in runbook
    assert f"mode `{bypass['bypass_mode']}`" in runbook

    assert "Immutable tagged releases." in runbook
    assert "A mutable, signed stable channel." in runbook
    assert "Never manually create, push, move, or delete a release tag." in runbook
    assert "Never edit, delete, or force-push `release-channel`" in runbook
    assert "publish a new patch version" in runbook


def test_release_runbook_preserves_install_upgrade_and_unsigned_scope() -> None:
    runbook = _words(RUNBOOK)

    for baseline in ("`0.8.6`", "`0.8.5`", "`0.8.4`", "`0.7.x`", "`0.6.x`", "`0.5.x`"):
        assert baseline in runbook
    for asset in (
        "install.sh",
        "install.ps1",
        "DefenseClawSetup-x64.exe",
        "checksums.txt",
        "defenseclaw-rescue.sh",
        "defenseclaw-rescue.ps1",
    ):
        assert asset in runbook
    assert "defenseclaw upgrade --yes" in runbook
    assert "Get-AuthenticodeSignature" in runbook
    assert "`-unverified`" in runbook
    assert "Authenticode `NotSigned`" in runbook
    assert "Missing platform credentials do not block an otherwise valid release" in runbook
    assert "Use disposable, clean hosts" in runbook


def test_windows_public_install_authenticates_saved_script_before_execution() -> None:
    runbook = _text(RUNBOOK)
    start = runbook.index("On a disposable native Windows x64 host")
    end = runbook.index("The installed CLI and gateway must report", start)
    windows = runbook[start:end]

    download = windows.index("gh release download")
    authenticate = windows.index("scripts/verify-sigstore-blob.py")
    bind_installer_digest = windows.index("Get-FileHash -LiteralPath $Installer")
    bind_setup_digest = windows.index("Get-FileHash -LiteralPath $Setup")
    inspect_signature = windows.index("Get-AuthenticodeSignature $Setup")
    inspect_publisher = windows.index("$SetupSignature.SignerCertificate.GetNameInfo")
    execute = windows.index("& $Installer")

    assert (
        download
        < authenticate
        < bind_installer_digest
        < bind_setup_digest
        < inspect_signature
        < inspect_publisher
        < execute
    )
    assert "checksums.txt.pem" in windows
    assert "checksums.txt.sig" in windows
    assert "release.yaml@refs/heads/main" in windows
    assert "^[0-9a-f]{64}  install\\.ps1$" in windows
    assert "^[0-9a-f]{64}  DefenseClawSetup-x64\\.exe$" in windows
    assert ".\\install.ps1 -Version" not in windows
    assert "$ExpectUnsignedSetup" in windows
    assert '"NotSigned"' in windows
    assert '"Valid"' in windows
    assert '"Cisco Systems, Inc."' in windows
    assert "$SetupSignature.Status.ToString()" in windows


def test_release_docs_route_to_canonical_runbook_and_preflight() -> None:
    validation_path = ROOT / "docs" / "RELEASE_VALIDATION.md"
    validation = _words(validation_path)
    channel = _words(ROOT / "docs" / "RELEASE_CHANNEL.md")

    assert "RELEASE_RUNBOOK.md" in validation
    assert "scripts/release-preflight.py operator" in validation
    assert "expected_commit" in validation
    assert "--repo cisco-ai-defense/defenseclaw" in validation
    assert 'RELEASE_COMMIT="replace-with-exact-40-character-workflow-commit"' in validation
    assert "RELEASE_COMMIT=<" not in _text(validation_path)
    assert "first native Windows release" in validation
    assert "through `0.8.8` is explicitly fresh-install-only" in validation
    assert "RELEASE_RUNBOOK.md" in channel
    assert "scripts/release-preflight.py operator" in channel
