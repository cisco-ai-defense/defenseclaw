# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml
from defenseclaw.commands.cmd_upgrade import _detect_platform
from defenseclaw.resolver_hint import COSIGN_BOOTSTRAP_SHA256, authenticated_resolver_instructions

ROOT = Path(__file__).resolve().parents[2]


def _text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_python_upgrade_rejects_intel_macos(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr("platform.system", lambda: "Darwin")
    monkeypatch.setattr("platform.machine", lambda: "x86_64")

    with pytest.raises(SystemExit, match="1"):
        _detect_platform()

    captured = capsys.readouterr()
    assert "Intel macOS is unsupported" in captured.out + captured.err


def test_release_build_and_package_contract_is_arm64_only() -> None:
    workflow = yaml.safe_load(_text(".github/workflows/ci.yml"))
    matrix = workflow["jobs"]["go-build"]["strategy"]["matrix"]["include"]
    assert {tuple(sorted(entry.items())) for entry in matrix} == {
        (("goarch", "amd64"), ("goos", "linux")),
        (("goarch", "arm64"), ("goos", "linux")),
        (("goarch", "arm64"), ("goos", "darwin")),
    }

    makefile = _text("Makefile")
    assert "BUNDLE_GOARCH ?= arm64" in makefile
    assert 'test "$(BUNDLE_GOARCH)" = "arm64"' in makefile
    assert "linux/amd64 linux/arm64 darwin/arm64" in makefile
    assert "linux/amd64 linux/arm64 darwin/amd64" not in makefile

    builder = _text("scripts/build-macos-bundle.sh")
    assert '[[ "${BUNDLE_GOARCH}" != "arm64" ]]' in builder
    assert "build_arch amd64" not in builder
    assert "lipo -create" not in builder

    app_builder = _text("scripts/build-macos-app-release.sh")
    assert '[[ "$(uname -m)" == "arm64" ]]' in app_builder
    assert "macOS app releases require Apple Silicon (arm64)" in app_builder

    goreleaser = _text(".goreleaser.yaml")
    assert "Darwin/amd64 compatibility slot" in goreleaser
    assert "user entry point rejects Intel macOS" in goreleaser


def test_macos_bundle_builder_refuses_intel_before_writing_output(tmp_path: Path) -> None:
    output = tmp_path / "bundle"
    completed = subprocess.run(
        [
            "bash",
            "scripts/build-macos-bundle.sh",
            "darwin",
            "amd64",
            "unsupported-intel-bundle",
            str(output),
            str(tmp_path),
            "9.9.9",
            "-X main.version=9.9.9",
            "",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 1
    assert "Intel and universal macOS bundles are unsupported" in completed.stderr
    assert not output.exists()


def test_all_macos_install_and_recovery_surfaces_refuse_intel_explicitly() -> None:
    install = _text("scripts/install.sh")
    assert "Intel macOS (${ARCH}) is unsupported" in install
    call_sequence = install.rindex("\ndetect_platform\nresolve_version\nensure_uv\nensure_python\nload_release_policy\n")
    assert call_sequence > install.index("Intel macOS (${ARCH}) is unsupported")

    upgrade = _text("scripts/upgrade.sh")
    early_refusal = 'if [[ "$(uname -s)" == "Darwin" && "$(uname -m)" != "arm64" ]]'
    assert early_refusal in upgrade
    assert upgrade.index(early_refusal) < upgrade.index('if [[ -e "${UPGRADE_RECOVERY_ROOT}/phase-one-active.json"')

    managed = _text("packaging/macos/install.sh")
    assert "the managed macOS package requires Apple Silicon (arm64)" in managed
    assert managed.index("the managed macOS package requires Apple Silicon") < managed.index("# ---- arg parsing")

    source_install = _text("scripts/install-dev.sh")
    assert "DefenseClaw for macOS requires Apple Silicon (arm64)" in source_install

    rescue = _text("scripts/defenseclaw-rescue.sh")
    assert 'darwin/x86_64)\n        die "Intel macOS is unsupported' in rescue


def test_authenticated_resolver_has_no_intel_macos_verifier_path() -> None:
    assert ("darwin", "amd64") not in COSIGN_BOOTSTRAP_SHA256
    instructions = authenticated_resolver_instructions("9.9.9")
    assert "cosign-darwin-amd64" not in instructions
    assert "Intel macOS is unsupported" in instructions


def test_support_docs_state_the_breaking_architecture_boundary() -> None:
    for path in (
        "docs/INSTALL.md",
        "docs/RELEASE_VALIDATION.md",
        "docs/RELEASE_RUNBOOK.md",
        "docs-site/content/docs/get-started/install.mdx",
    ):
        body = _text(path)
        assert "Intel" in body, path
        assert "arm64" in body, path
        assert "unsupported" in body.lower() or "outside the supported" in body.lower(), path
