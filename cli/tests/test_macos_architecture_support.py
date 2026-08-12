# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import defenseclaw.commands.cmd_upgrade as upgrade_module
import defenseclaw.main as main_module
import pytest
import yaml
from click.testing import CliRunner
from defenseclaw.commands.cmd_upgrade import _detect_platform
from defenseclaw.context import AppContext
from defenseclaw.resolver_hint import COSIGN_BOOTSTRAP_SHA256, authenticated_resolver_instructions

ROOT = Path(__file__).resolve().parents[2]
INTEL_REFUSAL_HARNESS = ROOT / "scripts/test-upgrade-macos-intel-refusal.sh"


def _text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def test_python_upgrade_rejects_intel_macos(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr("platform.system", lambda: "Darwin")
    monkeypatch.setattr("platform.machine", lambda: "x86_64")

    with pytest.raises(SystemExit, match="1"):
        _detect_platform()

    captured = capsys.readouterr()
    assert "Intel macOS is unsupported" in captured.out + captured.err


def test_public_upgrade_rejects_intel_before_resolver_network_or_state() -> None:
    with (
        patch.object(upgrade_module.platform, "system", return_value="Darwin"),
        patch.object(upgrade_module.platform, "machine", return_value="x86_64"),
        patch.object(upgrade_module, "_authenticated_release_resolver") as resolver,
        patch.object(upgrade_module, "_fetch_latest_version") as latest,
        patch.object(upgrade_module.tempfile, "TemporaryDirectory") as temporary_directory,
        pytest.raises(SystemExit, match="1"),
    ):
        upgrade_module._maybe_delegate_public_upgrade(["upgrade", "--yes"])

    resolver.assert_not_called()
    latest.assert_not_called()
    temporary_directory.assert_not_called()


def test_click_upgrade_rejects_intel_before_recovery_network_or_state() -> None:
    app = AppContext()
    with (
        patch.object(upgrade_module.platform, "system", return_value="Darwin"),
        patch.object(upgrade_module.platform, "machine", return_value="x86_64"),
        patch.object(main_module.os.path, "lexists") as recovery_probe,
        patch.object(upgrade_module, "_fetch_latest_version") as latest,
        patch.object(upgrade_module.tempfile, "TemporaryDirectory") as temporary_directory,
    ):
        result = CliRunner().invoke(main_module.cli, ["upgrade", "--yes"], obj=app)

    assert result.exit_code == 1, result.output
    assert "Intel macOS is unsupported" in result.output
    recovery_probe.assert_not_called()
    latest.assert_not_called()
    temporary_directory.assert_not_called()


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


def test_authenticated_resolver_has_no_intel_macos_verifier_or_state_path(tmp_path: Path) -> None:
    assert ("darwin", "amd64") not in COSIGN_BOOTSTRAP_SHA256
    instructions = authenticated_resolver_instructions("9.9.9")
    assert "cosign-darwin-amd64" not in instructions
    assert "Intel macOS is unsupported" in instructions
    platform_probe = "  platform=\"$(uname -s | tr '[:upper:]' '[:lower:]')/$(uname -m)\""
    temp_allocation = '  d="$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-upgrade.XXXXXX")"'
    assert instructions.index(platform_probe) < instructions.index(temp_allocation)

    marker = tmp_path / "mktemp-invoked"
    posix = instructions.split("POSIX:\n", 1)[1].split("\nWindows PowerShell:", 1)[0]
    intel = posix.replace(platform_probe, '  platform="darwin/x86_64"', 1).replace(
        temp_allocation,
        f"  printf invoked > '{marker}'; {temp_allocation.strip()}",
        1,
    )
    completed = subprocess.run(
        ["bash"],
        input=intel,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 1
    assert "Intel macOS is unsupported" in completed.stderr
    assert not marker.exists()


def test_documented_resolver_rejects_intel_before_temp_or_network() -> None:
    site = _text("docs-site/content/docs/get-started/upgrade.mdx")
    platform_probe = 'platform="$(uname -s | tr \'[:upper:]\' \'[:lower:]\')/$(uname -m)"'
    assert site.index(platform_probe) < site.index('d="$(mktemp -d')
    assert site.index("darwin/x86_64) echo 'Intel macOS is unsupported") < site.index('d="$(mktemp -d')
    assert site.index("darwin/x86_64) echo 'Intel macOS is unsupported") < site.index("curl --fail")


@pytest.mark.parametrize(
    ("surface", "controller_name"),
    (("fresh-install", "install.sh"), ("upgrade", "defenseclaw-upgrade.sh")),
)
def test_intel_refusal_harness_detects_transient_create_delete(
    tmp_path: Path,
    surface: str,
    controller_name: str,
) -> None:
    release = tmp_path / "release"
    fake_bin = tmp_path / "fake-bin"
    runner_temp = tmp_path / "runner-temp"
    release.mkdir()
    fake_bin.mkdir()
    runner_temp.mkdir()
    _write_executable(
        fake_bin / "uname",
        "#!/bin/sh\n"
        "case \"${1:-}\" in\n"
        "  -s) printf 'Darwin\\n' ;;\n"
        "  -m) printf 'x86_64\\n' ;;\n"
        "  *) exec /usr/bin/uname \"$@\" ;;\n"
        "esac\n",
    )
    transient_controller = (
        "#!/bin/bash\n"
        "set -u\n"
        "printf 'transient state\\n' > \"$HOME/create-then-delete\"\n"
        "/bin/rm -f \"$HOME/create-then-delete\"\n"
        "printf 'Intel macOS is unsupported\\n' >&2\n"
        "exit 1\n"
    )
    _write_executable(release / controller_name, transient_controller)

    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{fake_bin}:/usr/bin:/bin:/usr/sbin:/sbin",
            "RUNNER_TEMP": str(runner_temp),
        }
    )
    completed = subprocess.run(
        [
            str(INTEL_REFUSAL_HARNESS),
            "--surface",
            surface,
            "--release-dir",
            str(release),
            "--version",
            "9.9.9",
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    diagnostic = completed.stdout + completed.stderr
    assert completed.returncode == 1, diagnostic
    assert "changed the exact candidate, install, recovery, or temporary state" in diagnostic
    assert not list(runner_temp.iterdir())


def test_intel_refusal_harness_reaches_real_fresh_installer_guard(tmp_path: Path) -> None:
    release = tmp_path / "release"
    fake_bin = tmp_path / "fake-bin"
    runner_temp = tmp_path / "runner-temp"
    release.mkdir()
    fake_bin.mkdir()
    runner_temp.mkdir()
    _write_executable(
        fake_bin / "uname",
        "#!/bin/sh\n"
        "case \"${1:-}\" in\n"
        "  -s) printf 'Darwin\\n' ;;\n"
        "  -m) printf 'x86_64\\n' ;;\n"
        "  *) exec /usr/bin/uname \"$@\" ;;\n"
        "esac\n",
    )
    (release / "install.sh").write_bytes((ROOT / "scripts/install.sh").read_bytes())
    (release / "install.sh").chmod(0o755)

    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{fake_bin}:/usr/bin:/bin:/usr/sbin:/sbin",
            "RUNNER_TEMP": str(runner_temp),
        }
    )
    completed = subprocess.run(
        [
            str(INTEL_REFUSAL_HARNESS),
            "--surface",
            "fresh-install",
            "--release-dir",
            str(release),
            "--version",
            "9.9.9",
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    diagnostic = completed.stdout + completed.stderr
    assert completed.returncode == 0, diagnostic
    assert "Intel macOS fresh-install refusal passed" in diagnostic
    assert not list(runner_temp.iterdir())


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
