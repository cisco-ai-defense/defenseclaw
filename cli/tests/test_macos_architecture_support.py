# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
MACOS_HARDWARE_ENTRYPOINTS = (
    "scripts/install.sh",
    "scripts/install-dev.sh",
    "packaging/macos/install.sh",
    "scripts/build-macos-app-release.sh",
    "packaging/scripts/build-managed-macos-bundle.sh",
)


def _text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def _sysctl_translation_result(translated: bool) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        ["/usr/sbin/sysctl", "-in", "sysctl.proc_translated"],
        0,
        stdout="1\n" if translated else "0\n",
        stderr="",
    )










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

    managed_builder = _text("packaging/scripts/build-managed-macos-bundle.sh")
    assert 'BUNDLE_GOARCH="${BUNDLE_GOARCH:-arm64}"' in managed_builder
    assert '[[ "$(macos_hardware_machine "$(uname -m)")" == "arm64" ]]' in managed_builder
    assert "require_bin lipo" not in managed_builder
    assert "default: universal" not in managed_builder

    app_builder = _text("scripts/build-macos-app-release.sh")
    assert '[[ "$(macos_hardware_machine "$(uname -m)")" == "arm64" ]]' in app_builder
    assert "macOS app releases require Apple Silicon (arm64)" in app_builder

    goreleaser = yaml.safe_load(_text(".goreleaser.yaml"))
    gateway_build = next(build for build in goreleaser["builds"] if build["id"] == "defenseclaw")
    # GoReleaser still feeds the signed Protocol-2 compatibility slot. The
    # supported build/package matrices above remain arm64-only on Darwin.
    assert gateway_build["goos"] == ["linux", "darwin"]
    assert gateway_build["goarch"] == ["amd64", "arm64"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell contract")
def test_managed_bundle_wrapper_drives_arm64_target_without_lipo(tmp_path: Path) -> None:
    ai_common = tmp_path / "ai-common"
    fake_bin = tmp_path / "bin"
    fake_sysctl = tmp_path / "sysctl"
    make_log = tmp_path / "make.log"
    managed_builder = tmp_path / "packaging/scripts/build-managed-macos-bundle.sh"
    (ai_common / ".git").mkdir(parents=True)
    (ai_common / "cmid").mkdir()
    (ai_common / "cmid/go.mod").write_text("module example.invalid/cmid\n", encoding="utf-8")
    overlay = ai_common / "defenseclaw_cmid_overlay/provider_cisco.go"
    overlay.parent.mkdir()
    overlay.write_text("package provider\n", encoding="utf-8")
    fake_bin.mkdir()
    _write_executable(
        fake_bin / "uname",
        "#!/bin/sh\n"
        "case \"${1:-}\" in\n"
        "  -s) printf 'Darwin\\n' ;;\n"
        "  -m) printf 'x86_64\\n' ;;\n"
        "  *) exit 64 ;;\n"
        "esac\n",
    )
    _write_executable(fake_sysctl, "#!/bin/sh\nprintf '1\\n'\n")
    _write_executable(fake_bin / "go", "#!/bin/sh\nexit 0\n")
    _write_executable(
        fake_bin / "git",
        "#!/bin/sh\n"
        "case \" $* \" in\n"
        "  *' rev-parse HEAD '*) printf '0123456789abcdef0123456789abcdef01234567\\n' ;;\n"
        "  *' show -s '*) printf '20260812010101\\n' ;;\n"
        "  *) exit 0 ;;\n"
        "esac\n",
    )
    _write_executable(
        fake_bin / "make",
        f"#!/bin/sh\nprintf '%s\\n' \"$@\" > {make_log!s}\n",
    )
    managed_builder.parent.mkdir(parents=True)
    _write_executable(
        managed_builder,
        _text("packaging/scripts/build-managed-macos-bundle.sh").replace(
            'readonly MACOS_SYSCTL_BIN="/usr/sbin/sysctl"',
            f'readonly MACOS_SYSCTL_BIN="{fake_sysctl!s}"',
            1,
        ),
    )
    environment = {
        **os.environ,
        "PATH": f"{fake_bin}:/usr/bin:/bin",
    }

    completed = subprocess.run(
        [
            "bash",
            str(managed_builder),
            "--ai-common-dir",
            str(ai_common),
            "--ref",
            "reviewed-ref",
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    invocation = make_log.read_text(encoding="utf-8")
    assert "packaging-macos-bundle" in invocation
    assert "BUNDLE_GOARCH=arm64" in invocation
    assert "universal" not in invocation


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell contract")
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
        timeout=30,
    )

    assert completed.returncode == 1
    assert "Intel and universal macOS bundles are unsupported" in completed.stderr
    assert not output.exists()


def test_all_macos_install_and_recovery_surfaces_refuse_intel_explicitly() -> None:
    install = _text("scripts/install.sh")
    assert "Intel macOS (${MACHINE}) is unsupported" in install
    # The refusal happens before the installer downloads or changes anything.
    assert install.index("Intel macOS (${MACHINE}) is unsupported") < install.index("mkdir -p \"${DEFENSECLAW_HOME}\"")

    managed = _text("packaging/macos/install.sh")
    assert "the managed macOS package requires Apple Silicon (arm64)" in managed
    assert managed.index("the managed macOS package requires Apple Silicon") < managed.index("# ---- arg parsing")

    source_install = _text("scripts/install-dev.sh")
    assert "DefenseClaw for macOS requires Apple Silicon (arm64)" in source_install



@pytest.mark.parametrize("path", MACOS_HARDWARE_ENTRYPOINTS)
@pytest.mark.skipif(os.name == "nt", reason="POSIX shell contract")
def test_shell_entrypoints_distinguish_rosetta_from_genuine_intel(tmp_path: Path, path: str) -> None:
    source = _text(path)
    start = source.index("macos_hardware_machine() {")
    end = source.index("\n}\n", start) + len("\n}\n")
    helper = source[start:end]
    fake_sysctl = tmp_path / "sysctl"
    _write_executable(fake_sysctl, "#!/bin/sh\nprintf '1\\n'\n")
    probe = subprocess.run(
        ["bash", "-c", f'MACOS_SYSCTL_BIN={fake_sysctl!s}\n{helper}\nmacos_hardware_machine x86_64'],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.strip() == "arm64"

    _write_executable(fake_sysctl, "#!/bin/sh\nprintf '0\\n'\n")
    probe = subprocess.run(
        ["bash", "-c", f'MACOS_SYSCTL_BIN={fake_sysctl!s}\n{helper}\nmacos_hardware_machine x86_64'],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.strip() == "x86_64"














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
