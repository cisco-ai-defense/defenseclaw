# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
INTEL_REFUSAL_HARNESS = ROOT / "scripts/test-upgrade-macos-intel-refusal.sh"
MACOS_HARDWARE_ENTRYPOINTS = (
    "scripts/install.sh",
    "scripts/install-dev.sh",
    "scripts/upgrade.sh",
    "scripts/defenseclaw-rescue.sh",
    "packaging/macos/install.sh",
    "scripts/build-macos-app-release.sh",
    "packaging/scripts/build-managed-macos-bundle.sh",
    "scripts/test-fresh-install-release.sh",
    "scripts/test-upgrade-release.sh",
    "scripts/test-upgrade-macos-intel-refusal.sh",
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
    assert "Intel macOS (${ARCH}) is unsupported" in install
    call_sequence = install.rindex("\ndetect_platform\nresolve_version\nensure_uv\nensure_python\nload_release_policy\n")
    assert call_sequence > install.index("Intel macOS (${ARCH}) is unsupported")

    upgrade = _text("scripts/upgrade.sh")
    early_refusal = 'if [[ "${HOST_SYSTEM}" == "Darwin" && "${HOST_MACHINE}" != "arm64" ]]'
    assert early_refusal in upgrade
    assert upgrade.index(early_refusal) < upgrade.index('if [[ -e "${UPGRADE_RECOVERY_ROOT}/phase-one-active.json"')

    managed = _text("packaging/macos/install.sh")
    assert "the managed macOS package requires Apple Silicon (arm64)" in managed
    assert managed.index("the managed macOS package requires Apple Silicon") < managed.index("# ---- arg parsing")

    source_install = _text("scripts/install-dev.sh")
    assert "DefenseClaw for macOS requires Apple Silicon (arm64)" in source_install

    rescue = _text("scripts/defenseclaw-rescue.sh")
    assert 'darwin/x86_64 | darwin/amd64)\n        die "Intel macOS is unsupported' in rescue


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




def test_documented_resolver_rejects_intel_before_temp_or_network() -> None:
    site = _text("docs-site/content/docs/get-started/upgrade.mdx")
    platform_probe = 'platform_os="$(uname -s | tr \'[:upper:]\' \'[:lower:]\')"'
    assert site.index(platform_probe) < site.index('d="$(mktemp -d')
    refusal = "darwin/x86_64|darwin/amd64) echo 'Intel macOS is unsupported"
    assert site.index(refusal) < site.index('d="$(mktemp -d')
    assert site.index(refusal) < site.index("curl --fail")
    assert "sysctl.proc_translated" in site


@pytest.mark.parametrize(
    ("surface", "controller_name"),
    (("fresh-install", "install.sh"), ("upgrade", "defenseclaw-upgrade.sh")),
)
@pytest.mark.skipif(os.name == "nt", reason="POSIX shell contract")
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


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell contract")
def test_intel_refusal_harness_requires_release_dir() -> None:
    completed = subprocess.run(
        [
            str(INTEL_REFUSAL_HARNESS),
            "--surface",
            "fresh-install",
            "--version",
            "9.9.9",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 2
    assert "usage:" in completed.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX refusal harness")
@pytest.mark.parametrize(
    ("include_uname", "expected"),
    (
        (False, "uname is required to exercise the native platform guard"),
        (True, "python3 is required to snapshot the exact candidate and isolated install roots"),
    ),
)
def test_intel_refusal_harness_reports_missing_required_tools(
    tmp_path: Path,
    include_uname: bool,
    expected: str,
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "bash").symlink_to("/bin/bash")
    if include_uname:
        _write_executable(
            fake_bin / "uname",
            "#!/bin/bash\n"
            "case \"${1:-}\" in\n"
            "  -s) printf 'Darwin\\n' ;;\n"
            "  -m) printf 'x86_64\\n' ;;\n"
            "  *) exit 64 ;;\n"
            "esac\n",
        )

    completed = subprocess.run(
        [
            str(INTEL_REFUSAL_HARNESS),
            "--surface",
            "fresh-install",
            "--release-dir",
            str(ROOT),
            "--version",
            "9.9.9",
        ],
        cwd=ROOT,
        env={"PATH": str(fake_bin)},
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 1
    assert expected in completed.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell contract")
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
