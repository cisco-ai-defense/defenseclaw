# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts import release_candidate, source_release_identity

ROOT = Path(__file__).resolve().parents[2]
VERSION_PATHS = (
    "Makefile",
    "pyproject.toml",
    "uv.lock",
    "cli/defenseclaw/__init__.py",
    "extensions/defenseclaw/package.json",
    "extensions/defenseclaw/package-lock.json",
    "macos/DefenseClawMac/DefenseClawMac.xcodeproj/project.pbxproj",
    "release/source-install-identity.json",
)
SOURCE_FIXTURE_PATHS = VERSION_PATHS + (
    "internal/config/config.go",
    "cli/defenseclaw/install_publish.py",
    "scripts/source-install-publish.py",
    "scripts/source_release_identity.py",
)


def _copy_source_fixture(tmp_path: Path) -> Path:
    repo = tmp_path / "checkout"
    for relative in SOURCE_FIXTURE_PATHS:
        destination = repo / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)
    return repo


def _write_executable(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(0o755)


def _source_install_fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    repo = _copy_source_fixture(tmp_path)
    install_dir = tmp_path / "home/.local/bin"
    cli = repo / ".venv/bin/defenseclaw"
    source_gateway = repo / "defenseclaw-gateway"
    installed_gateway = install_dir / "defenseclaw-gateway"
    _write_executable(cli, b"source cli\n")
    install_dir.mkdir(parents=True)
    (install_dir / "defenseclaw").symlink_to(cli)
    _write_executable(source_gateway, b"gateway-v1\n")
    _write_executable(installed_gateway, b"gateway-v1\n")
    return repo, install_dir, source_gateway, installed_gateway


def _preflight(
    tmp_path: Path,
    repo: Path,
    install_dir: Path,
    mode: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "/bin/bash",
            str(ROOT / "scripts/source-install-preflight.sh"),
            mode,
            str(repo),
            str(install_dir),
            ".venv/bin",
            "defenseclaw",
            "defenseclaw-gateway",
        ],
        env={
            **os.environ,
            "HOME": str(tmp_path / "home"),
            "DEFENSECLAW_HOME": str(tmp_path / "home/.defenseclaw"),
            "PATH": "/usr/bin:/bin",
        },
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )


def _marker_payload(repo: Path, gateway: Path) -> dict[str, object]:
    return {
        "schema_version": 2,
        "checkout_root": str(repo.resolve()),
        "source_release": "0.8.4",
        "source_install_compatibility_epoch": 1,
        "runtime_config_version": 7,
        "gateway_sha256": hashlib.sha256(gateway.read_bytes()).hexdigest(),
    }


def test_reviewed_source_identity_binds_every_canonical_version_source() -> None:
    identity = source_release_identity.validate_source_tree(
        ROOT,
        expected_release="0.8.4",
    )

    assert identity == {
        "schema_version": 1,
        "source_release": "0.8.4",
        "source_install_compatibility_epoch": 1,
        "runtime_config_version": 7,
    }
    assert set(source_release_identity.checked_in_version_sources(ROOT).values()) == {"0.8.4"}
    assert release_candidate._reviewed_source_install_identity("0.8.4") == identity


def test_hard_cut_cannot_reuse_bridge_source_identity(tmp_path: Path) -> None:
    repo = _copy_source_fixture(tmp_path)
    identity_path = repo / "release/source-install-identity.json"
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    identity["source_release"] = "0.8.5"
    identity_path.write_text(json.dumps(identity), encoding="utf-8")

    with pytest.raises(
        source_release_identity.SourceIdentityError,
        match="cannot reuse the 0.8.4 bridge source-install identity",
    ):
        source_release_identity.validate_source_tree(repo)


def test_release_stamp_is_provably_noop_for_reviewed_source(tmp_path: Path) -> None:
    repo = _copy_source_fixture(tmp_path)
    stamp = repo / "scripts/stamp-version.sh"
    shutil.copy2(ROOT / "scripts/stamp-version.sh", stamp)
    before = {relative: (repo / relative).read_bytes() for relative in VERSION_PATHS}

    completed = subprocess.run(
        ["/bin/bash", str(stamp), "0.8.4"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert {relative: (repo / relative).read_bytes() for relative in VERSION_PATHS} == before


def test_release_workflow_rejects_unstamped_source_before_publish_and_tags_reviewed_commit() -> None:
    workflow = (ROOT / ".github/workflows/release.yaml").read_text(encoding="utf-8")
    tracked = workflow.index("git ls-files --error-unmatch --")
    preflight = workflow.index("python3 scripts/source_release_identity.py check")
    expected = workflow.index('--expected-release "$RELEASE_TAG"', preflight)
    stamp = workflow.index('scripts/stamp-version.sh "$RELEASE_TAG"', preflight)
    no_op_proof = workflow.index("git diff --exit-code --", stamp)
    publish = workflow.index('gh release create "$RELEASE_TAG"')

    assert tracked < preflight < expected < stamp < no_op_proof < publish
    for relative in VERSION_PATHS:
        assert relative in workflow[tracked:preflight]
    assert '--target "$RELEASE_COMMIT"' in workflow[publish:]
    assert 'test "$remote_commit" = "$RELEASE_COMMIT"' in workflow[publish:]


@pytest.mark.skipif(os.name == "nt", reason="source ownership uses POSIX symlinks")
def test_legacy_source_marker_refuses_before_gateway_mutation(tmp_path: Path) -> None:
    repo, install_dir, source_gateway, installed_gateway = _source_install_fixture(tmp_path)
    original = installed_gateway.read_bytes()
    source_gateway.write_bytes(b"gateway-v2\n")
    (install_dir / ".defenseclaw-source-root").write_text(
        f"{repo.resolve()}\ngateway_sha256={hashlib.sha256(original).hexdigest()}\n",
        encoding="utf-8",
    )

    completed = _preflight(tmp_path, repo, install_dir, "publish-gateway")

    assert completed.returncode != 0
    assert "legacy source-install marker" in completed.stdout + completed.stderr
    assert "No installed files or services were changed" in completed.stdout + completed.stderr
    assert installed_gateway.read_bytes() == original


@pytest.mark.skipif(os.name == "nt", reason="source ownership uses POSIX symlinks")
def test_markerless_source_with_managed_state_refuses_before_gateway_mutation(
    tmp_path: Path,
) -> None:
    repo, install_dir, source_gateway, installed_gateway = _source_install_fixture(tmp_path)
    original = installed_gateway.read_bytes()
    source_gateway.write_bytes(b"gateway-v2\n")
    (tmp_path / "home/.defenseclaw").mkdir()

    completed = _preflight(tmp_path, repo, install_dir, "publish-gateway")

    assert completed.returncode != 0
    assert "original release identity is unknowable" in completed.stdout + completed.stderr
    assert installed_gateway.read_bytes() == original


@pytest.mark.skipif(os.name == "nt", reason="source ownership uses POSIX symlinks")
@pytest.mark.parametrize(
    ("field", "mismatched"),
    (
        ("source_release", "0.8.3"),
        ("source_install_compatibility_epoch", 2),
        ("source_install_compatibility_epoch", True),
        ("runtime_config_version", 8),
    ),
)
def test_mismatched_source_identity_refuses_before_gateway_mutation(
    tmp_path: Path,
    field: str,
    mismatched: object,
) -> None:
    repo, install_dir, source_gateway, installed_gateway = _source_install_fixture(tmp_path)
    original = installed_gateway.read_bytes()
    marker = _marker_payload(repo, installed_gateway)
    marker[field] = mismatched
    (install_dir / ".defenseclaw-source-root").write_text(
        json.dumps(marker, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    source_gateway.write_bytes(b"gateway-v2\n")

    completed = _preflight(tmp_path, repo, install_dir, "publish-gateway")

    assert completed.returncode != 0
    assert "belongs to another release identity" in completed.stdout + completed.stderr
    assert installed_gateway.read_bytes() == original


@pytest.mark.skipif(os.name == "nt", reason="source ownership uses POSIX symlinks")
def test_same_source_identity_allows_rebuild_and_refreshes_marker(tmp_path: Path) -> None:
    repo, install_dir, source_gateway, installed_gateway = _source_install_fixture(tmp_path)

    claimed = _preflight(tmp_path, repo, install_dir, "claim")
    assert claimed.returncode == 0, claimed.stdout + claimed.stderr
    source_gateway.write_bytes(b"gateway-v2\n")
    source_gateway.chmod(0o755)

    published = _preflight(tmp_path, repo, install_dir, "publish-gateway")
    assert published.returncode == 0, published.stdout + published.stderr
    reclaimed = _preflight(tmp_path, repo, install_dir, "claim")
    assert reclaimed.returncode == 0, reclaimed.stdout + reclaimed.stderr

    marker = json.loads((install_dir / ".defenseclaw-source-root").read_text(encoding="utf-8"))
    assert installed_gateway.read_bytes() == b"gateway-v2\n"
    assert marker == _marker_payload(repo, installed_gateway)


@pytest.mark.skipif(os.name == "nt", reason="source ownership uses POSIX symlinks")
def test_source_checkout_alias_claims_the_canonical_root(tmp_path: Path) -> None:
    repo, install_dir, _source_gateway, installed_gateway = _source_install_fixture(tmp_path)
    alias = tmp_path / "checkout-alias"
    alias.symlink_to(repo, target_is_directory=True)

    claimed = _preflight(tmp_path, alias, install_dir, "claim")

    assert claimed.returncode == 0, claimed.stdout + claimed.stderr
    marker = json.loads((install_dir / ".defenseclaw-source-root").read_text(encoding="utf-8"))
    assert marker == _marker_payload(repo, installed_gateway)


def test_source_preflight_runs_before_dependency_install_or_make_mutations() -> None:
    installer = (ROOT / "scripts/install-dev.sh").read_text(encoding="utf-8")
    main = installer[installer.index("main() {") :]
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

    assert main.index("source_install_ownership check") < main.index("check_os")
    assert main.index("source_install_ownership check") < main.index("setup_python_venv")
    for target in ("all: _source-install-preflight", "install: _source-install-preflight"):
        assert target in makefile
    cli_start = makefile.index("\ncli-install:") + 1
    gateway_start = makefile.index("\ngateway-install:", cli_start) + 1
    plugin_start = makefile.index("\nplugin-install:", gateway_start) + 1
    cli_install = makefile[cli_start:gateway_start]
    gateway_install = makefile[gateway_start:plugin_start]
    assert cli_install.startswith("cli-install: _source-install-preflight\n")
    assert "$(MAKE) --no-print-directory pycli" in cli_install
    assert gateway_install.startswith("gateway-install: _source-install-preflight cli-install\n")
    assert "$(MAKE) --no-print-directory gateway" in gateway_install
    assert "source-install-preflight.sh claim" in gateway_install
    assert "plugin-install: _source-install-preflight gateway-install" in makefile
    assert "SOURCE_PLUGIN_INSTALL_TARGET = $(if $(filter openclaw,$(CONNECTOR)),plugin-install" in makefile


def test_source_installer_go_floor_matches_go_module() -> None:
    installer = (ROOT / "scripts/install-dev.sh").read_text(encoding="utf-8")
    go_module = (ROOT / "go.mod").read_text(encoding="utf-8")

    module_version = next(line.removeprefix("go ") for line in go_module.splitlines() if line.startswith("go "))
    assert f'readonly MIN_GO_VERSION="{module_version}"' in installer
    for relative in ("README.md", "docs/INSTALL.md", "docs/E2E.md"):
        assert f"{module_version}+" in (ROOT / relative).read_text(encoding="utf-8")


@pytest.mark.skipif(os.name == "nt", reason="parallel source install uses POSIX Make")
def test_parallel_make_install_refuses_before_dependency_or_build_commands(
    tmp_path: Path,
) -> None:
    make = shutil.which("make")
    if make is None:
        pytest.skip("make is unavailable")

    home = tmp_path / "home"
    install_dir = home / ".local/bin"
    release_cli = home / ".defenseclaw/.venv/bin/defenseclaw"
    _write_executable(release_cli, b"release cli\n")
    install_dir.mkdir(parents=True)
    (install_dir / "defenseclaw").symlink_to(release_cli)
    _write_executable(install_dir / "defenseclaw-gateway", b"release gateway\n")

    build_log = tmp_path / "build-called"
    fake_bin = tmp_path / "fake-bin"
    _write_executable(
        fake_bin / "uv",
        b'#!/bin/sh\nprintf "uv\\n" >> "$BUILD_LOG"\nexit 0\n',
    )
    _write_executable(
        fake_bin / "npm",
        b'#!/bin/sh\nprintf "npm\\n" >> "$BUILD_LOG"\nexit 0\n',
    )
    _write_executable(
        fake_bin / "go",
        b"#!/bin/sh\n"
        b'if [ "${1:-}" = "env" ] && [ "${2:-}" = "GOPATH" ]; then\n'
        b"  printf '/tmp\\n'\n"
        b"  exit 0\n"
        b"fi\n"
        b'printf "go-build\\n" >> "$BUILD_LOG"\n'
        b"exit 0\n",
    )
    environment = {
        **os.environ,
        "HOME": str(home),
        "DEFENSECLAW_HOME": str(home / ".defenseclaw"),
        "PATH": f"{fake_bin}:/usr/bin:/bin",
        "BUILD_LOG": str(build_log),
    }

    completed = subprocess.run(
        [
            make,
            "--no-print-directory",
            "-j4",
            "install",
            "CONNECTOR=openclaw",
            f"INSTALL_DIR={install_dir}",
        ],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
        timeout=20,
    )

    assert completed.returncode != 0
    assert "source install refused" in completed.stdout + completed.stderr
    assert not build_log.exists()
    assert (install_dir / "defenseclaw").readlink() == release_cli
    assert (install_dir / "defenseclaw-gateway").read_bytes() == b"release gateway\n"
