# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Regression for the enterprise upgrade release lookup gate."""

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _bash() -> str | None:
    """The bash the upgrade lanes run the script with (shell: bash).

    On Windows that is the bash of Git for Windows. A bare "bash" there
    starts System32\\bash.exe, the WSL launcher, because CreateProcess
    searches System32 before PATH; without a distribution it only prints
    how to install one (UTF-16, on stdout) and exits 1.
    """
    if os.name != "nt":
        return shutil.which("bash")
    git = shutil.which("git")
    for parent in Path(git).resolve().parents if git else ():
        if (candidate := parent / "bin" / "bash.exe").is_file():
            return str(candidate)
    return None


BASH = _bash()


@pytest.mark.skipif(BASH is None, reason="needs bash (the Git for Windows bash on Windows)")
def test_release_lookup_failure_fails_upgrade_lane(tmp_path: Path) -> None:
    gh = tmp_path / "gh"
    gh.write_bytes(b"#!/bin/sh\nexit 1\n")
    gh.chmod(0o755)
    path = os.pathsep.join([str(tmp_path), os.environ.get("PATH", "")])
    env = {**os.environ, "PATH": path, "GITHUB_REPOSITORY": "example/repo"}
    result = subprocess.run(
        [BASH, str(ROOT / "scripts/fetch-previous-enterprise-package.sh"),
         "--asset", "linux-amd64.deb", "--dir", str(tmp_path / "packages")],
        env=env, capture_output=True, text=True, check=False, timeout=60,
    )
    assert result.returncode != 0
    assert "could not look up" in result.stderr


@pytest.mark.skipif(BASH is None, reason="needs bash (the Git for Windows bash on Windows)")
def test_package_in_a_backslash_path_matches_checksums(tmp_path: Path) -> None:
    # GNU sha256sum escapes a file name with a backslash and then starts its
    # line with one, so on Windows (dir D:\a\_temp/previous) the hash read
    # from it never matched checksums.txt.
    assets = tmp_path / "assets"
    assets.mkdir()
    name = "DefenseClawSetup-Enterprise-Standalone-x64.exe"
    (assets / name).write_bytes(b"setup")
    digest = hashlib.sha256(b"setup").hexdigest()
    # The 1.0.0 checksums.txt also lists itself.
    (assets / "checksums.txt").write_text(f"{digest}  {name}\n{'0' * 64}  checksums.txt\n")
    (assets / "checksums.txt.bundle").write_text("{}")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool, body in {
        "gh": 'case "$2" in list) echo 1.0.0 ;; view) ls "$FAKE_ASSETS" ;; download) while [ $# -gt 0 ]; do '
              '[ "$1" = --dir ] && d=$2; shift; done; cp "$FAKE_ASSETS"/* "$d"/ ;; esac\n',
        "cosign": "exit 0\n",
    }.items():
        (bin_dir / tool).write_bytes(b"#!/bin/sh\n" + body.encode())
        (bin_dir / tool).chmod(0o755)
    env = {**os.environ, "PATH": os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")]),
           "GITHUB_REPOSITORY": "example/repo", "FAKE_ASSETS": str(assets)}
    command = [BASH, str(ROOT / "scripts/fetch-previous-enterprise-package.sh"),
               "--asset", "setup", "--dir", str(tmp_path / "a\\b")]

    result = subprocess.run(command, env=env, capture_output=True, text=True, check=False, timeout=60)
    assert result.returncode == 0, result.stderr
    assert f"verified {name} of 1.0.0: {digest}" in result.stdout

    (assets / name).write_bytes(b"other")
    result = subprocess.run(command, env=env, capture_output=True, text=True, check=False, timeout=60)
    assert result.returncode != 0
    assert "does not match checksums.txt" in result.stderr


def _fake_gh(tmp_path: Path, assets: list[str], download: str) -> dict[str, str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    listed = "\\n".join(assets)
    body = f'case "$2" in list) echo 1.0.3 ;; view) printf "{listed}\\n" ;; download) {download} ;; esac\n'
    (bin_dir / "gh").write_bytes(b"#!/bin/sh\n" + body.encode())
    (bin_dir / "gh").chmod(0o755)
    return {**os.environ, "PATH": os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")]),
            "GITHUB_REPOSITORY": "example/repo"}


def _fetch(tmp_path: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    output = tmp_path / "github-output"
    return subprocess.run(
        [BASH, str(ROOT / "scripts/fetch-previous-enterprise-package.sh"), "--asset", "linux-amd64.deb",
         "--dir", str(tmp_path / "packages"), "--github-output", str(output)],
        env=env, capture_output=True, text=True, check=False, timeout=60,
    )


@pytest.mark.skipif(BASH is None, reason="needs bash (the Git for Windows bash on Windows)")
def test_failed_download_of_a_published_package_fails_the_pr_upgrade_lane(tmp_path: Path) -> None:
    # The PR upgrade lanes run without --require. A download that fails for a
    # release that publishes the package used to skip with success and an
    # empty version, so the upgrade step never ran and the job passed.
    name = "defenseclaw-enterprise-1.0.3-linux-amd64.deb"
    env = _fake_gh(tmp_path, [name, "checksums.txt", "checksums.txt.bundle"], "exit 1")
    result = _fetch(tmp_path, env)
    assert result.returncode != 0, result.stdout
    assert f"could not download {name} of release 1.0.3" in result.stderr
    assert not (tmp_path / "github-output").exists()


@pytest.mark.parametrize("missing", ["defenseclaw-enterprise-1.0.3-linux-amd64.deb", "checksums.txt", "checksums.txt.bundle"])
@pytest.mark.skipif(BASH is None, reason="needs bash (the Git for Windows bash on Windows)")
def test_release_missing_a_required_asset_fails_the_pr_upgrade_lane(tmp_path: Path, missing: str) -> None:
    # A published release without the package or its signed checksums used to
    # skip with success and an empty version, so the PR upgrade lane passed
    # without upgrading anything.
    listed = ["defenseclaw-enterprise-1.0.3-linux-amd64.deb", "checksums.txt", "checksums.txt.bundle"]
    env = _fake_gh(tmp_path, [a for a in listed if a != missing], "exit 1")
    result = _fetch(tmp_path, env)
    assert result.returncode != 0, result.stdout
    assert f"release 1.0.3 has no {missing}" in result.stderr
    assert "skipped" not in result.stdout
    assert not (tmp_path / "github-output").exists()


@pytest.mark.skipif(BASH is None, reason="needs bash (the Git for Windows bash on Windows)")
def test_no_published_release_is_the_only_skip(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "gh").write_bytes(b"#!/bin/sh\nexit 0\n")
    (bin_dir / "gh").chmod(0o755)
    env = {**os.environ, "PATH": os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")]),
           "GITHUB_REPOSITORY": "example/repo"}
    result = _fetch(tmp_path, env)
    assert result.returncode == 0, result.stderr
    assert "no published release to upgrade from" in result.stdout
    assert (tmp_path / "github-output").read_text() == "version=\npackage=\n"
